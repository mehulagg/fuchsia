// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use {
    fuchsia_async as fasync,
    fuchsia_syslog::{fx_log_info, fx_log_warn, fx_vlog},
    fuchsia_zircon::{self as zx, Duration, Time},
    futures::{
        future::FusedFuture,
        ready, select,
        stream::Stream,
        task::{Poll, Waker},
        FutureExt,
    },
    parking_lot::Mutex,
    slab::Slab,

    std::{convert::TryFrom, collections::VecDeque, marker::Unpin, mem, pin::Pin, result, sync::Arc},
};

use crate::types::{
    AvOpCode, AvcHeader, AvctHeader, CommandType, Decodable, Encodable, Error, MessageType, Result,
    TxLabel, AV_REMOTE_PROFILE, BT_SIG_COMPANY_ID, PANEL_SUBUNIT,
};

#[derive(Debug)]
pub struct Peer {
    inner: Arc<PeerInner>,
}

#[derive(Debug)]
pub struct PeerInner {
    // Socket to the remote device owned by this peer object.
    socket: fasync::Socket,

    /// A map of transaction ids that have been sent but the response has not
    /// been received and/or processed yet.
    ///
    /// Waiters are added with `add_response_waiter` and get removed when they are
    /// polled or they are removed with `remove_waiter`
    response_waiters: Mutex<Slab<ResponseWaiter>>,

    /// A queue of requests that have been received and are waiting to
    /// be reponded to, along with the waker for the task that has
    /// taken the request receiver (if it exists)
    incoming_requests: Mutex<RequestQueue>,
}

impl Peer {
    /// Create a new peer from a channel socket.
    pub fn new(socket: zx::Socket) -> result::Result<Peer, zx::Status> {
        Ok(Peer {
            inner: Arc::new(PeerInner {
                socket: fasync::Socket::from_socket(socket)?,
                response_waiters: Mutex::new(Slab::<ResponseWaiter>::new()),
                incoming_requests: Mutex::<RequestQueue>::default(),
            }),
        })
    }

    /// Returns a stream of incoming commands from a remote peer.
    /// Stream returns AvctCommand objects on success that can be used to send back responses.
    pub fn take_command_stream(&self) -> CommandStream {
        {
            let mut lock = self.inner.incoming_requests.lock();
            if let CommandListener::None = lock.listener {
                lock.listener = CommandListener::New;
            } else {
                panic!("Command stream has already been taken");
            }
        }

        CommandStream { inner: self.inner.clone() }
    }

    /// Send an outgoing command to the remote peer. Returns a CommandResponseStream to
    /// handle incoming response packets.
    pub async fn send_command<'a>(&'a self, payload: &'a [u8]) -> Result<CommandResponseStream> {
        let id = self.inner.add_response_waiter()?;
        let avct_header = AvctHeader::new(id, AV_REMOTE_PROFILE, MessageType::Command, false);
        {
            let avct_h_len = avct_header.encoded_len();
            let mut buf = vec![0; avct_h_len];
            avct_header.encode(&mut buf[..avct_header.encoded_len()])?;
            buf.extend_from_slice(payload);
            self.inner.send_packet(buf.as_slice())?;
        }

        CommandResponseStream::new(avct_header.label(), self.inner.clone())
    }

}

impl PeerInner {
    /// Add a response waiter, and return a id that can be used to send the
    /// transaction.  Responses then can be received using poll_recv_response
    fn add_response_waiter(&self) -> Result<TxLabel> {
        let key = self.response_waiters.lock().insert(ResponseWaiter::default());
        let id = TxLabel::try_from(key as u8);
        if id.is_err() {
            fx_log_warn!(tag: "avctp", "Transaction IDs are exhausted");
            self.response_waiters.lock().remove(key);
        }
        id
    }

    /// When a waiter isn't interested in the response anymore, we need to just
    /// throw it out.  This is called when the response future is dropped.
    fn remove_response_interest(&self, id: &TxLabel) {
        let mut lock = self.response_waiters.lock();
        let idx = usize::from(id);
        lock.remove(idx);
    }

    // Attempts to receive a new request by processing all packets on the socket.
    // Resolves to an unprocessed request (header, body) if one was received.
    // Resolves to an error if there was an error reading from the socket or if the peer
    // disconnected.
    fn poll_recv_request(&self, lw: &Waker) -> Poll<Result<UnparsedRequest>> {
        let is_closed = self.recv_all(lw)?;

        let mut lock = self.incoming_requests.lock();

        if let Some(request) = lock.queue.pop_front() {
            Poll::Ready(Ok(request))
        } else {
            lock.listener = CommandListener::Some(lw.clone());
            if is_closed {
                Poll::Ready(Err(Error::PeerDisconnected))
            } else {
                Poll::Pending
            }
        }
    }

    // Attempts to receive a response to a request by processing all packets on the socket.
    // Resolves to the bytes in the response body if one was received.
    // Resolves to an error if there was an error reading from the socket, if the peer
    // disconnected, or if the |label| is not being waited on.
    fn poll_recv_response(&self, label: &TxLabel, lw: &Waker) -> Poll<Result<AvctPacket>> {
        let is_closed = self.recv_all(lw)?;

        let mut waiters = self.response_waiters.lock();
        let idx = usize::from(label);
        // We expect() below because the label above came from an internally-created object,
        // so the waiters should always exist in the map.
        let &mut waiter = waiters.get_mut(idx).expect("Polled unregistered waiter");
        if waiter.is_received() {
            // We got our response.
            let packet = waiter.pop_received();
            Poll::Ready(Ok(packet))
        } else {
            // Set the waker to be notified when a response shows up.
            waiter.listener = ResponseListener.Some(lw.clone());
            if is_closed {
                Poll::Ready(Err(Error::PeerDisconnected))
            } else {
                Poll::Pending
            }
        }
    }

    /// Poll for any packets on the socket
    /// Returns whether the channel was closed, or an Error::PeerRead or Error::PeerWrite
    /// if there was a problem communicating on the socket.
    fn recv_all(&self, lw: &Waker) -> Result<bool> {
        let mut buf = Vec::<u8>::new();
        loop {
            let packet_size = match self.socket.poll_datagram(&mut buf, lw) {
                Poll::Ready(Err(zx::Status::PEER_CLOSED)) => {
                    fx_vlog!(tag: "avctp", 1, "Peer closed");
                    return Ok(true);
                }
                Poll::Ready(Err(e)) => return Err(Error::PeerRead(e)),
                Poll::Pending => return Ok(false),
                Poll::Ready(Ok(size)) => size,
            };
            if packet_size == 0 {
                continue;
            }
            // Detects General Reject condition and sends the response back.
            // On other headers with errors, sends BAD_HEADER to the peer
            // and attempts to continue.
            let avct_header = match AvctHeader::decode(buf.as_slice()) {
                Err(_) => {
                    // Only possible error is OutOfRange
                    // Returned only when the packet is too small, can't make a meaningful reject.
                    fx_log_info!(tag: "avctp", "received unrejectable message");
                    buf = buf.split_off(packet_size);
                    continue;
                }
                Ok(x) => Ok(x),
            }?;

            // We only support AV remote targeted AVCTP messages on this socket.
            // Send a rejection AVCTP messages with ipid bit set to true.
            if avct_header.profile_id() != AV_REMOTE_PROFILE {
                fx_log_info!(tag: "avctp", "received packet not targeted at remote profile service class");
                let resp_avct = avct_header.create_invalid_profile_id_response();
                let mut rbuf = vec![0 as u8; resp_avct.encoded_len()];
                resp_avct.encode(&mut rbuf)?;
                self.send_packet(&rbuf)?;
                buf = buf.split_off(packet_size);
                continue;
            }

            if packet_size == avct_header.encoded_len() {
                // Only the avctp header was sent with no payload.
                fx_log_info!(tag: "avctp", "received incomplete packet");
                buf = buf.split_off(packet_size);
                continue;
            }

            let avc_header = match AvcHeader::decode(&buf[avct_header.encoded_len()..]) {
                Err(_) => {
                    // Possible errors are Invalid Header or OutOfRange
                    // Returned only when we can't make a meaningful reject.
                    fx_log_info!(tag: "avctp", "received unrejectable message");
                    buf = buf.split_off(packet_size);
                    continue;
                }
                Ok(x) => Ok(x),
            }?;

/*
            // We currently only support non-fragmented AVCTP messages.
            // Send a rejection to all message types that are not single.
            if !avct_header.is_single() {
                fx_log_info!(tag: "avctp", "received fragmented packet from peer");

                // Fragmented responses we drop on the floor. Fragmented commands
                // we respond to with a rejection.
                if avct_header.is_command() {
                    self.send_response(&avct_header, &avc_header, CommandType::NotImplemented)?;
                }
                buf = buf.split_off(packet_size);
                continue;
            }

            // The only type of subunit we support other than panel is unit subunit when a
            // unit info or sub unit info command is sent.
            if avct_header.is_command()
                && avc_header.is_unit_subunit()
                && (avc_header.is_op_code(AvOpCode::UnitInfo)
                    || avc_header.is_op_code(AvOpCode::SubUnitInfo))
            {
                fx_log_info!(tag: "avctp", "received UNITINFO/SUBUNITINFO command");
                let mut pbuf: [u8; 5] = [0xff; 5];
                match avc_header.op_code() {
                    AvOpCode::UnitInfo => {
                        // This constant is undefined in the spec. It just is always 7.
                        pbuf[0] = 0x07;
                        pbuf[1] = PANEL_SUBUNIT << 3;
                        // We might want to append company_id.
                        // For now using 0xfffff for generic the spec.
                    }
                    AvOpCode::SubUnitInfo => {
                        pbuf[0] = 0x07;
                        pbuf[1] = PANEL_SUBUNIT << 3;
                    }
                    _ => (),
                };
                self.send_response_with_body(&avct_header, &avc_header, CommandType::ImplementedStable, &pbuf)?;
                buf = buf.split_off(packet_size);
                continue;
            }

            // Send a rejection to any non-panel subunits.
            if !avc_header.is_panel_subunit() {
                if avct_header.is_command() {
                    self.send_response(&avct_header, &avc_header, CommandType::NotImplemented)?;
                }
                buf = buf.split_off(packet_size);
                continue;
            }
*/
            // Commands from the remote get translated into requests.
            if avct_header.is_command() {
                let rest = buf.split_off(packet_size);
                let mut lock = self.incoming_requests.lock();
                let body = buf.split_off(avct_header.encoded_len());
                lock.queue.push_back(AvctPacket{header: avct_header, body: body.to_vec()});
                //lock.queue.push_back(UnparsedRequest::new(avct_header, avc_header, body));
                if let CommandListener::Some(ref waker) = lock.listener {
                    waker.wake();
                }
                buf = rest;
            } else {
                // Should be a response to a command we sent.
                let rest = buf.split_off(packet_size);
                let body = buf.split_off(avct_header.encoded_len());
                let mut waiters = self.response_waiters.lock();
                let idx = usize::from(&avct_header.label());

                let Some(waiter) = waiters.get_mut(idx) {
                    waiter.queue.push_back(AvctPacket{header: avct_header, body: buf.to_vec()});
                    let old_entry = mem::replace(waiter.listener, ResponseListener::New);
                    if let ResponseListener::Some(waker) = old_entry {
                        waker.wake();
                    }
                } else {
                    fx_vlog!(tag: "avctp", 1, "response for {:?} we did not send, dropping", avct_header.label());
                }
                buf = rest;
                // Note: we drop any TxLabel response we are not waiting for
            }
        }
    }

    // Wakes up an arbitrary task that has begun polling on the channel so that
    // it will call recv_all and be registered as the new channel reader.
    fn wake_any(&self) {
        // Try to wake up response waiters first, rather than the event listener.
        // The event listener is a stream, and so could be between poll_nexts,
        // Response waiters should always be actively polled once
        // they've begun being polled on a task.
        {
            let lock = self.response_waiters.lock();
            for (_, response_waiter) in lock.iter() {
                if let ResponseWaiter::Waiting(waker) = response_waiter {
                    waker.wake();
                    return;
                }
            }
        }
        {
            let lock = self.incoming_requests.lock();
            if let CommandListener::Some(waker) = &lock.listener {
                waker.wake();
                return;
            }
        }
    }

    pub fn send_response(&self, command_header: &AvtcHeader, body: &[u8]) -> Result<()> {
        let resp_header = command_header.create_response();
        let mut rbuf = vec![0 as u8; resp_header.encoded_len()];
        resp_header.encode(&mut rbuf)?;
        if body.len() > 0 {
            rbuf.extend_from_slice(body);
        }
        self.inner.send_packet(&rbuf)
    }

    /// Sends a generic reject response given an existing command packet.
    fn send_reject(&self, avct_header: &AvctHeader, avc_header: &AvcHeader) -> Result<()> {
        self.send_response(&avct_header, &avc_header, CommandType::Rejected)
    }

    /// Sends a simple response given an existing command packet with no body.
    fn send_response(&self, avct_header: &AvctHeader, avc_header: &AvcHeader, command_type: CommandType) -> Result<()> {
        self.send_response_with_body(&avct_header, &avc_header, command_type, &[])
    }

    /// Sends a simple response given an existing command packet with a body.
    fn send_response_with_body(&self, avct_header: &AvctHeader, avc_header: &AvcHeader, command_type: CommandType, body: &[u8]) -> Result<()> {
        let resp_avct = avct_header.create_response();
        let resp_avc = avc_header.create_response(command_type);
        let mut rbuf = vec![0 as u8; resp_avct.encoded_len() + resp_avc.encoded_len()];
        resp_avct.encode(&mut rbuf)?;
        resp_avc.encode(&mut rbuf[resp_avct.encoded_len()..])?;
        if body.len() > 0 {
            rbuf.extend_from_slice(body);
        }
        self.send_packet(&rbuf)
    }

    /// Sends a response to an AVC passthrough command with the specified command type.
    fn send_passthrough_response(&self, id: TxLabel, command_type: CommandType) -> Result<()> {
        let resp_avct = AvctHeader::new(id, AV_REMOTE_PROFILE, MessageType::Response, false);
        let resp_avc = AvcHeader::new(command_type, PANEL_SUBUNIT, 0, AvOpCode::Passthrough, None);

        let mut rbuf = vec![0 as u8; resp_avct.encoded_len() + resp_avc.encoded_len()];
        resp_avct.encode(&mut rbuf)?;
        resp_avc.encode(&mut rbuf[resp_avct.encoded_len()..])?;
        self.send_packet(&rbuf)
    }

    /// Send a response to a vendor dependent packet with the payload specified.
    fn send_vendor_response(
        &self,
        id: TxLabel,
        buf: Option<&[u8]>,
        command_type: CommandType,
    ) -> Result<()> {
        let resp_avct = AvctHeader::new(id, AV_REMOTE_PROFILE, MessageType::Response, false);
        let resp_avc = AvcHeader::new(
            command_type,
            PANEL_SUBUNIT,
            0,
            AvOpCode::VendorDependent,
            Some(BT_SIG_COMPANY_ID),
        );

        let mut rbuf = vec![0 as u8; resp_avct.encoded_len() + resp_avc.encoded_len()];
        resp_avct.encode(&mut rbuf)?;
        resp_avc.encode(&mut rbuf[resp_avct.encoded_len()..])?;
        if buf.is_some() {
            rbuf.extend(buf.unwrap());
        }

        self.send_packet(&rbuf)
    }

    fn send_packet(&self, data: &[u8]) -> Result<()> {
        self.socket.as_ref().write(data).map_err(|x| Error::PeerWrite(x))?;
        Ok(())
    }
}

/// A stream of requests from the remote peer.
#[derive(Debug)]
pub struct CommandStream {
    inner: Arc<PeerInner>,
}

impl Unpin for CommandStream {}

impl Stream for CommandStream {
    type Item = Result<AvctCommand>;

    fn poll_next(self: Pin<&mut Self>, lw: &Waker) -> Poll<Option<Self::Item>> {
        Poll::Ready(match ready!(self.inner.poll_recv_request(lw)) {
            Ok(AvctPacket(header, body, ..)) => {
                Some(AvctCommand{peer: self.inner.clone(), avct_header: header, body: body})
            }
            Err(Error::PeerDisconnected) => None,
            Err(e) => Some(Err(e)),
        })
    }
}

impl Drop for CommandStream {
    fn drop(&mut self) {
        self.inner.incoming_requests.lock().listener = CommandListener::None;
        self.inner.wake_any();
    }
}


#[derive(Debug)]
pub struct AvctCommand {
    peer: Arc<PeerInner>,
    avct_header: header,
    body: Vec<u8>,
}

impl AvctCommand {
    pub fn header -> &AvctHeader {
        &self.header
    }

    pub fn body(&self) -> &[u8] {
        &self.body[..]
    }

    pub fn send_response(&self, body: &[u8]) -> Result<()> {
        self.peer.send_response(&self.header, body)
    }
}

#[derive(Debug)]
pub struct AvctPacket{
    header: AvctHeader,
    body: Vec<u8>,
}

impl AvctPacket {
    pub fn header(&self) -> &AvcHeader {
        &self.header;
    }

    pub fn body(&self) -> &[u8] {
        &self.body[..];
    }
}

/*
#[derive(Debug)]
struct UnparsedRequest(AvctHeader, AvcHeader, Vec<u8>);

impl UnparsedRequest {
    fn new(avct_header: AvctHeader, avc_header: AvcHeader, body: Vec<u8>) -> UnparsedRequest {
        UnparsedRequest(avct_header, avc_header, body)
    }
}

// These are the only four types of packets we will transmit or receive
#[derive(Debug)]
pub enum Request {
    Passthrough {
        body: Vec<u8>,
        responder: PassthroughResponder,
    },
    VendorDependent {
        body: Vec<u8>,
        command_type: CommandType,
        responder: VendorDependentResponder,
    },
}

impl Request {
    /// Constructs a Request that be vended off the request stream. Each Request object has
    /// an associated responder to reply to that message.
    fn parse(
        peer: Arc<PeerInner>,
        label: TxLabel,
        command_type: CommandType,
        op_code: AvOpCode,
        body: &[u8],
    ) -> Result<Request> {
        match op_code {
            AvOpCode::Passthrough => {
                if command_type != CommandType::Control {
                    return Err(Error::RequestInvalid);
                }
                Ok(Request::Passthrough {
                    body: body.to_vec(),
                    responder: PassthroughResponder { peer: peer.clone(), id: label },
                })
            }
            AvOpCode::VendorDependent => Ok(Request::VendorDependent {
                body: body.to_vec(),
                command_type: command_type,
                responder: VendorDependentResponder { peer: peer.clone(), id: label },
            }),
            _ => Err(Error::RequestInvalid),
        }
    }
}

#[derive(Debug)]
pub struct PassthroughResponder {
    peer: Arc<PeerInner>,
    id: TxLabel,
}

impl PassthroughResponder {
    pub fn accept(&self) -> Result<()> {
        self.peer.send_passthrough_response(self.id, CommandType::Accepted)
    }

    pub fn interim(&self) -> Result<()> {
        self.peer.send_passthrough_response(self.id, CommandType::Interim)
    }

    pub fn not_implemented(&self) -> Result<()> {
        self.peer.send_passthrough_response(self.id, CommandType::NotImplemented)
    }

    pub fn reject(&self) -> Result<()> {
        self.peer.send_passthrough_response(self.id, CommandType::Rejected)
    }
}

#[derive(Debug)]
pub struct VendorDependentResponder {
    peer: Arc<PeerInner>,
    id: TxLabel,
}

impl VendorDependentResponder {
    // Note: Interim may be handled interally in the future.
    pub fn interim(&self) -> Result<()> {
        self.peer.send_vendor_response(self.id, None, CommandType::Interim)
    }

    pub fn stable(&self, buf: &[u8]) -> Result<()> {
        self.peer.send_vendor_response(self.id, Some(buf), CommandType::ImplementedStable)
    }

    pub fn not_implemented(&self) -> Result<()> {
        self.peer.send_vendor_response(self.id, None, CommandType::NotImplemented)
    }

    pub fn reject(&self, buf: &[u8]) -> Result<()> {
        self.peer.send_vendor_response(self.id, Some(buf), CommandType::Rejected)
    }

    pub fn changed(&self, buf: &[u8]) -> Result<()> {
        self.peer.send_vendor_response(self.id, Some(buf), CommandType::Changed)
    }
}
*/

#[derive(Debug, Default)]
struct CommandQueue {
    listener: CommandListener,
    queue: VecDeque<AvctPacket>,
}

#[derive(Debug)]
enum CommandListener {
    /// No one is listening.
    None,
    /// Someone wants to listen but hasn't polled.
    New,
    /// Someone is listening, and can be woken whith the waker.
    Some(Waker),
}

impl Default for CommandListener {
    fn default() -> Self {
        CommandListener::None
    }
}

#[#[derive(Debug, Default)]]
struct ResponseWaiter {
    listener: ResponseListener,
    queue: VecDeque<AvctPacket>
}

/// An enum representing an interest in the response to a command.
#[derive(Debug)]
enum ResponseListener {
    /// A new waiter which hasn't been polled yet.
    New,
    /// A task waiting for a response, which can be woken with the waker.
    Some(Waker),
    /// We can't handle or don't want to handle the next message so discard it.
    Discard,
}

impl Default for ResponseListener {
    fn default() -> Self {
        ResponseListener::New
    }
}

impl ResponseWaiter {
    /// Check if a message has been received.
    fn has_response(&self) -> bool {
        !self.queue.is_empty()
    }

    fn pop_received(&mut self) -> Vec<u8> {
        if self.has_response() {
            self.queue.pop_front()
        } else {
            panic!("expected received buf")
        }
    }
}

/// A stream wrapper that polls for the responses to a command we sent.
/// Removes the associated response waiter when dropped or explictly
/// completed.
#[derive(Debug)]
pub struct CommandResponseStream {
    id: TxLabel,
    inner: Arc<PeerInner>,
    complete : bool,
}

impl CommandResponseStream {
    fn new(id: TxLabel, inner:Arc<PeerInner>) -> CommandResponseStream {
        CommandResponseStream{
            id: id,
            inner: inner,
            complete: false,
        }
    }

    pub fn complete(&mut self) {
        if !self.complete {
            self.inner.remove_response_interest(&self.id);
            self.complete = true;
            self.inner.wake_any();
        }
    }
}

impl Unpin for CommandResponseStream {}

impl Stream for CommandResponseStream {
    type Item = Result<AvctPacket>;
    fn poll_next(mut self: Pin<&mut Self>, lw: &Waker) -> Poll<Option<Self::Item>>> {
        let this = &mut *self;
        if this.complete {
            Poll::Ready(None);
        }
        Poll::Ready(match ready!(this.inner.poll_recv_response(&this.id, lw)){
            Ok(packet) => {
                if packet.header().is_invalid_profile_id() {
                    Some(Err(Error::InvalidProfileId(packet.header().label())))
                } else {
                    Some(Ok(packet))
                }
            }
            Err(Error::PeerDisconnected) => None,
            Err(e) => Some(Err(e)),
        })
    }
}

impl Drop for CommandResponseStream {
    fn drop(&mut self) {
        self.complete();
    }
}
