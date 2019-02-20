// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use {
    fuchsia_zircon::{self as zx, Duration, Time},
    std::result,
};

use crate::peer::{
    Peer, CommandStream
};

use crate::types::{
    AvcHeader, Error, CommandType, PANEL_SUBUNIT, AvOpCode, BT_SIG_COMPANY_ID
};

#[derive(Debug)]
pub struct AvcPeer {
    peer: Peer,
}

impl AvcPeer {
    pub fn new (socket: zx::Socket) -> result::Result<AvcPeer, zx::Status> {
        Ok(AvcPeer{peer: Peer::new(socket)?})
    }


    pub fn take_command_stream(&self) -> CommandStream {

    }


    /// The maximum amount of time we will wait for a response to a command packet.
    fn passthrough_command_timeout() -> Duration {
        const CMD_TIMER_MS: i64 = 1000;
        Duration::from_millis(CMD_TIMER_MS)
    }

    /// Sends an AVC passthrough command
    pub async fn send_avc_passthrough_command<'a>(&'a self, payload: &'a [u8]) -> Result<Vec<u8>> {
        let avc_header = AvcHeader::new(
            CommandType::Control,
            PANEL_SUBUNIT,
            0,
            AvOpCode::VendorDependent,
            Some(BT_SIG_COMPANY_ID),
        );

        let avc_h_len = avc_header.encoded_len();
        let mut buf = vec![0; avc_h_len];

        avc_header.encode(&mut buf[avct_header.encoded_len() + 1..])?;
        buf.extend_from_slice(payload);

        let mut response = self.peer.send_command(buf.as_slice())?;

        loop {
            let mut timeout = fasync::Timer::new(Time::after(AvcPeer::passthrough_command_timeout())).fuse();
            select! {
                _ = timeout => Err(Error::Timeout),
                r = response => {
                    let response_packet = r?;
                    decode_passthrough_response(response_packet)
                },
            }
        }
    }
}

enum PassthroughResponse {
    Interim(),
    Accept(Vec<u8>),
    Reject(Vec<u8>),
}

fn decode_passthrough_response(buf: Vec<u8>) -> Result<PassthroughResponse> {
    let avct_header = AvctHeader::decode(&buf[..])?;
    if buf.len() == avct_header.encoded_len() {
        return Err(Error::InvalidHeader);
    }
    if avct_header.is_invalid_profile_id() {
        return Err(Error::InvalidProfileId(avct_header.label()));
    }
    let avc_header = AvcHeader::decode(&buf[avct_header.encoded_len()..])?;
    Ok(buf[avct_header.encoded_len() + avc_header.encoded_len()..].to_vec())
}
