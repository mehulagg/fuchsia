// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![feature(futures_api, async_await, await_macro)]
#![recursion_limit = "256"]

#[allow(unused_imports)] // TODO remove
use {
    bt_avctp as avctp,
    failure::{format_err, Error, ResultExt},
    fidl::{
        endpoints::{RequestStream, ServiceMarker},
        Error as FidlError,
    },
    fidl_fuchsia_bluetooth::{self, Status},
    fidl_fuchsia_bluetooth_avrcp::*,
    fidl_fuchsia_bluetooth_bredr::*,
    fuchsia_app::server::ServicesServer,
    fuchsia_async as fasync,
    fuchsia_bluetooth::bt_fidl_status,
    fuchsia_syslog::{self, fx_log_err, fx_log_info, fx_log_warn},
    fuchsia_zircon as zx,
    futures::{
        channel::mpsc::{self as mpsc, Receiver, Sender},
        select,
        stream::{FuturesUnordered, StreamFuture},
        FutureExt, StreamExt, TryFutureExt, TryStreamExt,
    },
    log::warn,
    parking_lot::RwLock,
    std::{collections::hash_map::Entry, collections::HashMap, string::String, sync::Arc},
};

type DeviceId = String;
type RemotesMap = HashMap<DeviceId, avctp::Peer>;

const AVRCP_FEATURE_CATEGORY_1: u16 = 0x0001;
const AVRCP_FEATURE_CATEGORY_2: u16 = 0x0002;
// const AVRCP_FEATURE_CATEGORY_3 : u16 = 0x0004;
// const AVRCP_FEATURE_CATEGORY_4 : u16 = 0x0008;
// const AVRCP_FEATURE_PLAYER_SETTINGS : u16 = 0x0010;
// const AVRCP_FEATURE_BROWSING : u16 = 0x0040;

/// Make the SDP definition for the AVRCP service.
fn make_profile_service_definition() -> ServiceDefinition {
    let service_class_uuids =
        vec![String::from("110E"), String::from("110F"), String::from("110C")];

    ServiceDefinition {
        service_class_uuids: service_class_uuids, // AVRCP UUID
        protocol_descriptors: vec![
            ProtocolDescriptor {
                protocol: ProtocolIdentifier::L2Cap,
                params: vec![DataElement {
                    type_: DataElementType::UnsignedInteger,
                    size: 2,
                    data: DataElementData::Integer(PSM_AVCTP),
                }],
            },
            ProtocolDescriptor {
                protocol: ProtocolIdentifier::Avctp,
                params: vec![DataElement {
                    type_: DataElementType::UnsignedInteger,
                    size: 2,
                    data: DataElementData::Integer(0x0103), // Indicate v1.3
                }],
            },
        ],
        profile_descriptors: vec![ProfileDescriptor {
            profile_id: ServiceClassProfileIdentifier::AvRemoteControl,
            major_version: 1,
            minor_version: 6,
        }],
        additional_protocol_descriptors: None,
        information: vec![Information {
            language: "en".to_string(),
            name: Some("AVRCP".to_string()),
            description: Some("AVRCP".to_string()),
            provider: Some("Fuchsia".to_string()),
        }],
        additional_attributes: Some(vec![Attribute {
            id: 0x0311, // SDP Attribute "SUPPORTED FEATURES"
            element: DataElement {
                type_: DataElementType::UnsignedInteger,
                size: 2,
                data: DataElementData::Integer(
                    (AVRCP_FEATURE_CATEGORY_1 | AVRCP_FEATURE_CATEGORY_2) as i64,
                ),
            },
        }]),
    }
}


async fn register_service(profile_svc: &ProfileProxy) -> Result<(), Error> {
    let mut service_def = make_profile_service_definition();
    let (status, service_id) = await!(profile_svc.add_service(
        &mut service_def,
        SecurityLevel::EncryptionOptional,
        false
    ))?;

    fx_log_info!("Registered Service ID {}", service_id);

    if let Some(e) = status.error {
        return Err(format_err!("Couldn't add AVRCP service: {:?}", e));
    };
    Ok(())
}

async fn run_avrcp_client(_remotes: Arc<RwLock<RemotesMap>>, chan: fasync::Channel) -> Result<(), Error>  {
    let mut stream = AvrcpRequestStream::from_channel(chan);

    while let Some(event) = await!(stream.try_next())? {
        match event {
            AvrcpRequest::GetControllerForTarget {
                device_id: _,
                client,
                responder
            } => {
                match client.into_stream_and_control_handle(){
                    Err(err) => {
                        warn!("Err unable to create server end point from stream {:?}", err);
                        responder.send(&mut bt_fidl_status!(Failed))?;
                    }
                    Ok(_request_stream) => {
                        /*fasync::spawn(

                        );*/
                        responder.send(&mut bt_fidl_status!())?;
                    }
                }
            },
        }
    };
    Ok(())
}

#[fasync::run_singlethreaded]
async fn main() -> Result<(), Error> {
    fuchsia_syslog::init_with_tags(&["avrcp"]).expect("Can't init logger");


    let remotes: Arc<RwLock<RemotesMap>> = Arc::new(RwLock::new(HashMap::new()));

    let profile_svc = fuchsia_app::client::connect_to_service::<ProfileMarker>()
        .context("Failed to connect to Bluetooth profile service")?;

    await!(register_service(&profile_svc))?;

    let mut evt_stream = profile_svc.take_event_stream().fuse();
    /*let (test_input_chan, mut test_service_chan) = mpsc::channel(512);*/
    let (test_input_chan, mut _test_service_chan) = mpsc::channel(512);
    let mut fidl_server = ServicesServer::new()
        .add_service((AvrcpMarker::NAME, move |chan| {
            fx_log_info!("New AVRCP client");
            fasync::spawn(
                run_avrcp_client(remotes.clone(), chan)
                    .unwrap_or_else(|e| fx_log_err!("failed to spawn {:?}", e)),
            )
        }))
        .add_service((AvrcpTestMarker::NAME, move |chan| {
            fx_log_info!("New AVRCP test client");
            let mut input_chan = test_input_chan.clone();
            if let Err(e) = input_chan.try_send(chan) {
                fx_log_err!("Error registering new test client: {}", e);
            }
        }))
        .start()?
        .fuse();

    loop {
        select! {
            _ = fidl_server => {
                break Ok(());
            },
            evt = evt_stream.next() => match evt {
                Some(evt) => {
                    match evt {
                        Ok(ProfileEvent::OnConnected {
                            device_id,
                            service_id,
                            channel,
                            protocol,
                        }) => {
                            fx_log_info!(
                                "Connection from {}: {:?} {:?} {:?}!",
                                device_id,
                                channel,
                                protocol,
                                service_id
                            );

                            match avctp::Peer::new(channel) {
                                Err(e) => {
                                    format_err!("peer error {:?}", e);
                                },
                                Ok(peer) => {
                                    let mut request_stream = peer.take_request_stream();
                                    fuchsia_async::spawn(
                                        async move {
                                            while let Some(r) = await!(request_stream.next()) {
                                                match r {
                                                    Err(e) => fx_log_info!("Request Error on {}: {:?}", device_id, e),
                                                    Ok(avctp::Request::Passthrough{body, responder}) => {
                                                        fx_log_info!("Passthrough {}: {:?}", device_id, body);
                                                        let _ = responder.accept();
                                                    },
                                                    Ok(avctp::Request::VendorDependent{body, command_type, responder}) => {
                                                        fx_log_info!("VendorDependent {}: {:?} {:?}", device_id, command_type, body);
                                                        let _ = responder.not_implemented();
                                                    }
                                                }
                                            }
                                        }
                                    );
                                }
                            }

                            //remotes.lock().insert(Peer::new(channel));
                            //
                        },
                        Err(e) => return Err(format_err!("profile service error {:?}", e)),
                    }
                },
                None => return Err(format_err!("profile service stream closed")),
            },
        }
    }
}

/*
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Test something
    fn test_something() {
    }
}
*/
