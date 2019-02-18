// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![feature(futures_api, async_await, await_macro)]
#![recursion_limit = "256"]

use {
    bt_avctp as avctp,
    fidl_fuchsia_bluetooth_avrcp::*,
    fuchsia_bluetooth::bt_fidl_status,
    futures::{
        Sender
    }
}

/// TODO change to u64 once that change happens
pub type DeviceId = String;

pub enum ControllerCommand {

}

pub struct RemotePeerManager {
    peers: HashMap<DeviceId, RemotePeer>,
    peers: HashMap<DeviceId, RemotePeer>,
}


struct RemotePeer {
    peer: Option<avctp::Peer>,
    device_id: DeviceId,
    controller_event_sink: Sender<ControllerCommand>,
}

impl RemotePeer {
    pub fn new(device_id: DeviceId) -> RemotePeer {
        let (avrcp_input_chan, mut avrcp_service_chan) = mpsc::channel(512);

        RemotePeer {
            peer: None,
            device_id: device_id,
            controller_event_sink: controller_event_sink,
        }
    }

    pub async fn serve_controller_client()  {

    }

    pub async fn server_controller_test_client() {

    }

    pub fn has_peer() -> bool {
        peer.is_some()
    }
}