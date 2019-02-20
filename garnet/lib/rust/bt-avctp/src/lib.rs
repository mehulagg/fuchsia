// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![feature(async_await, await_macro, futures_api)]

#[cfg(test)]
mod tests;

mod avcpeer;
mod peer;
mod types;

pub use crate::peer:: {
    Peer, RequestStream, Request
};
