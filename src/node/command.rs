// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::stage::State;
use crate::{
    location::{DstLocation, SrcLocation},
    messages::Message,
};
use bytes::Bytes;
use std::net::SocketAddr;

#[derive(Debug)]
pub(crate) enum Command {
    ProcessMessage {
        message: Message,
        sender: SocketAddr,
    },
    ProcessTimeout(u64),
    SendUserMessage {
        src: SrcLocation,
        dst: DstLocation,
        content: Bytes,
    },
    Transition(Box<State>),
}
