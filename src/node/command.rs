// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::stage::State;
use crate::{
    consensus::{ProofShare, Vote},
    location::{DstLocation, SrcLocation},
    messages::Message,
};
use bytes::Bytes;
use std::{net::SocketAddr, time::Duration};

/// Command for node.
#[derive(Debug)]
pub(crate) enum Command {
    /// Handle `message` from `sender`.
    /// Note: `sender` is `Some` if the message was received from someone else
    /// and `None` if it came from an accumulated `Vote::SendMessage`
    HandleMessage {
        sender: Option<SocketAddr>,
        message: Message,
    },
    /// Handle a timeout previously scheduled with `ScheduleTimeout`.
    HandleTimeout(u64),
    /// Handle peer that's been detected as lost.
    HandlePeerLost(SocketAddr),
    /// Handle vote cast either by us or some other peer.
    HandleVote { vote: Vote, proof_share: ProofShare },
    /// Send a message to `delivery_group_size` peers out of the given `recipients`.
    SendMessage {
        recipients: Vec<SocketAddr>,
        delivery_group_size: usize,
        message: Bytes,
    },
    /// Send `UserMessage` with the given source and destination.
    SendUserMessage {
        src: SrcLocation,
        dst: DstLocation,
        content: Bytes,
    },
    /// Send `BootstrapRequest` to the given recipients.
    SendBootstrapRequest(Vec<SocketAddr>),
    /// Schedule a timeout after the given duration. When the timeout expires, a `HandleTimeout`
    /// command is pushed into the command queue. The token is used to identify the timeout.
    ScheduleTimeout { duration: Duration, token: u64 },
    /// Transition into the given state.
    Transition(Box<State>),
}
