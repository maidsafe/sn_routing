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
use std::{
    net::SocketAddr,
    slice,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

#[derive(Debug)]
pub(crate) enum Command {
    HandleMessage {
        // Some if the message was received from someone else
        // None if the message came from an accumulated `Vote::SendMessage`
        // TODO: consider using a custom enum for clarity
        sender: Option<SocketAddr>,
        message: Message,
    },
    HandleTimeout(u64),
    HandlePeerLost(SocketAddr),
    HandleVote {
        vote: Vote,
        proof_share: ProofShare,
    },
    SendMessage {
        recipients: Vec<SocketAddr>,
        delivery_group_size: usize,
        message: Bytes,
    },
    SendUserMessage {
        src: SrcLocation,
        dst: DstLocation,
        content: Bytes,
    },
    SendBootstrapRequest(Vec<SocketAddr>),
    ScheduleTimeout {
        duration: Duration,
        token: u64,
    },
    Transition(Box<State>),
}

pub(crate) struct Context(Vec<Command>);

impl Context {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn push(&mut self, command: Command) {
        self.0.push(command);
    }

    pub fn send_message_to_target(&mut self, recipient: &SocketAddr, message: Bytes) {
        self.send_message_to_targets(slice::from_ref(recipient), 1, message)
    }

    pub fn send_message_to_targets(
        &mut self,
        recipients: &[SocketAddr],
        delivery_group_size: usize,
        message: Bytes,
    ) {
        self.push(Command::SendMessage {
            recipients: recipients.to_vec(),
            delivery_group_size,
            message,
        })
    }

    pub fn schedule_timeout(&mut self, duration: Duration) -> u64 {
        let token = NEXT_TIMER_TOKEN.fetch_add(1, Ordering::Relaxed);
        self.push(Command::ScheduleTimeout { duration, token });
        token
    }

    pub fn into_commands(self) -> Vec<Command> {
        self.0
    }
}

static NEXT_TIMER_TOKEN: AtomicU64 = AtomicU64::new(0);
