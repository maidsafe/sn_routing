// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    consensus::{DkgFailureProofSet, ProofShare, Vote},
    location::{DstLocation, SrcLocation},
    messages::Message,
    relocation::SignedRelocateDetails,
    section::{EldersInfo, SectionKeyShare},
};
use bls_signature_aggregator::Proof;
use bytes::Bytes;
use hex_fmt::HexFmt;
use sn_messaging::{
    infrastructure::Message as InfrastructureMessage, node::NodeMessage, MessageType,
};
use std::{
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
    slice,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::sync::mpsc;

/// Command for node.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Command {
    /// Handle `message` from `sender`.
    /// Note: `sender` is `Some` if the message was received from someone else
    /// and `None` if it came from an accumulated `Vote::SendMessage`
    HandleMessage {
        sender: Option<SocketAddr>,
        message: Message,
    },
    /// Handle infrastructure query message.
    HandleInfrastructureMessage {
        sender: SocketAddr,
        message: InfrastructureMessage,
    },
    /// Handle a timeout previously scheduled with `ScheduleTimeout`.
    HandleTimeout(u64),
    /// Handle lost connection to a peer.
    HandleConnectionLost(SocketAddr),
    /// Handle peer that's been detected as lost.
    HandlePeerLost(SocketAddr),
    /// Handle vote cast either by us or some other peer.
    HandleVote { vote: Vote, proof_share: ProofShare },
    /// Handle consensus on a vote.
    HandleConsensus { vote: Vote, proof: Proof },
    /// Handle the outcome of a DKG session where we are one of the participants (that is, one of
    /// the proposed new elders).
    HandleDkgOutcome {
        elders_info: EldersInfo,
        outcome: SectionKeyShare,
    },
    /// Handle a DKG failure that was observed by a majority of the DKG participants.
    HandleDkgFailure {
        elders_info: EldersInfo,
        proofs: DkgFailureProofSet,
    },
    /// Send a message to `delivery_group_size` peers out of the given `recipients`.
    SendMessage {
        recipients: Vec<SocketAddr>,
        delivery_group_size: usize,
        message: MessageType,
    },
    /// Send `UserMessage` with the given source and destination.
    SendUserMessage {
        src: SrcLocation,
        dst: DstLocation,
        content: Bytes,
    },
    /// Schedule a timeout after the given duration. When the timeout expires, a `HandleTimeout`
    /// command is raised. The token is used to identify the timeout.
    ScheduleTimeout { duration: Duration, token: u64 },
    /// Relocate
    Relocate {
        /// Contacts to re-bootstrap to
        bootstrap_addrs: Vec<SocketAddr>,
        /// Details of the relocation
        details: SignedRelocateDetails,
        /// Message receiver to pass to the bootstrap task.
        message_rx: mpsc::Receiver<(MessageType, SocketAddr)>,
    },
    /// Attempt to set JoinsAllowed flag.
    SetJoinsAllowed(bool),
}

impl Command {
    /// Convenience method to create `Command::SendMessage` with a single recipient.
    pub fn send_message_to_node(recipient: &SocketAddr, message_bytes: Bytes) -> Self {
        Self::send_message_to_nodes(slice::from_ref(recipient), 1, message_bytes)
    }

    /// Convenience method to create `Command::SendMessage` with multiple recipients.
    pub fn send_message_to_nodes(
        recipients: &[SocketAddr],
        delivery_group_size: usize,
        message_bytes: Bytes,
    ) -> Self {
        let node_msg = NodeMessage::new(message_bytes);
        Self::SendMessage {
            recipients: recipients.to_vec(),
            delivery_group_size,
            message: MessageType::NodeMessage(node_msg),
        }
    }
}

impl Debug for Command {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::HandleMessage { sender, message } => f
                .debug_struct("HandleMessage")
                .field("sender", sender)
                .field("message", message)
                .finish(),
            Self::HandleInfrastructureMessage { sender, message } => f
                .debug_struct("HandleInfrastructureMessage")
                .field("sender", sender)
                .field("message", message)
                .finish(),
            Self::HandleTimeout(token) => f.debug_tuple("HandleTimeout").field(token).finish(),
            Self::HandleConnectionLost(addr) => {
                f.debug_tuple("HandleConnectionLost").field(addr).finish()
            }
            Self::HandlePeerLost(addr) => f.debug_tuple("HandlePeerLost").field(addr).finish(),
            Self::HandleVote { vote, proof_share } => f
                .debug_struct("HandleVote")
                .field("vote", vote)
                .field("proof_share.index", &proof_share.index)
                .finish(),
            Self::HandleConsensus { vote, proof } => f
                .debug_struct("HandleConsensus")
                .field("vote", vote)
                .field("proof.public_key", &proof.public_key)
                .finish(),
            Self::HandleDkgOutcome {
                elders_info,
                outcome,
            } => f
                .debug_struct("HandleDkgOutcome")
                .field("elders_info", elders_info)
                .field("outcome", &outcome.public_key_set.public_key())
                .finish(),
            Self::HandleDkgFailure {
                elders_info,
                proofs,
            } => f
                .debug_struct("HandleDkgFailure")
                .field("elders_info", elders_info)
                .field("proofs", proofs)
                .finish(),
            Self::SendMessage {
                recipients,
                delivery_group_size,
                message,
            } => f
                .debug_struct("SendMessage")
                .field("recipients", recipients)
                .field("delivery_group_size", delivery_group_size)
                .field("message", message)
                .finish(),
            Self::SendUserMessage { src, dst, content } => f
                .debug_struct("SendUserMessage")
                .field("src", src)
                .field("dst", dst)
                .field("content", &format_args!("{:10}", HexFmt(content)))
                .finish(),
            Self::ScheduleTimeout { duration, token } => f
                .debug_struct("ScheduleTimeout")
                .field("duration", duration)
                .field("token", token)
                .finish(),
            Self::Relocate {
                bootstrap_addrs,
                details,
                ..
            } => f
                .debug_struct("Relocate")
                .field("bootstrap_addrs", bootstrap_addrs)
                .field("details", details)
                .finish(),
            Self::SetJoinsAllowed(joins_allowed) => f
                .debug_tuple("SetJoinsAllowed")
                .field(joins_allowed)
                .finish(),
        }
    }
}

/// Generate unique timer token.
pub(crate) fn next_timer_token() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}
