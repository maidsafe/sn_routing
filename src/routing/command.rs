// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    consensus::{DkgKey, ProofShare, Vote},
    location::{DstLocation, SrcLocation},
    messages::Message,
    relocation::SignedRelocateDetails,
    section::EldersInfo,
};
use bls_dkg::key_gen::outcome::Outcome as DkgOutcome;
use bls_signature_aggregator::Proof;
use bytes::Bytes;
use std::{
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
    slice,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::sync::mpsc;

/// Command for node.
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
    /// Handle lost connection to a peer.
    HandleConnectionLost(SocketAddr),
    /// Handle peer that's been detected as lost.
    HandlePeerLost(SocketAddr),
    /// Handle vote cast either by us or some other peer.
    HandleVote { vote: Vote, proof_share: ProofShare },
    /// Handle consensus on a vote.
    HandleConsensus { vote: Vote, proof: Proof },
    /// Handle the result of a DKG session where we are one of the participants (that is, one of
    /// the proposed new elders).
    HandleDkgParticipationResult {
        dkg_key: DkgKey,
        elders_info: EldersInfo,
        result: Result<DkgOutcome, ()>,
    },
    /// Handle the result of a DKG session that we are an observer of (that is, one of the current
    /// elders).
    HandleDkgObservationResult {
        elders_info: EldersInfo,
        result: Result<bls::PublicKey, ()>,
    },
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
        message_rx: mpsc::Receiver<(Message, SocketAddr)>,
    },
}

impl Command {
    /// Convenience method to create `Command::SendMessage` with a single recipient.
    pub fn send_message_to_target(recipient: &SocketAddr, message: Bytes) -> Self {
        Self::send_message_to_targets(slice::from_ref(recipient), 1, message)
    }

    /// Convenience method to create `Command::SendMessage` with multiple recipients.
    pub fn send_message_to_targets(
        recipients: &[SocketAddr],
        delivery_group_size: usize,
        message: Bytes,
    ) -> Self {
        Self::SendMessage {
            recipients: recipients.to_vec(),
            delivery_group_size,
            message,
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
            Self::HandleDkgParticipationResult {
                dkg_key,
                elders_info,
                result,
            } => f
                .debug_struct("HandleDkgParticipationResult")
                .field("dkg_key", dkg_key)
                .field("elders_info", elders_info)
                .field("result", result)
                .finish(),
            Self::HandleDkgObservationResult {
                elders_info,
                result,
            } => f
                .debug_struct("HandleDkgObservationResult")
                .field("elders_info", elders_info)
                .field("result", result)
                .finish(),
            Self::SendMessage {
                recipients,
                delivery_group_size,
                message,
            } => f
                .debug_struct("SendMessage")
                .field("recipients", recipients)
                .field("delivery_group_size", delivery_group_size)
                .field("message", &format_args!("{:10}", hex_fmt::HexFmt(message)))
                .finish(),
            Self::SendUserMessage { src, dst, content } => f
                .debug_struct("SendUserMessage")
                .field("src", src)
                .field("dst", dst)
                .field("content", &format_args!("{:10}", hex_fmt::HexFmt(content)))
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
        }
    }
}

/// Generate unique timer token.
pub(crate) fn next_timer_token() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}
