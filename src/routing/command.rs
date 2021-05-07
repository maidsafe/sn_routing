// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::routing::Peer;
use crate::{
    agreement::{DkgFailureProofSet, Proposal},
    messages::Message,
    relocation::SignedRelocateDetails,
    section::{SectionAuthorityProvider, SectionKeyShare},
    XorName,
};
use bls_signature_aggregator::Proof;
use bytes::Bytes;
use hex_fmt::HexFmt;
use sn_messaging::{
    node::RoutingMsg, section_info::Message as SectionInfoMsg, DestInfo, Itinerary, MessageType,
};
use std::{
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::sync::mpsc;

/// Command for node.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Command {
    /// Handle `message` from `sender`.
    /// Note: `sender` is `Some` if the message was received from someone else
    /// and `None` if it is an aggregated message.
    HandleMessage {
        sender: Option<SocketAddr>,
        message: Message,
        dest_info: DestInfo,
    },
    /// Handle network info message.
    HandleSectionInfoMsg {
        sender: SocketAddr,
        message: SectionInfoMsg,
        dest_info: DestInfo,
    },
    /// Handle a timeout previously scheduled with `ScheduleTimeout`.
    HandleTimeout(u64),
    /// Handle lost connection to a peer.
    HandleConnectionLost(SocketAddr),
    /// Handle peer that's been detected as lost.
    HandlePeerLost(SocketAddr),
    /// Handle agreement on a proposal.
    HandleAgreement { proposal: Proposal, proof: Proof },
    /// Handle the outcome of a DKG session where we are one of the participants (that is, one of
    /// the proposed new elders).
    HandleDkgOutcome {
        section_auth: SectionAuthorityProvider,
        outcome: SectionKeyShare,
    },
    /// Handle a DKG failure that was observed by a majority of the DKG participants.
    HandleDkgFailure(DkgFailureProofSet),
    /// Send a message to `delivery_group_size` peers out of the given `recipients`.
    SendMessage {
        recipients: Vec<(SocketAddr, XorName)>,
        delivery_group_size: usize,
        message: MessageType,
    },
    /// Send `UserMessage` with the given source and destination.
    SendUserMessage {
        itinerary: Itinerary,
        content: Bytes,
        additional_proof_chain_key: Option<bls::PublicKey>,
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
    /// Test peer's connectivity
    TestConnectivity {
        peer: Peer,
        // Previous name if relocated.
        previous_name: Option<XorName>,
        // The key of the destination section that the joining node knows, if any.
        their_knowledge: Option<bls::PublicKey>,
    },
    /// Proposes a peer as offline
    ProposeOffline(XorName),
}

impl Command {
    /// Convenience method to create `Command::SendMessage` with a single recipient.
    pub fn send_message_to_node(
        recipient: (SocketAddr, XorName),
        message_bytes: Bytes,
        dest_info: DestInfo,
    ) -> Self {
        Self::send_message_to_nodes(vec![recipient], 1, message_bytes, dest_info)
    }

    /// Convenience method to create `Command::SendMessage` with multiple recipients.
    pub fn send_message_to_nodes(
        recipients: Vec<(SocketAddr, XorName)>,
        delivery_group_size: usize,
        message_bytes: Bytes,
        dest_info: DestInfo,
    ) -> Self {
        let msg = RoutingMsg::new(message_bytes);
        Self::SendMessage {
            recipients,
            delivery_group_size,
            message: MessageType::Routing { dest_info, msg },
        }
    }
}

impl Debug for Command {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::HandleMessage {
                sender,
                message,
                dest_info,
            } => f
                .debug_struct("HandleMessage")
                .field("sender", sender)
                .field("message", message)
                .field("dest_info", dest_info)
                .finish(),
            Self::HandleSectionInfoMsg {
                sender,
                message,
                dest_info,
            } => f
                .debug_struct("HandleSectionInfoMsg")
                .field("sender", sender)
                .field("message", message)
                .field("dest_info", dest_info)
                .finish(),
            Self::HandleTimeout(token) => f.debug_tuple("HandleTimeout").field(token).finish(),
            Self::HandleConnectionLost(addr) => {
                f.debug_tuple("HandleConnectionLost").field(addr).finish()
            }
            Self::HandlePeerLost(addr) => f.debug_tuple("HandlePeerLost").field(addr).finish(),
            Self::HandleAgreement { proposal, proof } => f
                .debug_struct("HandleAgreement")
                .field("proposal", proposal)
                .field("proof.public_key", &proof.public_key)
                .finish(),
            Self::HandleDkgOutcome {
                section_auth,
                outcome,
            } => f
                .debug_struct("HandleDkgOutcome")
                .field("section_auth", section_auth)
                .field("outcome", &outcome.public_key_set.public_key())
                .finish(),
            Self::HandleDkgFailure(proofs) => {
                f.debug_tuple("HandleDkgFailure").field(proofs).finish()
            }
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
            Self::SendUserMessage {
                itinerary,
                content,
                additional_proof_chain_key,
            } => f
                .debug_struct("SendUserMessage")
                .field("itinerary", itinerary)
                .field("content", &format_args!("{:10}", HexFmt(content)))
                .field("additional_proof_chain_key", additional_proof_chain_key)
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
            Self::TestConnectivity {
                peer,
                previous_name,
                ..
            } => f
                .debug_struct("TestConnectivity")
                .field("peer", peer)
                .field("previous_name", previous_name)
                .finish(),
            Self::ProposeOffline(name) => f.debug_tuple("ProposeOffline").field(name).finish(),
        }
    }
}

/// Generate unique timer token.
pub(crate) fn next_timer_token() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}
