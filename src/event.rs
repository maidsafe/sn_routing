// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    agreement::SectionSigned,
    section::{NodeOp, OnlineNodes, SectionAuthorityProvider, SectionChain},
};
use bls_signature_aggregator::Proof;
use bytes::Bytes;
use ed25519_dalek::Keypair;
use hex_fmt::HexFmt;
pub use qp2p::{RecvStream, SendStream};
use sn_messaging::{client::ClientMsg, DstLocation, EndUser, SrcLocation};
use std::{
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
    sync::Arc,
};
use xor_name::XorName;

/// An Event raised by a `Node` or `Client` via its event sender.
///
/// These are sent by sn_routing to the library's user. It allows the user to handle requests and
/// responses, and to react to changes in the network.
///
/// `Request` and `Response` events from section locations are only raised once the majority has
/// been reached, i.e. enough members of the section have sent the same message.
#[allow(clippy::large_enum_variant)]
pub enum Event {
    /// This event will be fired when:
    ///    1, any membership change (join or left)
    ///    2, any SAP change (including split)
    SectionChanged {
        /// Current SAP could be equal to previous SAP when:
        ///   1, This is the genesis join event.
        ///   2, The event is regarding an adult change.
        previous_section_auth: SectionSigned<SectionAuthorityProvider>,
        /// The churn op triggering this event to be fired.
        /// Could be None when:
        ///   1, during split
        ///   2, during elder promotion or demotion
        ///   3, updated via sync
        node_op: Option<SectionSigned<NodeOp>>,
        /// Alread holds the current SAP.
        online_nodes: OnlineNodes,
    },
    /// Received a message.
    MessageReceived {
        /// The content of the message.
        content: Bytes,
        /// The source location that sent the message.
        src: SrcLocation,
        /// The destination location that receives the message.
        dst: DstLocation,
        /// The proof if the message was set to be aggregated at source.
        proof: Option<Proof>,
        /// The proof chain for the message, if any.
        proof_chain: Option<SectionChain>,
    },
    /// This node has started relocating to other section. Will be followed by
    /// `Relocated` when the node finishes joining the destination section.
    RelocationStarted {
        /// Previous name before relocation
        previous_name: XorName,
    },
    /// This node has completed relocation to other section.
    Relocated {
        /// Old name before the relocation.
        previous_name: XorName,
        /// New keypair to be used after relocation.
        new_keypair: Arc<Keypair>,
    },
    /// Disconnected or failed to connect - restart required.
    RestartRequired,
    /// Received a message from a client node.
    ClientMsgReceived {
        /// The content of the message.
        msg: Box<ClientMsg>,
        /// The SocketAddr and PublicKey that sent the message.
        /// (Note: socket_id will be a random hash, to map against the actual socketaddr)
        user: EndUser,
    },
    /// Failed in sending a message to client, or connection to client is lost
    ClientLost(SocketAddr),
}

impl Debug for Event {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match self {
            Self::SectionChanged {
                previous_section_auth,
                node_op,
                online_nodes,
            } => formatter
                .debug_struct("SectionChanged")
                .field("previous_section_auth", &previous_section_auth.value)
                .field("node_op", node_op)
                .field("online_nodes", online_nodes)
                .finish(),
            Self::MessageReceived {
                content, src, dst, ..
            } => write!(
                formatter,
                "MessageReceived {{ content: \"{:<8}\", src: {:?}, dst: {:?} }}",
                HexFmt(content),
                src,
                dst
            ),
            Self::RelocationStarted { previous_name } => formatter
                .debug_struct("RelocationStarted")
                .field("previous_name", previous_name)
                .finish(),
            Self::Relocated {
                previous_name,
                new_keypair,
            } => formatter
                .debug_struct("Relocated")
                .field("previous_name", previous_name)
                .field("new_keypair", new_keypair)
                .finish(),
            Self::RestartRequired => write!(formatter, "RestartRequired"),
            Self::ClientMsgReceived { msg, user, .. } => write!(
                formatter,
                "ClientMsgReceived {{ msg: {:?}, src: {:?} }}",
                msg, user,
            ),
            Self::ClientLost(addr) => write!(formatter, "ClientLost({:?})", addr),
        }
    }
}
