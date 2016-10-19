// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use authority::Authority;
use append_types::AppendWrapper;
#[cfg(not(feature = "use-mock-crust"))]
use crust::PeerId;
use data::{Data, DataIdentifier};
use error::RoutingError;
use id::{FullId, PublicId};
#[cfg(feature = "use-mock-crust")]
use mock_crust::crust::PeerId;
use lru_time_cache::LruCache;
use maidsafe_utilities;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use rust_sodium::crypto::{box_, sign};
use rust_sodium::crypto::hash::sha256;
use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;
use types::MessageId;
use utils;
use xor_name::XorName;

/// The maximal length of a user message part, in bytes.
const MAX_PART_LEN: usize = 20 * 1024;

/// Get and refresh messages from nodes have a high priority: They relocate data under churn and are
/// critical to prevent data loss.
pub const RELOCATE_PRIORITY: u8 = 1;
/// Other requests have a lower priority: If they fail due to high traffic, the sender retries.
pub const DEFAULT_PRIORITY: u8 = 2;
/// `Get` requests from clients have the lowest priority: If bandwidth is insufficient, the network
/// needs to prioritise maintaining its structure, data and consensus.
pub const CLIENT_GET_PRIORITY: u8 = 3;

/// Wrapper of all messages.
///
/// This is the only type allowed to be sent / received on the network.
#[derive(Debug, RustcEncodable, RustcDecodable)]
pub enum Message {
    /// A message sent between two nodes directly
    Direct(DirectMessage),
    /// A message sent across the network (in transit)
    Hop(HopMessage),
    /// A direct message sent via a tunnel because the nodes could not connect directly
    TunnelDirect {
        /// The wrapped message
        content: DirectMessage,
        /// The sender
        src: PeerId,
        /// The receiver
        dst: PeerId,
    },
    /// A hop message sent via a tunnel because the nodes could not connect directly
    TunnelHop {
        /// The wrapped message
        content: HopMessage,
        /// The sender
        src: PeerId,
        /// The receiver
        dst: PeerId,
    },
}

/// Messages sent via a direct connection.
///
/// Allows routing to directly send specific messages between nodes.
#[derive(RustcEncodable, RustcDecodable)]
pub enum DirectMessage {
    /// Sent from the bootstrap node to a client in response to `ClientIdentify`.
    BootstrapIdentify {
        /// The bootstrap node's keys and name.
        public_id: ::id::PublicId,
        /// The dynamically calculated quorum size the client's accumulator should use.
        current_quorum_size: usize,
    },
    /// Sent to the client to indicate that this node is not available as a bootstrap node.
    BootstrapDeny,
    /// Sent from a newly connected client to the bootstrap node to inform it about the client's
    /// public ID.
    ClientIdentify {
        /// Serialised keys and claimed name.
        serialised_public_id: Vec<u8>,
        /// Signature of the client.
        signature: sign::Signature,
        /// Indicate whether we intend to remain a client, as opposed to becoming a routing node.
        client_restriction: bool,
    },
    /// Sent from a node to a node, to allow the latter to add the former to its routing table.
    NodeIdentify {
        /// Keys and claimed name, serialised outside routing.
        serialised_public_id: Vec<u8>,
        /// Signature of the originator of this message.
        signature: sign::Signature,
    },
    /// Sent from a client that became a full routing node. The recipient can remove it from its
    /// client map.
    ClientToNode,
    /// Sent from a node that found a new node in the network to all its contacts who might need to
    /// add the new node to their routing table.
    NewNode(PublicId),
    /// Sent to a node that, on the addition of a node at a given bucket index, we no longer need to
    /// be connected to.
    ConnectionUnneeded(XorName),
    /// Sent from a node that needs a tunnel to be able to connect to the given peer.
    TunnelRequest(PeerId),
    /// Sent as a response to `TunnelRequest` if the node can act as a tunnel.
    TunnelSuccess(PeerId),
    /// Sent from a tunnel node to indicate that the given peer has disconnected.
    TunnelClosed(PeerId),
    /// Sent to a tunnel node to indicate the tunnel is not needed any more.
    TunnelDisconnect(PeerId),
}

impl DirectMessage {
    /// The priority Crust should send this message with.
    pub fn priority(&self) -> u8 {
        0 // Currently all direct messages are small and should be treated with high priority.
    }
}

/// And individual hop message that represents a part of the route of a message in transit.
///
/// To relay a `SignedMessage` via another node, the `SignedMessage` is wrapped in a `HopMessage`.
/// The `signature` is from the node that sends this directly to a node in its routing table. To
/// prevent Man-in-the-middle attacks, the `content` is signed by the original sender.
#[derive(RustcEncodable, RustcDecodable)]
pub struct HopMessage {
    /// Wrapped signed message.
    content: SignedMessage,
    /// Route number; corresponds to the index of the peer in the group of target peers being
    /// considered for the next hop.
    route: u8,
    /// Every node this has already been sent to.
    sent_to: Vec<XorName>,
    /// Signature to be validated against `name`'s public key.
    signature: sign::Signature,
}

impl HopMessage {
    /// Wrap `content` for transmission to the next hop and sign it.
    pub fn new(content: SignedMessage,
               route: u8,
               sent_to: Vec<XorName>,
               sign_key: &sign::SecretKey)
               -> Result<HopMessage, RoutingError> {
        let bytes_to_sign = try!(serialise(&content));
        Ok(HopMessage {
            content: content,
            route: route,
            sent_to: sent_to,
            signature: sign::sign_detached(&bytes_to_sign, sign_key),
        })
    }

    /// Validate that the message is signed by `verification_key` contained in message.
    ///
    /// This does not imply that the message came from a known node. That requires a check against
    /// the routing table to identify the name associated with the `verification_key`.
    pub fn verify(&self, verification_key: &sign::PublicKey) -> Result<(), RoutingError> {
        let signed_bytes = try!(serialise(&self.content));
        if sign::verify_detached(&self.signature, &signed_bytes, verification_key) {
            Ok(())
        } else {
            Err(RoutingError::FailedSignature)
        }
    }

    /// Returns the `SignedMessage` and the `name` of the previous routing node.
    ///
    /// Does not validate the message! [#verify] must be called to ensure that the sender is valid
    /// and signed the message.
    pub fn content(&self) -> &SignedMessage {
        &self.content
    }

    pub fn route(&self) -> u8 {
        self.route
    }

    pub fn sent_to(&self) -> &Vec<XorName> {
        &self.sent_to
    }
}

/// Wrapper around a routing message, signed by the originator of the message.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, RustcEncodable, RustcDecodable)]
pub struct SignedMessage {
    /// A request or response type message.
    content: RoutingMessage,
    /// Claimed public ID of a node or client.
    ///
    /// For clients this is easily verifiable since their name is computed from the ID. For nodes it
    /// needs to be confirmed by their `NodeManager`.
    public_id: PublicId,
    signature: sign::Signature,
}

impl SignedMessage {
    /// Creates a `SignedMessage` with the given `content` and signed by the given `full_id`.
    pub fn new(content: RoutingMessage, full_id: &FullId) -> Result<SignedMessage, RoutingError> {
        let bytes_to_sign = try!(serialise(&(&content, full_id.public_id())));
        Ok(SignedMessage {
            content: content,
            public_id: *full_id.public_id(),
            signature: sign::sign_detached(&bytes_to_sign, full_id.signing_private_key()),
        })
    }

    /// Confirms the signature against the claimed public ID.
    pub fn check_integrity(&self) -> Result<(), RoutingError> {
        let signed_bytes = try!(serialise(&(&self.content, &self.public_id)));
        if sign::verify_detached(&self.signature,
                                 &signed_bytes,
                                 self.public_id().signing_public_key()) {
            Ok(())
        } else {
            Err(RoutingError::FailedSignature)
        }
    }

    /// The routing message that was signed.
    pub fn routing_message(&self) -> &RoutingMessage {
        &self.content
    }

    /// The `PublicId` associated with the signed message
    pub fn public_id(&self) -> &PublicId {
        &self.public_id
    }

    /// The priority Crust should send this message with.
    pub fn priority(&self) -> u8 {
        self.content.priority()
    }
}

/// A routing message with source and destination authorities.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Debug, RustcEncodable, RustcDecodable)]
pub struct RoutingMessage {
    /// Source authority
    pub src: Authority,
    /// Destination authority
    pub dst: Authority,
    /// The message content
    pub content: MessageContent,
}

impl RoutingMessage {
    /// Returns the priority Crust should send this message with.
    pub fn priority(&self) -> u8 {
        self.content.priority()
    }

    /// Replaces this message's contents with its hash.
    pub fn to_grp_msg_hash(&self) -> Result<RoutingMessage, RoutingError> {
        let content = match self.content {
            MessageContent::GetNodeNameResponse { .. } |
            MessageContent::GetCloseGroupResponse { .. } |
            MessageContent::UserMessagePart { .. } => {
                let serialised_msg = try!(serialise(self));
                MessageContent::GroupMessageHash(sha256::hash(&serialised_msg), self.priority())
            }
            _ => self.content.clone(),
        };
        Ok(RoutingMessage {
            src: self.src.clone(),
            dst: self.dst.clone(),
            content: content,
        })
    }
}

/// The routing message types
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, RustcEncodable, RustcDecodable)]
pub enum MessageContent {
    // ---------- Internal ------------
    /// Ask the network to alter your `PublicId` name.
    ///
    /// This is sent by a `Client` to its `NaeManager` with the intent to become a routing node with
    /// a new name chosen by the `NaeManager`.
    GetNodeName {
        /// The client's `PublicId` (public keys and name)
        current_id: PublicId,
        /// The message's unique identifier.
        message_id: MessageId,
    },
    /// Notify a joining node's `NodeManager` so that it expects a `GetCloseGroup` request from it.
    ExpectCloseNode {
        /// The joining node's `PublicId` (public keys and name)
        expect_id: PublicId,
        /// The client's current authority.
        client_auth: Authority,
        /// The message's unique identifier.
        message_id: MessageId,
    },
    /// Request the `PublicId`s of the recipient's close group.
    ///
    /// This is sent from a joining node to its `NodeManager` to request the `PublicId`s of the
    /// `NodeManager`'s members.
    GetCloseGroup(MessageId),
    /// Send our connection_info encrypted to a node we wish to connect to and have the keys for.
    ConnectionInfo {
        /// Encrypted Crust connection info.
        encrypted_connection_info: Vec<u8>,
        /// Nonce used to provide a salt in the encrypted message.
        nonce_bytes: [u8; box_::NONCEBYTES],
        // TODO: The receiver should have that in the node_id_cache.
        /// The sender's public ID.
        public_id: PublicId,
    },
    /// Reply with the new `PublicId` for the joining node.
    ///
    /// Sent from the `NodeManager` to the `Client`.
    GetNodeNameResponse {
        /// Supplied `PublicId`, but with the new name
        relocated_id: PublicId,
        /// Our close group `PublicId`s.
        close_group_ids: Vec<PublicId>,
        /// The message's unique identifier.
        message_id: MessageId,
    },
    /// Return the close `PublicId`s back to the requester.
    ///
    /// Sent from a `NodeManager` to a node or client.
    GetCloseGroupResponse {
        /// Our close group `PublicId`s.
        close_group_ids: Vec<PublicId>,
        /// The message ID.
        message_id: MessageId,
    },
    /// Acknowledge receipt of any message except an `Ack`. It contains the hash of the
    /// received message and the priority.
    Ack(u64, u8),
    /// The hash of a `RoutingMessage`. This is sent by the source group authority members as a
    /// confirmation, so that only one of them needs to send the full message. The second field is
    /// the message priority.
    GroupMessageHash(sha256::Digest, u8),
    /// Part of a user-facing message
    UserMessagePart {
        /// The hash of this user message.
        hash: u64,
        /// The number of parts.
        part_count: u32,
        /// The index of this part.
        part_index: u32,
        /// The message priority.
        priority: u8,
        /// Is the message cacheable?
        cacheable: bool,
        /// The `part_index`-th part of the serialised user message.
        payload: Vec<u8>,
    },
}

impl MessageContent {
    /// The priority Crust should send this message with.
    pub fn priority(&self) -> u8 {
        match *self {
            MessageContent::Ack(_, priority) |
            MessageContent::GroupMessageHash(_, priority) |
            MessageContent::UserMessagePart { priority, .. } => priority,
            _ => 0,
        }
    }
}

impl Debug for DirectMessage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            DirectMessage::BootstrapIdentify { ref public_id, ref current_quorum_size } => {
                write!(formatter,
                       "BootstrapIdentify {{ {:?}, {:?} }}",
                       public_id,
                       current_quorum_size)
            }
            DirectMessage::BootstrapDeny => write!(formatter, "BootstrapDeny"),
            DirectMessage::ClientToNode => write!(formatter, "ClientToNode"),
            DirectMessage::ClientIdentify { client_restriction: true, .. } => {
                write!(formatter, "ClientIdentify (client only)")
            }
            DirectMessage::ClientIdentify { client_restriction: false, .. } => {
                write!(formatter, "ClientIdentify (joining node)")
            }
            DirectMessage::NodeIdentify { .. } => write!(formatter, "NodeIdentify {{ .. }}"),
            DirectMessage::NewNode(ref public_id) => write!(formatter, "NewNode({:?})", public_id),
            DirectMessage::ConnectionUnneeded(ref name) => {
                write!(formatter, "ConnectionUnneeded({:?})", name)
            }
            DirectMessage::TunnelRequest(peer_id) => {
                write!(formatter, "TunnelRequest({:?})", peer_id)
            }
            DirectMessage::TunnelSuccess(peer_id) => {
                write!(formatter, "TunnelSuccess({:?})", peer_id)
            }
            DirectMessage::TunnelClosed(peer_id) => {
                write!(formatter, "TunnelClosed({:?})", peer_id)
            }
            DirectMessage::TunnelDisconnect(peer_id) => {
                write!(formatter, "TunnelDisconnect({:?})", peer_id)
            }
        }
    }
}

impl Debug for HopMessage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter,
               "HopMessage {{ content: {:?}, route: {}, sent_to: .., signature: .. }}",
               self.content,
               self.route)
    }
}

impl Debug for SignedMessage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter,
               "SignedMessage {{ content: {:?}, public_id: {:?}, signature: .. }}",
               self.content,
               self.public_id)
    }
}

impl Debug for MessageContent {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            MessageContent::GetNodeName { ref current_id, ref message_id } => {
                write!(formatter,
                       "GetNodeName {{ {:?}, {:?} }}",
                       current_id,
                       message_id)
            }
            MessageContent::ExpectCloseNode { ref expect_id, ref client_auth, ref message_id } => {
                write!(formatter,
                       "ExpectCloseNode {{ {:?}, {:?}, {:?} }}",
                       expect_id,
                       client_auth,
                       message_id)
            }
            MessageContent::GetCloseGroup(id) => write!(formatter, "GetCloseGroup({:?})", id),
            MessageContent::ConnectionInfo { .. } => write!(formatter, "ConnectionInfo {{ .. }}"),
            MessageContent::GetNodeNameResponse { ref relocated_id,
                                                  ref close_group_ids,
                                                  ref message_id } => {
                write!(formatter,
                       "GetNodeNameResponse {{ {:?}, {:?}, {:?} }}",
                       close_group_ids,
                       relocated_id,
                       message_id)
            }
            MessageContent::GetCloseGroupResponse { ref close_group_ids, message_id } => {
                write!(formatter,
                       "GetCloseGroupResponse {{ {:?}, {:?} }}",
                       close_group_ids,
                       message_id)
            }
            MessageContent::Ack(ref ack, priority) => {
                write!(formatter, "Ack({:x}, {})", ack, priority)
            }
            MessageContent::GroupMessageHash(ref hash, priority) => {
                write!(formatter,
                       "GroupMessageHash({}, {})",
                       utils::format_binary_array(&hash.0),
                       priority)
            }
            MessageContent::UserMessagePart { hash, part_count, part_index, priority, .. } => {
                write!(formatter,
                       "UserMessagePart {{ {}/{}, priority: {}  {:x}}}",
                       part_index + 1,
                       part_count,
                       priority,
                       hash)
            }
        }
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Debug, Hash, RustcEncodable, RustcDecodable)]
/// A user-visible message: a `Request` or `Response`.
pub enum UserMessage {
    /// A user-visible request message.
    Request(Request),
    /// A user-visible response message.
    Response(Response),
}

impl UserMessage {
    /// Splits up the message into smaller `MessageContent` parts, which can individually be sent
    /// and routed, and then be put back together by the receiver.
    pub fn to_parts(&self, priority: u8) -> Result<Vec<MessageContent>, RoutingError> {
        // TODO: This internally serialises the message - remove that duplicated work!
        let hash = maidsafe_utilities::big_endian_sip_hash(self);
        let payload = try!(serialise(self));
        let len = payload.len();
        let part_count = (len + MAX_PART_LEN - 1) / MAX_PART_LEN;

        Ok((0..part_count)
            .map(|i| {
                MessageContent::UserMessagePart {
                    hash: hash,
                    part_count: part_count as u32,
                    part_index: i as u32,
                    cacheable: self.is_cacheable(),
                    payload: payload[(i * len / part_count)..((i + 1) * len / part_count)].to_vec(),
                    priority: priority,
                }
            })
            .collect())
    }

    /// Puts the given parts of a serialised message together and verifies that it matches the
    /// given hash code. If it does, returns the `UserMessage`.
    pub fn from_parts<'a, I: Iterator<Item = &'a Vec<u8>>>(hash: u64,
                                                           parts: I)
                                                           -> Result<UserMessage, RoutingError> {
        let mut payload = Vec::new();
        for part in parts {
            payload.extend_from_slice(part);
        }
        let user_msg = try!(deserialise(&payload[..]));
        if hash != maidsafe_utilities::big_endian_sip_hash(&user_msg) {
            Err(RoutingError::HashMismatch)
        } else {
            Ok(user_msg)
        }
    }

    fn is_cacheable(&self) -> bool {
        match *self {
            UserMessage::Request(ref request) => request.is_cacheable(),
            UserMessage::Response(ref response) => response.is_cacheable(),
        }
    }
}

/// Request message types
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, RustcEncodable, RustcDecodable)]
pub enum Request {
    /// Message from upper layers sending network state on any network churn event.
    Refresh(Vec<u8>, MessageId),
    /// Ask for data from network, passed from API with data name as parameter
    Get(DataIdentifier, MessageId),
    /// Put data to network. Provide actual data as parameter
    Put(Data, MessageId),
    /// Post data to network. Provide actual data as parameter
    Post(Data, MessageId),
    /// Delete data from network. Provide actual data as parameter
    Delete(Data, MessageId),
    /// Append an item to an appendable data chunk.
    Append(AppendWrapper, MessageId),
    /// Get account information for Client with given ID
    GetAccountInfo(MessageId),
}

/// Response message types
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, RustcEncodable, RustcDecodable)]
pub enum Response {
    /// Reply with the requested data (may not be ignored)
    ///
    /// Sent from a `ManagedNode` to an `NaeManager`, and from there to a `Client`, although this
    /// may be shortcut if the data is in a node's cache.
    GetSuccess(Data, MessageId),
    /// Success token for Put (may be ignored)
    PutSuccess(DataIdentifier, MessageId),
    /// Success token for Post (may be ignored)
    PostSuccess(DataIdentifier, MessageId),
    /// Success token for delete (may be ignored)
    DeleteSuccess(DataIdentifier, MessageId),
    /// Success token for append (may be ignored)
    AppendSuccess(DataIdentifier, MessageId),
    /// Response containing account information for requested Client account
    GetAccountInfoSuccess {
        /// Unique message identifier
        id: MessageId,
        /// Amount of data stored on the network by this Client
        data_stored: u64,
        /// Amount of network space available to this Client
        space_available: u64,
    },
    /// Error for `Get`, includes signed request to prevent injection attacks
    GetFailure {
        /// Unique message identifier
        id: MessageId,
        /// ID of the affected data chunk
        data_id: DataIdentifier,
        /// Error type sent back, may be injected from upper layers
        external_error_indicator: Vec<u8>,
    },
    /// Error for Put, includes signed request to prevent injection attacks
    PutFailure {
        /// Unique message identifier
        id: MessageId,
        /// ID of the affected data chunk
        data_id: DataIdentifier,
        /// Error type sent back, may be injected from upper layers
        external_error_indicator: Vec<u8>,
    },
    /// Error for Post, includes signed request to prevent injection attacks
    PostFailure {
        /// Unique message identifier
        id: MessageId,
        /// ID of the affected data chunk
        data_id: DataIdentifier,
        /// Error type sent back, may be injected from upper layers
        external_error_indicator: Vec<u8>,
    },
    /// Error for delete, includes signed request to prevent injection attacks
    DeleteFailure {
        /// Unique message identifier
        id: MessageId,
        /// ID of the affected data chunk
        data_id: DataIdentifier,
        /// Error type sent back, may be injected from upper layers
        external_error_indicator: Vec<u8>,
    },
    /// Error for append, includes signed request to prevent injection attacks
    AppendFailure {
        /// Unique message identifier
        id: MessageId,
        /// ID of the affected data chunk
        data_id: DataIdentifier,
        /// Error type sent back, may be injected from upper layers
        external_error_indicator: Vec<u8>,
    },
    /// Error for `GetAccountInfo`
    GetAccountInfoFailure {
        /// Unique message identifier
        id: MessageId,
        /// Error type sent back, may be injected from upper layers
        external_error_indicator: Vec<u8>,
    },
}

impl Request {
    /// The priority Crust should send this message with.
    pub fn priority(&self) -> u8 {
        match *self {
            Request::Refresh(..) => 2,
            Request::Get(..) |
            Request::GetAccountInfo(..) => 3,
            Request::Append(..) => 4,
            Request::Put(ref data, _) |
            Request::Post(ref data, _) |
            Request::Delete(ref data, _) => {
                match *data {
                    Data::Structured(..) => 4,
                    _ => 5,
                }
            }
        }
    }

    /// Is the response corresponding to this request cacheable?
    pub fn is_cacheable(&self) -> bool {
        if let Request::Get(DataIdentifier::Immutable(..), _) = *self {
            true
        } else {
            false
        }
    }
}

impl Response {
    /// The priority Crust should send this message with.
    pub fn priority(&self) -> u8 {
        match *self {
            Response::GetSuccess(ref data, _) => {
                match *data {
                    Data::Structured(..) => 4,
                    _ => 5,
                }
            }
            Response::PutSuccess(..) |
            Response::PostSuccess(..) |
            Response::DeleteSuccess(..) |
            Response::AppendSuccess(..) |
            Response::GetAccountInfoSuccess { .. } |
            Response::GetFailure { .. } |
            Response::PutFailure { .. } |
            Response::PostFailure { .. } |
            Response::DeleteFailure { .. } |
            Response::AppendFailure { .. } |
            Response::GetAccountInfoFailure { .. } => 3,
        }
    }

    /// Is this response cacheable?
    pub fn is_cacheable(&self) -> bool {
        if let Response::GetSuccess(Data::Immutable(..), _) = *self {
            true
        } else {
            false
        }
    }
}

impl Debug for Request {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Request::Refresh(ref data, ref message_id) => {
                write!(formatter,
                       "Refresh({}, {:?})",
                       utils::format_binary_array(data),
                       message_id)
            }
            Request::Get(ref data_request, ref message_id) => {
                write!(formatter, "Get({:?}, {:?})", data_request, message_id)
            }
            Request::Put(ref data, ref message_id) => {
                write!(formatter, "Put({:?}, {:?})", data, message_id)
            }
            Request::Post(ref data, ref message_id) => {
                write!(formatter, "Post({:?}, {:?})", data, message_id)
            }
            Request::Delete(ref data, ref message_id) => {
                write!(formatter, "Delete({:?}, {:?})", data, message_id)
            }
            Request::Append(ref wrapper, ref message_id) => {
                write!(formatter, "Append({:?}, {:?})", wrapper, message_id)
            }
            Request::GetAccountInfo(ref message_id) => {
                write!(formatter, "GetAccountInfo({:?})", message_id)
            }
        }
    }
}

impl Debug for Response {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Response::GetSuccess(ref data, ref message_id) => {
                write!(formatter, "GetSuccess({:?}, {:?})", data, message_id)
            }
            Response::PutSuccess(ref name, ref message_id) => {
                write!(formatter, "PutSuccess({:?}, {:?})", name, message_id)
            }
            Response::PostSuccess(ref name, ref message_id) => {
                write!(formatter, "PostSuccess({:?}, {:?})", name, message_id)
            }
            Response::DeleteSuccess(ref name, ref message_id) => {
                write!(formatter, "DeleteSuccess({:?}, {:?})", name, message_id)
            }
            Response::AppendSuccess(ref name, ref message_id) => {
                write!(formatter, "AppendSuccess({:?}, {:?})", name, message_id)
            }
            Response::GetAccountInfoSuccess { ref id, .. } => {
                write!(formatter, "GetAccountInfoSuccess {{ {:?}, .. }}", id)
            }
            Response::GetFailure { ref id, ref data_id, .. } => {
                write!(formatter, "GetFailure {{ {:?}, {:?}, .. }}", id, data_id)
            }
            Response::PutFailure { ref id, ref data_id, .. } => {
                write!(formatter, "PutFailure {{ {:?}, {:?}, .. }}", id, data_id)
            }
            Response::PostFailure { ref id, ref data_id, .. } => {
                write!(formatter, "PostFailure {{ {:?}, {:?}, .. }}", id, data_id)
            }
            Response::DeleteFailure { ref id, ref data_id, .. } => {
                write!(formatter, "DeleteFailure {{ {:?}, {:?}, .. }}", id, data_id)
            }
            Response::AppendFailure { ref id, ref data_id, .. } => {
                write!(formatter, "AppendFailure {{ {:?}, {:?}, .. }}", id, data_id)
            }
            Response::GetAccountInfoFailure { ref id, .. } => {
                write!(formatter, "GetAccountInfoFailure {{ {:?}, .. }}", id)
            }
        }
    }
}

/// This assembles `UserMessage`s from `UserMessagePart`s.
/// It maps `(hash, part_count)` of an incoming `UserMessage` to the map containing
/// all `UserMessagePart`s that have already arrived, by `part_index`.
pub struct UserMessageCache(LruCache<(u64, u32), BTreeMap<u32, Vec<u8>>>);

impl UserMessageCache {
    pub fn with_expiry_duration(duration: Duration) -> Self {
        UserMessageCache(LruCache::with_expiry_duration(duration))
    }

    /// Adds the given one to the cache of received message parts, returning a `UserMessage` if the
    /// given part was the last missing piece of it.
    pub fn add(&mut self,
               hash: u64,
               part_count: u32,
               part_index: u32,
               payload: Vec<u8>)
               -> Option<UserMessage> {
        {
            let entry = self.0.entry((hash, part_count)).or_insert_with(BTreeMap::new);
            let _ = entry.insert(part_index, payload);
            if entry.len() != part_count as usize {
                return None;
            }
        }

        self.0
            .remove(&(hash, part_count))
            .and_then(|part_map| UserMessage::from_parts(hash, part_map.values()).ok())
    }
}

#[cfg(test)]
mod test {
    extern crate rand;

    use super::*;
    use authority::Authority;
    use data::Data;
    use id::FullId;
    use immutable_data::ImmutableData;
    use maidsafe_utilities;
    use maidsafe_utilities::serialisation::serialise;
    use rust_sodium::crypto::sign;
    use types::MessageId;
    use xor_name::XorName;

    #[test]
    fn signed_message_check_integrity() {
        let name: XorName = rand::random();
        let routing_message = RoutingMessage {
            src: Authority::ClientManager(name),
            dst: Authority::ClientManager(name),
            content: MessageContent::GetCloseGroup(MessageId::zero()),
        };
        let full_id = FullId::new();
        let signed_message_result = SignedMessage::new(routing_message.clone(), &full_id);

        assert!(signed_message_result.is_ok());

        let mut signed_message = unwrap!(signed_message_result);

        assert_eq!(routing_message, *signed_message.routing_message());
        assert_eq!(full_id.public_id(), signed_message.public_id());

        let check_integrity_result = signed_message.check_integrity();

        assert!(check_integrity_result.is_ok());

        let full_id = FullId::new();
        let bytes_to_sign = unwrap!(serialise(&(&routing_message, full_id.public_id())));
        let signature = sign::sign_detached(&bytes_to_sign, full_id.signing_private_key());

        signed_message.signature = signature;

        let check_integrity_result = signed_message.check_integrity();

        assert!(check_integrity_result.is_err());
    }

    #[test]
    fn grp_msg_hash() {
        let data_bytes: Vec<u8> = (0..10).map(|i| i as u8).collect();
        let data = Data::Immutable(ImmutableData::new(data_bytes));
        let user_msg = UserMessage::Request(Request::Put(data, MessageId::new()));
        let parts = unwrap!(user_msg.to_parts(1));
        assert_eq!(1, parts.len());
        let part = parts[0].clone();
        let name: XorName = rand::random();
        let routing_message = RoutingMessage {
            src: Authority::ClientManager(name),
            dst: Authority::ClientManager(name),
            content: part,
        };
        let hash_msg = unwrap!(routing_message.to_grp_msg_hash());
        match hash_msg.content {
            MessageContent::GroupMessageHash(..) => (),
            _ => panic!("Wrong content for hashed message: {:?}", hash_msg),
        }
        assert_eq!(hash_msg, unwrap!(hash_msg.to_grp_msg_hash()));

        let non_hash_routing_msg = RoutingMessage {
            src: Authority::ClientManager(name),
            dst: Authority::ClientManager(name),
            content: MessageContent::GetCloseGroup(MessageId::zero()),
        };
        assert_eq!(non_hash_routing_msg,
                   unwrap!(non_hash_routing_msg.to_grp_msg_hash()));
    }

    #[test]
    fn hop_message_verify() {
        let name: XorName = rand::random();
        let routing_message = RoutingMessage {
            src: Authority::ClientManager(name),
            dst: Authority::ClientManager(name),
            content: MessageContent::GetCloseGroup(MessageId::zero()),
        };
        let full_id = FullId::new();
        let signed_message_result = SignedMessage::new(routing_message.clone(), &full_id);

        assert!(signed_message_result.is_ok());

        let signed_message = unwrap!(signed_message_result);
        let (public_signing_key, secret_signing_key) = sign::gen_keypair();
        let hop_message_result =
            HopMessage::new(signed_message.clone(), 0, vec![], &secret_signing_key);

        assert!(hop_message_result.is_ok());

        let hop_message = unwrap!(hop_message_result);

        assert_eq!(signed_message, *hop_message.content());

        let verify_result = hop_message.verify(&public_signing_key);

        assert!(verify_result.is_ok());

        let (public_signing_key, _) = sign::gen_keypair();
        let verify_result = hop_message.verify(&public_signing_key);

        assert!(verify_result.is_err());
    }

    #[test]
    fn user_message_parts() {
        let data_bytes: Vec<u8> = (0..(super::MAX_PART_LEN * 2)).map(|i| i as u8).collect();
        let data = Data::Immutable(ImmutableData::new(data_bytes));
        let user_msg = UserMessage::Request(Request::Put(data, MessageId::new()));
        let msg_hash = maidsafe_utilities::big_endian_sip_hash(&user_msg);
        let parts = unwrap!(user_msg.to_parts(42));
        assert_eq!(parts.len(), 3);
        let payloads: Vec<Vec<u8>> = parts.into_iter()
            .enumerate()
            .map(|(i, msg)| match msg {
                MessageContent::UserMessagePart { hash,
                                                  part_count,
                                                  part_index,
                                                  payload,
                                                  priority,
                                                  cacheable } => {
                    assert_eq!(msg_hash, hash);
                    assert_eq!(3, part_count);
                    assert_eq!(i, part_index as usize);
                    assert_eq!(42, priority);
                    assert!(!cacheable);
                    payload
                }
                msg => panic!("Unexpected message {:?}", msg),
            })
            .collect();
        let deserialised_user_msg = unwrap!(UserMessage::from_parts(msg_hash, payloads.iter()));
        assert_eq!(user_msg, deserialised_user_msg);
    }
}
