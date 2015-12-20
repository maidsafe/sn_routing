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

use data::{Data, DataRequest};
use id::{PublicId, FullId};
use xor_name::XorName;
use error::RoutingError;
use sodiumoxide::crypto::{box_, sign, hash};
use authority::Authority;
use maidsafe_utilities::serialisation::serialise;
use rustc_serialize::{Decoder, Encoder};

/// Wrapper of all messages.
/// This is the only type allowed to be sent / received on the network
#[derive(Debug, RustcEncodable, RustcDecodable)]
pub enum Message {
    /// A message sent between w nodes directly
    DirectMessage(DirectMessage),
    /// A message ent across the network (in transit)
    HopMessage(HopMessage),
}

/// Messages sent direct to a node
/// Allows routing to directly send specific messages between nodes
#[derive(Debug, RustcEncodable, RustcDecodable)]
pub enum DirectMessage {
    /// Sent from bootstrap node to client
    BootstrapIdentify {
        /// keys and clamed name
        public_id: ::id::PublicId,
        /// quorum size, dynamically calculated
        current_quorum_size: usize,
    },
    /// Sent form client -> bootstrap node
    ClientIdentify {
        /// keys and claimed name. Serialised outside routing
        serialised_public_id: Vec<u8>,
        /// Signature of the originator of this message
        signature: sign::Signature,
    },
    /// Sent form a node to a node
    NodeIdentify {
        /// keys and claimed name, serialised outside routing
        serialised_public_id: Vec<u8>,
        /// Signature of the originator of this message
        signature: sign::Signature,
    },
    /// If  our close group changes, tell all our close group memebers of change
    /// They may be interested in some id's for harvesting
    /// Importantly this wil allow nodes to `see` nodes in their clsoe group vanish
    /// even they do not have an actual connection (i.e. both behind symmetric NAT)
    Churn {
        /// Close group (to self) as calculated by a node.
        close_group: Vec<XorName>,
    },
}

/// A wrapper for all messages sent form node to node.
/// Allows nodes to be sure there has been no alteration of message in transit. Also defeats
/// MiTM attacks
#[derive(Debug, RustcEncodable, RustcDecodable)]
pub struct HopMessage {
    /// wrapped signed message
    content: SignedMessage,
    /// name claimed to have sent hop message
    name: XorName,
    /// signatire to be validated against public key held by name
    signature: sign::Signature,
}

impl HopMessage {
    /// Wrap a signed message for transmission to next hop.
    pub fn new(content: SignedMessage,
               name: XorName,
               sign_key: &sign::SecretKey)
               -> Result<HopMessage, RoutingError> {
        let bytes_to_sign = try!(serialise(&(&content, &name)));
        Ok(HopMessage {
            content: content,
            name: name,
            signature: sign::sign_detached(&bytes_to_sign, sign_key),
        })
    }
    /// Validate message is signed by public key contained in message.
    /// this does not validate the message came from know node. That requires a check against
    /// the routing table of the node to identify the name associated with the PublicKey
    pub fn verify(&self, verification_key: &sign::PublicKey) -> Result<(), RoutingError> {
        let signed_bytes = try!(serialise(&(&self.content, &self.name)));
        if sign::verify_detached(&self.signature, &signed_bytes, verification_key) {
            Ok(())
        } else {
            Err(RoutingError::FailedSignature)
        }
    }
    /// return a signed message, does not validate message. [#verify] must be called prior
    /// to ensure sender is valid and validly signed he message
    pub fn extract(&self) -> (SignedMessage, XorName) {
        (self.content.clone(), self.name.clone())
    }
    /// The name asociated with te hop message.
    pub fn name(&self) -> &XorName {
        &self.name
    }
}

/// Wrapper around a routing message, signed by the originator of the message.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Debug, RustcEncodable, RustcDecodable)]
pub struct SignedMessage {
    /// A request or response type message.
    content: RoutingMessage,
    /// Claimed public_id of a node/client. If cline then it is self verifyable. For nodes we need
    /// to confirm this PublicId via a network message to the group of the claimed name.
    public_id: PublicId,
    signature: sign::Signature,
}

impl SignedMessage {
    /// Construct a signed message wrapper around a routing message.
    pub fn new(content: RoutingMessage, full_id: &FullId) -> Result<SignedMessage, RoutingError> {
        let bytes_to_sign = try!(serialise(&(&content, full_id.public_id())));
        Ok(SignedMessage {
            content: content,
            public_id: full_id.public_id().clone(),
            signature: sign::sign_detached(&bytes_to_sign, full_id.signing_private_key()),
        })
    }
    /// confirm signature against `claimed` PublicId contained in signed message
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

    /// The routing message that was singed.
    pub fn content(&self) -> &RoutingMessage {
        &self.content
    }

    /// PublicId associated with the signed message
    pub fn public_id(&self) -> &PublicId {
        &self.public_id
    }
}

/// Variant type to old `either` a request or response
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Debug, RustcEncodable, RustcDecodable)]
pub enum RoutingMessage {
    /// outgoing RPC type message.
    Request(RequestMessage),
    /// Incoming answer to request RPC.
    Response(ResponseMessage),
}

impl RoutingMessage {
    /// Return source authority of routing message.
    pub fn src(&self) -> &Authority {
        match *self {
            RoutingMessage::Request(ref msg) => &msg.src,
            RoutingMessage::Response(ref msg) => &msg.src,
        }
    }
    /// Return destination authority of routing message.
    pub fn dst(&self) -> &Authority {
        match *self {
            RoutingMessage::Request(ref msg) => &msg.dst,
            RoutingMessage::Response(ref msg) => &msg.dst,
        }
    }
}

/// A request message wrapper
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Debug, RustcEncodable, RustcDecodable)]
pub struct RequestMessage {
    /// Source address and persona type
    pub src: Authority,
    /// Destination target address (may be a group)
    pub dst: Authority,
    /// Varient of request types
    pub content: RequestContent,
}

/// A response message wrapper
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Debug, RustcEncodable, RustcDecodable)]
pub struct ResponseMessage {
    /// Source address and persona type
    pub src: Authority,
    /// Destination target address (may be a group)
    pub dst: Authority,
    /// varient of response types
    pub content: ResponseContent,
}

/// types of requests allowed on network
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Debug, RustcEncodable, RustcDecodable)]
pub enum RequestContent {
    // ---------- Internal ------------
    /// Ask network to alter your PublciId name and forward to appropriate group
    /// Client -> NaeManager
    GetNetworkName {
        /// Your PublicId (public keys and name)
        current_id: PublicId,
    },
    /// Receiving group of relocatted name will get this message
    ExpectCloseNode {
        /// Your PublicId (public keys and name)
        expect_id: PublicId,
    },
    /// Ask each memeber of a group near an address for the PublicId of that node
    GetCloseGroup,
    /// Request a connection to this node
    Connect,
    /// Send our endpoints encrypted toa node we wish to connect to and have the keys for
    Endpoints {
        /// encrypted crust endpoints (socket addr and protocol)
        encrypted_endpoints: Vec<u8>,
        /// nonce used to provide a salt in the encrytped message
        nonce_bytes: [u8; box_::NONCEBYTES],
    },
    /// Ask each memeber of a group near a node address for the PublicId
    GetPublicId,
    /// Ask for a publicId but provide our endpoints encrytped
    GetPublicIdWithEndpoints {
        /// encrypted crust endpoints (socket addr and protocol)
        encrypted_endpoints: Vec<u8>,
        /// nonce used to provide a salt in the encrytped message
        nonce_bytes: [u8; box_::NONCEBYTES],
    },
    /// Message from upper layers sending network state on any network churn event
    Refresh {
        /// externally defined message
        raw_bytes: Vec<u8>,
        /// The node that caused the churn event.
        /// Used here (passed up to upper layers in churn event) who must give it back in
        /// which allows filtering of different churn events (used as unique identifier)
        cause: XorName,
    },
    // ---------- External ------------
    /// Ask for data from network, passed from API with data name as parameter
    Get(DataRequest),
    /// Put data to network. Provide actual data as parameter
    Put(Data),
    /// Post data to network. Provide actual data as parameter
    Post(Data),
    /// Delete data from network. Provide actual data as parameter
    Delete(Data),
}

/// Types of respnses to exepect on the network.
/// All responses will map to a specific request and where request was from a single node
/// or client the response will contatin the singed request. This prevents forgery or co-ersion
/// attacks.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Debug, RustcEncodable, RustcDecodable)]
pub enum ResponseContent {
    // ---------- Internal ------------
    /// Reply with the altered publicId
    /// NaeManager -> Client
    GetNetworkName {
        /// Supplied publicId with name altered
        relocated_id: PublicId,
    },
    /// Reply with the requested PublciId
    /// NodeManager -> Client | ManagedNode
    GetPublicId {
        /// The relocatted PublciId
        public_id: PublicId,
    },
    /// Send our publicId along with senders encrypted endpoints bak to sender
    /// ManagedNode -> ManagedNode | client
    GetPublicIdWithEndpoints {
        /// Our publicId
        public_id: PublicId,
        /// their endpoints
        encrypted_endpoints: Vec<u8>,
        /// message salt
        nonce_bytes: [u8; box_::NONCEBYTES],
    },
    /// Return the close PublicId's back to requestor
    /// NodeManager -> client | ManagedNode
    GetCloseGroup {
        /// Our close group publci Id's
        close_group_ids: Vec<PublicId>,
    },
    // ---------- External ------------
    /// Should not be ignored. The data requested sent back
    /// (ManagedNode (cache) | NaeManagers) -> client
    /// ManagedNode -> NaeManagers
    GetSuccess(Data),
    /// Success token for Put (may be ignored)
    PutSuccess(hash::sha512::Digest),
    /// Success token for Post  (may be ignored)
    PostSuccess(hash::sha512::Digest),
    /// Success token for delete  (may be ignored)
    DeleteSuccess(hash::sha512::Digest),
    /// Error for Get, includes signed request to prevent injection attacks
    GetFailure {
        /// Originators signed reuest
        request: RequestMessage,
        /// Error type sent back, may be injected from upper layers
        external_error_indicator: Vec<u8>,
    },
    /// Error for Put, includes signed request to prevent injection attacks
    PutFailure {
        /// Originators signed reuest
        request: RequestMessage,
        /// Error type sent back, may be injected from upper layers
        external_error_indicator: Vec<u8>,
    },
    /// Error for Post, includes signed request to prevent injection attacks
    PostFailure {
        /// Originators signed reuest
        request: RequestMessage,
        /// Error type sent back, may be injected from upper layers
        external_error_indicator: Vec<u8>,
    },
    /// Error for delete, includes signed request to prevent injection attacks
    DeleteFailure {
        /// Originators signed reuest
        request: RequestMessage,
        /// Error type sent back, may be injected from upper layers
        external_error_indicator: Vec<u8>,
    },
}
