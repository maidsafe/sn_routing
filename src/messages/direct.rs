// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chain::EldersInfo,
    crypto::signing::Signature,
    error::RoutingError,
    id::{FullId, PublicId},
    messages::SignedRoutingMessage,
    parsec,
    relocation::{RelocatePayload, SignedRelocateDetails},
    xor_space::XorName,
    ConnectionInfo,
};
use maidsafe_utilities::serialisation::serialise;
use std::{
    fmt::{self, Debug, Formatter},
    hash::{Hash, Hasher},
    mem,
};

/// Direct message content.
#[derive(Eq, PartialEq, Serialize, Deserialize)]
pub enum DirectMessage {
    /// Sent from members of a section or group message's source authority to the first hop. The
    /// message will only be relayed once enough signatures have been accumulated.
    MessageSignature(Box<SignedRoutingMessage>),
    /// Sent from a newly connected peer to the bootstrap node to request connection infos of
    /// members of the section matching the given name.
    BootstrapRequest(XorName),
    /// Sent from the bootstrap node to a peer in response to `BootstrapRequest`. It can either
    /// accept the peer into the section, or redirect it to another set of bootstrap peers
    BootstrapResponse(BootstrapResponse),
    /// Sent from a bootstrapping peer to the section that responded with a
    /// `BootstrapResponse::Join` to its `BootstrapRequest`.
    JoinRequest(Box<JoinRequest>),
    /// Sent from members of a section to a joining node in response to `ConnectionRequest` (which is
    /// a routing message)
    ConnectionResponse,
    /// Sent from Adults and Infants to Elders. Updates Elders about the sender's knowledge of its
    /// own section.
    MemberKnowledge(MemberKnowledge),
    /// Parsec request message
    ParsecRequest(u64, parsec::Request),
    /// Parsec response message
    ParsecResponse(u64, parsec::Response),
    /// Send from a section to the node being relocated.
    Relocate(Box<SignedRelocateDetails>),
}

/// Response to a BootstrapRequest
#[derive(Eq, PartialEq, Serialize, Deserialize, Debug, Hash)]
pub enum BootstrapResponse {
    /// This response means that the new peer is clear to join the section. The connection infos of
    /// the section elders and the section prefix are provided.
    Join(EldersInfo),
    /// The new peer should retry bootstrapping with another section. The set of connection infos
    /// of the members of that section is provided.
    Rebootstrap(Vec<ConnectionInfo>),
}

/// Request to join a section
#[derive(Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct JoinRequest {
    /// The section version to join
    pub elders_version: u64,
    /// If the peer is being relocated, contains `RelocatePayload`. Otherwise contains `None`.
    pub relocate_payload: Option<RelocatePayload>,
}

/// Node's knowledge about its own section.
#[derive(Default, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Debug, Hash)]
pub struct MemberKnowledge {
    pub elders_version: u64,
    pub parsec_version: u64,
}

impl MemberKnowledge {
    pub fn update(&mut self, other: MemberKnowledge) {
        self.elders_version = self.elders_version.max(other.elders_version);
        self.parsec_version = self.parsec_version.max(other.parsec_version);
    }
}

impl Debug for DirectMessage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        use self::DirectMessage::*;
        match self {
            MessageSignature(msg) => write!(formatter, "MessageSignature({:?})", msg),
            BootstrapRequest(name) => write!(formatter, "BootstrapRequest({})", name),
            BootstrapResponse(response) => write!(formatter, "BootstrapResponse({:?})", response),
            JoinRequest(join_request) => write!(
                formatter,
                "JoinRequest({}, {:?})",
                join_request.elders_version,
                join_request
                    .relocate_payload
                    .as_ref()
                    .map(|payload| payload.details.content())
            ),
            ConnectionResponse => write!(formatter, "ConnectionResponse"),
            ParsecRequest(v, _) => write!(formatter, "ParsecRequest({}, _)", v),
            ParsecResponse(v, _) => write!(formatter, "ParsecResponse({}, _)", v),
            MemberKnowledge(payload) => write!(formatter, "{:?}", payload),
            Relocate(payload) => write!(formatter, "Relocate({:?})", payload.content()),
        }
    }
}

// Note: we need explicit impl here, because `parsec::Request` and `parsec::Response` don't
// implement `Hash`.
// We don't need explicit `PartialEq` impl, because `parsec::Request/Response` do implement it.
// So it's OK to silence this clippy lint:
#[allow(clippy::derive_hash_xor_eq)]
impl Hash for DirectMessage {
    fn hash<H: Hasher>(&self, state: &mut H) {
        use self::DirectMessage::*;

        mem::discriminant(self).hash(state);

        match self {
            MessageSignature(msg) => msg.hash(state),
            BootstrapRequest(name) => name.hash(state),
            BootstrapResponse(response) => response.hash(state),
            JoinRequest(join_request) => join_request.hash(state),
            ConnectionResponse => (),
            MemberKnowledge(payload) => payload.hash(state),
            ParsecRequest(version, request) => {
                version.hash(state);
                // Fake hash via serialisation
                serialise(&request).ok().hash(state)
            }
            ParsecResponse(version, response) => {
                version.hash(state);
                // Fake hash via serialisation
                serialise(&response).ok().hash(state)
            }
            Relocate(details) => details.hash(state),
        }
    }
}

#[derive(Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SignedDirectMessage {
    content: DirectMessage,
    src_id: PublicId,
    signature: Signature,
}

impl SignedDirectMessage {
    /// Create new `DirectMessage` with `content` and signed by `src_full_id`.
    pub fn new(content: DirectMessage, src_full_id: &FullId) -> Result<Self, RoutingError> {
        let serialised = serialise(&content)?;
        let signature = src_full_id.sign(&serialised);

        Ok(Self {
            content,
            src_id: *src_full_id.public_id(),
            signature,
        })
    }

    /// Verify the message signature.
    pub fn verify(&self) -> Result<(), RoutingError> {
        let serialised = serialise(&self.content)?;

        if self.src_id.verify(&serialised, &self.signature) {
            Ok(())
        } else {
            Err(RoutingError::FailedSignature)
        }
    }

    /// Verify the message signature and return its content and the sender id.
    /// Consume the message in the process.
    pub fn open(self) -> Result<(DirectMessage, PublicId), RoutingError> {
        self.verify()?;
        Ok((self.content, self.src_id))
    }

    /// Content of the message.
    #[cfg(all(test, feature = "mock_base"))]
    pub fn content(&self) -> &DirectMessage {
        &self.content
    }
}

impl Debug for SignedDirectMessage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "SignedDirectMessage {{ content: {:?}, src_id: {:?}, signature: {:?} }}",
            self.content, self.src_id, self.signature
        )
    }
}
