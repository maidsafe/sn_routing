// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    crypto::signing::Signature,
    error::{BootstrapResponseError, RoutingError},
    id::{FullId, PublicId},
    messages::SignedRoutingMessage,
    parsec,
    routing_table::Prefix,
    xor_name::XorName,
    ConnectionInfo,
};
use maidsafe_utilities::serialisation::serialise;
use std::{
    fmt::{self, Debug, Formatter},
    hash::{Hash, Hasher},
    mem,
};

/// Direct message content.
#[cfg_attr(feature = "mock_serialise", derive(Clone))]
#[derive(Eq, PartialEq, Serialize, Deserialize)]
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
pub enum DirectMessage {
    /// Sent from members of a section or group message's source authority to the first hop. The
    /// message will only be relayed once enough signatures have been accumulated.
    MessageSignature(SignedRoutingMessage),
    /// Sent from a newly connected peer to the bootstrap node to request connection infos of
    /// members of the section matching the given name.
    BootstrapRequest(XorName),
    /// Sent from the bootstrap node to a peer in response to `BootstrapRequest`. It can either
    /// accept the peer into the section, or redirect it to another set of bootstrap peers
    BootstrapResponse(BootstrapResponse),
    /// Sent from a bootstrapping peer to the section that responded with a
    /// `BootstrapResponse::Join` to its `BootstrapRequest`
    JoinRequest,
    /// Sent from members of a section to a joining node in response to `ConnectionRequest` (which is
    /// a routing message)
    ConnectionResponse,
    /// Poke a node to send us the first gossip request
    ParsecPoke(u64),
    /// Parsec request message
    ParsecRequest(u64, parsec::Request),
    /// Parsec response message
    ParsecResponse(u64, parsec::Response),
}

/// Response to a BootstrapRequest
#[cfg_attr(feature = "mock_serialise", derive(Clone))]
#[derive(Eq, PartialEq, Serialize, Deserialize, Debug, Hash)]
pub enum BootstrapResponse {
    /// This response means that the new peer is clear to join the section. The connection infos of
    /// the Elders of the section and the section prefix are provided.
    Join {
        prefix: Prefix<XorName>,
        conn_infos: Vec<ConnectionInfo>,
    },
    /// The new peer should retry bootstrapping with another section. The set of connection infos
    /// of the members of that section is provided.
    Rebootstrap(Vec<ConnectionInfo>),
    /// An error has occurred
    Error(BootstrapResponseError),
}

impl Debug for DirectMessage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        use self::DirectMessage::*;
        match self {
            MessageSignature(msg) => write!(formatter, "MessageSignature ({:?})", msg),
            BootstrapRequest(name) => write!(formatter, "BootstrapRequest({})", name),
            BootstrapResponse(response) => write!(formatter, "BootstrapResponse({:?})", response),
            JoinRequest => write!(formatter, "JoinRequest"),
            ConnectionResponse => write!(formatter, "ConnectionResponse"),
            ParsecRequest(v, _) => write!(formatter, "ParsecRequest({}, _)", v),
            ParsecResponse(v, _) => write!(formatter, "ParsecResponse({}, _)", v),
            ParsecPoke(v) => write!(formatter, "ParsecPoke({})", v),
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

        match *self {
            MessageSignature(ref msg) => {
                msg.hash(state);
            }
            ConnectionResponse | JoinRequest => (),
            BootstrapRequest(name) => name.hash(state),
            BootstrapResponse(ref response) => response.hash(state),
            ParsecPoke(version) => version.hash(state),
            ParsecRequest(version, ref request) => {
                version.hash(state);
                // Fake hash via serialisation
                serialise(&request).ok().hash(state)
            }
            ParsecResponse(version, ref response) => {
                version.hash(state);
                // Fake hash via serialisation
                serialise(&response).ok().hash(state)
            }
        }
    }
}

#[cfg_attr(feature = "mock_serialise", derive(Clone))]
#[derive(Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SignedDirectMessage {
    content: DirectMessage,
    src_id: PublicId,
    signature: Signature,
}

impl SignedDirectMessage {
    /// Create new `DirectMessage` with `content` and signed by `src_full_id`.
    pub fn new(content: DirectMessage, src_full_id: &FullId) -> Result<Self, RoutingError> {
        let signature = self::implementation::sign(src_full_id, &content)?;

        Ok(Self {
            content,
            src_id: *src_full_id.public_id(),
            signature,
        })
    }

    /// Verify the message signature.
    pub fn verify(&self) -> Result<(), RoutingError> {
        self::implementation::verify(&self.src_id, &self.signature, &self.content)
    }

    /// Verify the message signature and return its content and the sender id.
    /// Consume the message in the process.
    pub fn open(self) -> Result<(DirectMessage, PublicId), RoutingError> {
        self.verify()?;
        Ok((self.content, self.src_id))
    }

    /// Content of the message.
    #[cfg(any(all(test, feature = "mock_base"), feature = "mock_serialise"))]
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

#[cfg(not(feature = "mock_serialise"))]
mod implementation {
    use super::*;

    pub fn sign(src_full_id: &FullId, content: &DirectMessage) -> Result<Signature, RoutingError> {
        let serialised = serialise(content)?;
        let signature = src_full_id.sign(&serialised);
        Ok(signature)
    }

    pub fn verify(
        src_id: &PublicId,
        signature: &Signature,
        content: &DirectMessage,
    ) -> Result<(), RoutingError> {
        let serialised = serialise(content)?;

        if src_id.verify(&serialised, signature) {
            Ok(())
        } else {
            Err(RoutingError::FailedSignature)
        }
    }
}

#[cfg(feature = "mock_serialise")]
mod implementation {
    use super::*;
    use crate::crypto::signing::SIGNATURE_LENGTH;
    use unwrap::unwrap;

    pub fn sign(_: &FullId, _: &DirectMessage) -> Result<Signature, RoutingError> {
        Ok(unwrap!(Signature::from_bytes(&[0; SIGNATURE_LENGTH])))
    }

    pub fn verify(_: &PublicId, _: &Signature, _: &DirectMessage) -> Result<(), RoutingError> {
        Ok(())
    }
}
