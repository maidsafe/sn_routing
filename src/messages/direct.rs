// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    ack_manager::Ack,
    error::{BootstrapResponseError, RoutingError},
    id::{FullId, PublicId},
    parsec,
    routing_table::Authority,
    sha3::Digest256,
    xor_name::XorName,
};
use hex_fmt::HexFmt;
use maidsafe_utilities::serialisation::serialise;
use safe_crypto::Signature;
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
    MessageSignature(Digest256, Signature),
    /// Sent from a newly connected client to the bootstrap node to prove that it is the owner of
    /// the client's claimed public ID.
    BootstrapRequest,
    /// Sent from the bootstrap node to a client in response to `BootstrapRequest`. If `true`,
    /// bootstrapping is successful; if `false` the sender is not available as a bootstrap node.
    BootstrapResponse(Result<(), BootstrapResponseError>),
    /// Sent from members of a section to a joining node in response to `ConnectRequest` (which is
    /// a routing message)
    ConnectResponse,
    /// Sent from a node which is still joining the network to another node, to allow the latter to
    /// add the former to its routing table.
    CandidateInfo {
        /// `PublicId` from before relocation.
        old_public_id: PublicId,
        /// Signature of both old and new `PublicId`s using the pre-relocation key.
        signature_using_old: Signature,
        /// Client authority from after relocation.
        new_client_auth: Authority<XorName>,
    },
    /// Request a proof to be provided by the joining node.
    ///
    /// This is sent from member of Group Y to the joining node.
    ResourceProof {
        /// seed of proof
        seed: Vec<u8>,
        /// size of the proof
        target_size: usize,
        /// leading zero bits of the hash of the proof
        difficulty: u8,
    },
    /// Provide a proof to the network
    ///
    /// This is sent from the joining node to member of Group Y
    ResourceProofResponse {
        /// The index of this part of the resource proof.
        part_index: usize,
        /// The total number of parts.
        part_count: usize,
        /// Proof to be presented
        proof: Vec<u8>,
        /// Claimed leading zero bytes to be added to proof's header so that the hash matches
        /// the difficulty requirement
        leading_zero_bytes: u64,
    },
    /// Receipt of a part of a ResourceProofResponse
    ResourceProofResponseReceipt,
    /// Sent from a proxy node to its client to indicate that the client exceeded its rate limit.
    ProxyRateLimitExceeded { ack: Ack },
    /// Poke a node to send us the first gossip request
    ParsecPoke(u64),
    /// Parsec request message
    ParsecRequest(u64, parsec::Request),
    /// Parsec response message
    ParsecResponse(u64, parsec::Response),
}

impl Debug for DirectMessage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        use self::DirectMessage::*;
        match *self {
            MessageSignature(ref digest, _) => {
                write!(formatter, "MessageSignature ({:.14}, ..)", HexFmt(&digest))
            }
            BootstrapRequest => write!(formatter, "BootstrapRequest"),
            BootstrapResponse(ref result) => write!(formatter, "BootstrapResponse({:?})", result),
            ConnectResponse => write!(formatter, "ConnectResponse"),
            CandidateInfo { .. } => write!(formatter, "CandidateInfo {{ .. }}"),
            ResourceProof {
                ref seed,
                ref target_size,
                ref difficulty,
            } => write!(
                formatter,
                "ResourceProof {{ seed: {:?}, target_size: {:?}, difficulty: {:?} }}",
                seed, target_size, difficulty
            ),
            ResourceProofResponse {
                part_index,
                part_count,
                ref proof,
                leading_zero_bytes,
            } => write!(
                formatter,
                "ResourceProofResponse {{ part {}/{}, proof_len: {:?}, leading_zero_bytes: \
                 {:?} }}",
                part_index + 1,
                part_count,
                proof.len(),
                leading_zero_bytes
            ),
            ResourceProofResponseReceipt => write!(formatter, "ResourceProofResponseReceipt"),
            ProxyRateLimitExceeded { ref ack } => {
                write!(formatter, "ProxyRateLimitExceeded({:?})", ack)
            }
            ParsecRequest(ref v, _) => write!(formatter, "ParsecRequest({}, _)", v),
            ParsecResponse(ref v, _) => write!(formatter, "ParsecResponse({}, _)", v),
            ParsecPoke(ref v) => write!(formatter, "ParsecPoke({})", v),
        }
    }
}

// Note: need manual impl here, because `parsec::Request` and `parsec::Response` don't implement `Hash`.
impl Hash for DirectMessage {
    fn hash<H: Hasher>(&self, state: &mut H) {
        use self::DirectMessage::*;

        mem::discriminant(self).hash(state);

        match *self {
            MessageSignature(ref digest, ref signature) => {
                digest.hash(state);
                signature.hash(state);
            }
            BootstrapRequest | ConnectResponse | ResourceProofResponseReceipt => (),
            BootstrapResponse(ref result) => result.hash(state),
            CandidateInfo {
                ref old_public_id,
                ref signature_using_old,
                ref new_client_auth,
            } => {
                old_public_id.hash(state);
                signature_using_old.hash(state);
                new_client_auth.hash(state);
            }
            ResourceProof {
                ref seed,
                target_size,
                difficulty,
            } => {
                seed.hash(state);
                target_size.hash(state);
                difficulty.hash(state);
            }
            ResourceProofResponse {
                part_index,
                part_count,
                ref proof,
                leading_zero_bytes,
            } => {
                part_index.hash(state);
                part_count.hash(state);
                proof.hash(state);
                leading_zero_bytes.hash(state);
            }
            ProxyRateLimitExceeded { ref ack } => ack.hash(state),
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
    #[cfg(any(test, feature = "mock_serialise"))]
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
        let mut serialised = serialise(src_full_id.public_id())?;
        serialised.extend_from_slice(&serialise(content)?);

        let signature = src_full_id.signing_private_key().sign_detached(&serialised);
        Ok(signature)
    }

    pub fn verify(
        src_id: &PublicId,
        signature: &Signature,
        content: &DirectMessage,
    ) -> Result<(), RoutingError> {
        let mut serialised = serialise(src_id)?;
        serialised.extend_from_slice(&serialise(content)?);

        if src_id
            .signing_public_key()
            .verify_detached(signature, &serialised)
        {
            Ok(())
        } else {
            Err(RoutingError::FailedSignature)
        }
    }
}

#[cfg(feature = "mock_serialise")]
mod implementation {
    use super::*;
    use safe_crypto::SIGNATURE_BYTES;

    pub fn sign(_: &FullId, _: &DirectMessage) -> Result<Signature, RoutingError> {
        Ok(Signature::from_bytes([0; SIGNATURE_BYTES]))
    }

    pub fn verify(_: &PublicId, _: &Signature, _: &DirectMessage) -> Result<(), RoutingError> {
        Ok(())
    }
}
