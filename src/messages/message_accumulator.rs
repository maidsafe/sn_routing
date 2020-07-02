// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    consensus::{AccumulationError, SignatureAccumulator},
    messages::{AccumulatingMessage, Message, PlainMessage, SrcAuthority},
    section::SectionProofChain,
};
use serde::{Serialize, Serializer};

/// Accumulator for section-source messages.
#[derive(Default)]
pub struct MessageAccumulator(SignatureAccumulator<Payload>);

impl MessageAccumulator {
    /// Add `AccumulatingMessage` to the accumulator. Returns the full `Message` if we have enough
    /// shares or `None` otherwise.
    pub fn add(&mut self, accumulating_msg: AccumulatingMessage) -> Option<Message> {
        let payload = Payload {
            content: accumulating_msg.content,
            proof_chain: accumulating_msg.proof_chain,
        };

        match self.0.add(payload, accumulating_msg.proof_share) {
            Ok((payload, proof)) => {
                // TODO: should we verify that `proof.public_key` is the same as
                // `proof_chain.last_key()`?

                let src = SrcAuthority::Section {
                    prefix: payload.content.src,
                    signature: proof.signature,
                    proof_chain: payload.proof_chain,
                };

                match Message::new_signed(
                    src,
                    payload.content.dst,
                    Some(payload.content.dst_key),
                    payload.content.variant,
                ) {
                    Ok(msg) => Some(msg),
                    Err(error) => {
                        error!("Failed to make message: {:?}", error);
                        None
                    }
                }
            }
            Err(AccumulationError::NotEnoughShares)
            | Err(AccumulationError::AlreadyAccumulated) => None,
            Err(error) => {
                error!("Failed to add accumulating message: {}", error);
                None
            }
        }
    }
}

// Wrapper for the message being accumulated in `MessageAccumulator`.
#[derive(Debug, Serialize)]
struct Payload {
    #[serde(serialize_with = "serialise_plain_message_for_singing")]
    content: PlainMessage,
    // Don't serialize this to allow `AccumulatingMessage`s with the same content and the same
    // public key set but different proof chains to be combined together.
    #[serde(skip)]
    proof_chain: SectionProofChain,
}

fn serialise_plain_message_for_singing<S: Serializer>(
    msg: &PlainMessage,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    msg.as_signable().serialize(serializer)
}
