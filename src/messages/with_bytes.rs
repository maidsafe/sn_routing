// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    Message, PartialMessage, PartialSignedRoutingMessage, SignedDirectMessage, SignedRoutingMessage,
};
use crate::{
    crypto::{self, Digest256},
    error::{Result, RoutingError},
    location::Location,
    states::common::{from_network_bytes, partial_from_network_bytes, to_network_bytes},
    utils::LogIdent,
};
use bytes::Bytes;

#[allow(clippy::large_enum_variant)]
pub enum MessageWithBytes {
    Hop(HopMessageWithBytes),
    Direct(SignedDirectMessage, Bytes),
}

impl MessageWithBytes {
    pub fn partial_from_bytes(bytes: Bytes) -> Result<Self> {
        match partial_from_network_bytes(&bytes)? {
            PartialMessage::Hop(msg_partial) => Ok(Self::Hop(HopMessageWithBytes::new_from_parts(
                None,
                msg_partial,
                bytes,
            ))),
            PartialMessage::Direct(msg) => Ok(Self::Direct(msg, bytes)),
        }
    }
}

/// An individual hop message that will be relayed to its destination.
#[derive(Eq, PartialEq, Clone)]
pub struct HopMessageWithBytes {
    /// Wrapped signed message.
    full_content: Option<SignedRoutingMessage>,
    /// Partial SignedRoutingMessage infos
    partial_content: PartialSignedRoutingMessage,
    /// Serialized Message as received or sent to quic_p2p.
    full_message_bytes: Bytes,
    /// Crypto hash of the full message.
    full_message_crypto_hash: Digest256,
}

impl HopMessageWithBytes {
    /// Serialize message and keep both SignedRoutingMessage and Bytes.
    pub fn new(full_content: SignedRoutingMessage, log_ident: &LogIdent) -> Result<Self> {
        let hop_msg_result = {
            let (full_content, full_message_bytes) = {
                let full_message = Message::Hop(full_content);
                let full_message_bytes = to_network_bytes(&full_message)?;

                if let Message::Hop(full_content) = full_message {
                    (full_content, full_message_bytes)
                } else {
                    unreachable!("Created as Hop can only match Hop.")
                }
            };

            let partial_content = PartialSignedRoutingMessage {
                dst: full_content.routing_message().dst,
            };

            Self::new_from_parts(Some(full_content), partial_content, full_message_bytes)
        };

        trace!(
            "{} Creating message hash({:?}) {:?}",
            log_ident,
            hop_msg_result.full_message_crypto_hash,
            hop_msg_result
                .full_content
                .as_ref()
                .expect("New HopMessageWithBytes need full_content")
                .routing_message(),
        );

        Ok(hop_msg_result)
    }

    fn new_from_parts(
        full_content: Option<SignedRoutingMessage>,
        partial_content: PartialSignedRoutingMessage,
        full_message_bytes: Bytes,
    ) -> Self {
        let full_message_crypto_hash = crypto::sha3_256(&full_message_bytes);

        Self {
            full_content,
            partial_content,
            full_message_bytes,
            full_message_crypto_hash,
        }
    }

    pub fn take_or_deserialize_signed_routing_message(&mut self) -> Result<SignedRoutingMessage> {
        self.take_signed_routing_message()
            .map_or_else(|| self.deserialize_signed_routing_message(), Ok)
    }

    pub fn full_message_bytes(&self) -> &Bytes {
        &self.full_message_bytes
    }

    pub fn full_message_crypto_hash(&self) -> &Digest256 {
        &self.full_message_crypto_hash
    }

    pub fn message_dst(&self) -> &Location {
        &self.partial_content.dst
    }

    fn take_signed_routing_message(&mut self) -> Option<SignedRoutingMessage> {
        self.full_content.take()
    }

    fn deserialize_signed_routing_message(&self) -> Result<SignedRoutingMessage> {
        match from_network_bytes(&self.full_message_bytes)? {
            Message::Hop(msg) => Ok(msg),
            Message::Direct(_msg) => Err(RoutingError::InvalidMessage),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{RoutingMessage, Variant},
        *,
    };
    use crate::{
        id::FullId,
        rng::{self, MainRng},
        unwrap,
    };
    use rand::{self, Rng};

    #[test]
    fn serialise_and_partial_at_hop_message() {
        let mut rng = rng::new();
        let full_id = FullId::gen(&mut rng);
        let msg = gen_message(&mut rng);

        let signed_msg_org = unwrap!(SignedRoutingMessage::single_source(msg, &full_id,));

        let msg = unwrap!(HopMessageWithBytes::new(
            signed_msg_org.clone(),
            &LogIdent::new("node")
        ));
        let bytes = msg.full_message_bytes();
        let full_msg = unwrap!(from_network_bytes(bytes));
        let partial_msg = unwrap!(partial_from_network_bytes(bytes));
        let partial_msg_head = unwrap!(partial_from_network_bytes(&bytes.slice(0, 40)));

        let expected_partial = PartialMessage::Hop(PartialSignedRoutingMessage {
            dst: signed_msg_org.routing_message().dst,
        });
        let signed_msg = if let Message::Hop(signed_msg) = full_msg {
            Some(signed_msg)
        } else {
            None
        };

        assert_eq!(partial_msg, expected_partial);
        assert_eq!(partial_msg_head, expected_partial);
        assert_eq!(signed_msg, Some(signed_msg_org))
    }

    fn gen_message(rng: &mut MainRng) -> RoutingMessage {
        use rand::distributions::Standard;

        RoutingMessage {
            src: Location::Section(rng.gen()),
            dst: Location::Section(rng.gen()),
            content: Variant::UserMessage(rng.sample_iter(Standard).take(6).collect()),
        }
    }
}
