// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{DstLocation, Message, MessageHash, PartialMessage};
use crate::{error::Result, utils::LogIdent};
use bytes::Bytes;
use std::fmt::{self, Debug, Formatter};

/// Message in both its serialized and unserialized forms.
#[derive(Eq, PartialEq, Clone)]
pub struct MessageWithBytes {
    /// Wrapped message.
    full_content: Option<Message>,
    /// Partial message (just the destination location)
    partial_content: PartialMessage,
    /// Serialized full message as received or sent to quic_p2p.
    full_bytes: Bytes,
    /// Crypto hash of the full message.
    full_crypto_hash: MessageHash,
}

impl MessageWithBytes {
    /// Serialize message and keep both SignedRoutingMessage and Bytes.
    pub fn new(full_content: Message, log_ident: &LogIdent) -> Result<Self> {
        let full_bytes = full_content.to_bytes()?;
        let partial_content = full_content.to_partial();
        let result = Self::new_from_parts(Some(full_content), partial_content, full_bytes);

        trace!(
            "{} Creating message hash({:?}) {:?}",
            log_ident,
            result.full_crypto_hash,
            result
                .full_content
                .as_ref()
                .expect("New MessageWithBytes need full_content")
        );

        Ok(result)
    }

    pub fn partial_from_bytes(bytes: Bytes) -> Result<Self> {
        let partial_content = PartialMessage::from_bytes(&bytes)?;
        Ok(Self::new_from_parts(None, partial_content, bytes))
    }

    // Precondition: `full_bytes == serialize(&full_content)`
    fn new_from_parts(
        full_content: Option<Message>,
        partial_content: PartialMessage,
        full_bytes: Bytes,
    ) -> Self {
        let full_crypto_hash = MessageHash::from_bytes(&full_bytes);

        Self {
            full_content,
            partial_content,
            full_bytes,
            full_crypto_hash,
        }
    }

    pub fn take_or_deserialize_message(&mut self) -> Result<Message> {
        self.full_content
            .take()
            .map_or_else(|| self.deserialize_message(), Ok)
    }

    pub fn full_bytes(&self) -> &Bytes {
        &self.full_bytes
    }

    pub fn full_crypto_hash(&self) -> &MessageHash {
        &self.full_crypto_hash
    }

    pub fn message_dst(&self) -> &DstLocation {
        &self.partial_content.dst
    }

    fn deserialize_message(&self) -> Result<Message> {
        Message::from_bytes(&self.full_bytes)
    }
}

impl Debug for MessageWithBytes {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if let Some(content) = &self.full_content {
            write!(f, "{:?}", content)
        } else {
            write!(f, "Message({:?})", self.full_crypto_hash)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::Variant, *};
    use crate::{id::FullId, rng, unwrap};
    use rand::{distributions::Standard, Rng};

    #[test]
    fn serialise_and_partial_at_message() {
        let mut rng = rng::new();
        let full_id = FullId::gen(&mut rng);

        let dst = DstLocation::Section(rng.gen());
        let variant = Variant::UserMessage(rng.sample_iter(Standard).take(6).collect());
        let msg = unwrap!(Message::single_src(&full_id, dst, variant));

        let msg_with_bytes = unwrap!(MessageWithBytes::new(msg.clone(), &LogIdent::new("node")));
        let bytes = msg_with_bytes.full_bytes();

        let full_msg = unwrap!(Message::from_bytes(bytes));
        let partial_msg = unwrap!(PartialMessage::from_bytes(bytes));
        let partial_msg_head = unwrap!(PartialMessage::from_bytes(&bytes.slice(0, 40)));

        let expected_partial = PartialMessage { dst: msg.dst };

        assert_eq!(partial_msg, expected_partial);
        assert_eq!(partial_msg_head, expected_partial);
        assert_eq!(full_msg, msg);
    }
}
