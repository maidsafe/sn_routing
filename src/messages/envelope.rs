// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::convert::TryFrom;

use super::{InfrastructureQuery, Message};
use bytes::Bytes;
use thiserror::Error;

/// Single byte that identifies the message type.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[repr(u8)]
pub enum MessageKind {
    /// Ping message used to probe whether nodes/client are online. Does not need to be handled.
    Ping = 0,
    /// Node-to-node message.
    Node = 1,
    /// Node-to-client or client-to-node message.
    Client = 2,
    /// Message to query the network infrastructure or a response to such query.
    Infrastructure = 3,
}

impl TryFrom<u8> for MessageKind {
    type Error = UnknownMessageKind;

    fn try_from(input: u8) -> Result<Self, Self::Error> {
        match input {
            0 => Ok(Self::Ping),
            1 => Ok(Self::Node),
            2 => Ok(Self::Client),
            3 => Ok(Self::Infrastructure),
            _ => Err(UnknownMessageKind),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("unknown message kind")]
pub struct UnknownMessageKind;

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum Envelope {
    Ping,
    Node(Message),
    Client(Bytes),
    Infrastructure(InfrastructureQuery),
}

impl Envelope {
    pub fn from_bytes(bytes: &Bytes) -> Result<Self, FromBytesError> {
        match MessageKind::try_from(bytes[0]) {
            Ok(MessageKind::Ping) => Ok(Self::Ping),
            Ok(MessageKind::Node) => Ok(Self::Node(Message::from_bytes(&bytes.slice(1..))?)),
            Ok(MessageKind::Client) => Ok(Self::Client(bytes.slice(1..))),
            Ok(MessageKind::Infrastructure) => Ok(Self::Infrastructure(
                bincode::deserialize(&bytes[1..]).map_err(FromBytesError::Infrastructure)?,
            )),
            Err(_) => Err(FromBytesError::UnknownMessageKind),
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum FromBytesError {
    #[error("failed to parse node message: {}", .0)]
    Node(#[from] super::CreateError),
    #[error("failed to parse infrastructure query: {}", .0)]
    Infrastructure(#[source] bincode::Error),
    #[error("unknown message kind")]
    UnknownMessageKind,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_kind_from_u8() {
        for &(kind, byte) in &[
            (MessageKind::Ping, 0),
            (MessageKind::Node, 1),
            (MessageKind::Client, 2),
            (MessageKind::Infrastructure, 3),
        ] {
            assert_eq!(kind as u8, byte);
            assert_eq!(MessageKind::try_from(byte), Ok(kind))
        }

        for byte in 4..u8::MAX {
            assert!(MessageKind::try_from(byte).is_err())
        }
    }
}
