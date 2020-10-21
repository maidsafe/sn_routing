// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::crypto::{self, Digest256};
use hex_fmt::HexFmt;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Formatter};

/// Cryptographic hash of Message
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct MessageHash(Digest256);

impl MessageHash {
    /// Compute hash of the given message.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(crypto::sha3_256(bytes))
    }
}

impl Default for MessageHash {
    fn default() -> MessageHash {
        MessageHash([0u8; 32])
    }
}

impl Debug for MessageHash {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:10}", HexFmt(&self.0))
    }
}
