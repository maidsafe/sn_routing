// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::types::MessageId as MsgId;

/// Request message types
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Request {
    /// Generic vault message
    Vault(Vec<u8>, MsgId),
    // Routing specific requests can appear below
}

impl Request {
    /// Message ID getter.
    pub fn message_id(&self) -> &MsgId {
        use crate::Request::*;
        match *self {
            Vault(_, ref msg_id) => msg_id
        }
    }

    /// Is the response corresponding to this request cacheable?
    pub fn is_cacheable(&self) -> bool {
            false
    }
}
