// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! This module caters for common types between vaults and clients but which routing does not
//! concern itself with. Ideally this could be moved to a crate which vaults and clients use,
//! later.

/// Account packet that is used to provide an invitation code for registration.
/// After successful registration it should be replaced with `AccountPacket::AccPkt`
/// with the contents of `account_ciphertext` as soon as possible to prevent an
/// invitation code leak.
#[derive(Serialize, Deserialize)]
pub enum AccountPacket {
    /// Account data with an invitation code that is used for registration.
    WithInvitation {
        /// Invitation code.
        invitation_string: String,
        /// Encrypted account data.
        acc_pkt: Vec<u8>,
    },
    /// Encrypted account data.
    AccPkt(Vec<u8>),
}
