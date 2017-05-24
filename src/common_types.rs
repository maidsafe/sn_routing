// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

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
