// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! Direct messages are different from SignedMessages as they have no header information and
//! are restricted to transfer on a single connection.  They cannot be transferred
//! as SignedMessages (wrapping RoutingMessages) over the routing network.

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub enum DirectMessage {
    BootstrapIdentify {
        public_id: ::id::PublicId,
        current_quorum_size: usize,
    },
    ClientIdentify {
        serialised_public_id: Vec<u8>,
        signature: ::sodiumoxide::crypto::sign::Signature,
    },
    NodeIdentify {
        serialised_public_id: Vec<u8>,
        signature: ::sodiumoxide::crypto::sign::Signature,
    },
    Churn {
        close_group: Vec<::XorName>,
    },
}
