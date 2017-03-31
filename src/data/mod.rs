// Copyright 2015 MaidSafe.net limited.
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

mod immutable_data;
mod structured_data;
mod mutable_data;

pub use self::immutable_data::{ImmutableData, MAX_IMMUTABLE_DATA_SIZE_IN_BYTES};
pub use self::mutable_data::{Action, EntryAction, EntryActions, MutableData, PermissionSet, User,
                             Value};
pub use self::mutable_data::{MAX_MUTABLE_DATA_ENTRIES, MAX_MUTABLE_DATA_ENTRY_ACTIONS,
                             MAX_MUTABLE_DATA_SIZE_IN_BYTES};
pub use self::structured_data::{MAX_STRUCTURED_DATA_SIZE_IN_BYTES, StructuredData};
use error::RoutingError;
use rust_sodium::crypto::sign::{self, PublicKey, Signature};
use std::collections::{BTreeMap, BTreeSet};

/// A signing key with no matching private key. Passing ownership to it will make a chunk
/// effectively immutable.
pub const NO_OWNER_PUB_KEY: PublicKey = PublicKey([0; sign::PUBLICKEYBYTES]);

/// Confirms *unique and valid* signatures are more than 50% of total owners.
pub fn verify_signatures(owners: &BTreeSet<PublicKey>,
                         data: &[u8],
                         signatures: &BTreeMap<PublicKey, Signature>)
                         -> Result<(), RoutingError> {
    // Refuse when not enough signatures found
    if signatures.len() < (owners.len() + 1) / 2 {
        return Err(RoutingError::NotEnoughSignatures);
    }

    // Refuse if there is any invalid signature
    if !signatures
            .iter()
            .all(|(pub_key, sig)| {
                     owners.contains(pub_key) && verify_detached(sig, data, pub_key)
                 }) {
        return Err(RoutingError::FailedSignature);
    }
    Ok(())
}

// Returns whether the signature is valid. It explicitly considers any signature for
// `NO_OWNER_PUB_KEY` invalid.
fn verify_detached(sig: &Signature, data: &[u8], pub_key: &PublicKey) -> bool {
    *pub_key != NO_OWNER_PUB_KEY && sign::verify_detached(sig, data, pub_key)
}
