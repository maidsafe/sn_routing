// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use id::PublicId;
use itertools::Itertools;
use maidsafe_utilities::serialisation;
use messages::SignedMessage;
use rust_sodium::crypto::sign;
use rust_sodium::crypto::hash::sha256;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::time::Instant;

/// Time (in seconds) within which a message and a quorum of signatures need to arrive to
/// accumulate.
const ACCUMULATION_TIMEOUT_SECS: u64 = 30;

#[derive(Default)]
pub struct SignatureAccumulator {
    sigs: HashMap<sha256::Digest, (Vec<(PublicId, sign::Signature)>, Instant)>,
    msgs: HashMap<sha256::Digest, (SignedMessage, u8, Instant)>,
}

impl SignatureAccumulator {
    /// Adds the given signature to the list of pending signatures or to the appropriate
    /// `SignedMessage`. Returns the message, if it has enough signatures now.
    pub fn add_signature(&mut self,
                         hash: sha256::Digest,
                         sig: sign::Signature,
                         pub_id: PublicId)
                         -> Option<(SignedMessage, u8)> {
        self.remove_expired();
        if let Some(&mut (ref mut msg, _, _)) = self.msgs.get_mut(&hash) {
            msg.add_signature(pub_id, sig);
        } else {
            let mut sigs_vec = self.sigs.entry(hash).or_insert_with(|| (vec![], Instant::now()));
            sigs_vec.0.push((pub_id, sig));
            return None;
        }
        self.remove_if_complete(&hash)
    }

    /// Adds the given message to the list of pending messages. Returns it if it has enough
    /// signatures.
    pub fn add_message(&mut self,
                       mut msg: SignedMessage,
                       route: u8)
                       -> Option<(SignedMessage, u8)> {
        if msg.is_fully_signed() {
            return Some((msg, route));
        }
        self.remove_expired();
        let hash = match serialisation::serialise(&msg) {
            Ok(serialised_msg) => sha256::hash(&serialised_msg),
            Err(err) => {
                error!("Failed to serialise {:?}: {:?}.", msg, err);
                return None;
            }
        };
        match self.msgs.entry(hash) {
            Entry::Occupied(mut entry) => {
                trace!("Received two full SignedMessages {:?}.", msg);
                entry.get_mut().0.add_signatures(msg);
            }
            Entry::Vacant(entry) => {
                for (pub_id, sig) in self.sigs.remove(&hash).into_iter().flat_map(|(vec, _)| vec) {
                    msg.add_signature(pub_id, sig);
                }
                let _ = entry.insert((msg, route, Instant::now()));
            }
        }
        self.remove_if_complete(&hash)
    }

    fn remove_expired(&mut self) {
        let expired_sigs = self.sigs
            .iter()
            .filter(|&(_, &(_, ref time))| time.elapsed().as_secs() > ACCUMULATION_TIMEOUT_SECS)
            .map(|(hash, _)| *hash)
            .collect_vec();
        for hash in expired_sigs {
            let _ = self.sigs.remove(&hash);
        }
        let expired_msgs = self.msgs
            .iter()
            .filter(|&(_, &(_, _, ref time))| time.elapsed().as_secs() > ACCUMULATION_TIMEOUT_SECS)
            .map(|(hash, _)| *hash)
            .collect_vec();
        for hash in expired_msgs {
            let _ = self.msgs.remove(&hash);
        }
    }

    fn remove_if_complete(&mut self, hash: &sha256::Digest) -> Option<(SignedMessage, u8)> {
        match self.msgs.get(hash) {
            None => return None,
            Some(&(ref msg, _, _)) => {
                if !msg.is_fully_signed() {
                    return None;
                }
            }
        }
        self.msgs.remove(hash).map(|(msg, route, _)| (msg, route))
    }
}
