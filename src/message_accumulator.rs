// Copyright 2016 MaidSafe.net limited.
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

use lru_time_cache::LruCache;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::hash::sha256;
use std::time::Duration;

use accumulator::Accumulator;
use error::RoutingError;
use id::PublicId;
use message_filter::MessageFilter;
use messages::{MessageContent, RoutingMessage};

const EXPIRY_DURATION_SECS: u64 = 60 * 20;

pub struct MessageAccumulator {
    accumulator: Accumulator<RoutingMessage, sign::PublicKey>,
    cache: LruCache<sha256::Digest, RoutingMessage>,
    filter: MessageFilter<RoutingMessage>,
}

impl MessageAccumulator {
    pub fn new() -> Self {
        let expiry_duration = Duration::from_secs(EXPIRY_DURATION_SECS);

        MessageAccumulator {
            accumulator: Accumulator::with_duration(1, expiry_duration),
            cache: LruCache::with_expiry_duration(expiry_duration),
            filter: MessageFilter::with_expiry_duration(expiry_duration),
        }
    }

    pub fn set_quorum_size(&mut self, size: usize) {
        self.accumulator.set_quorum(size)
    }

    pub fn quorum_size(&self) -> usize {
        self.accumulator.quorum()
    }

    pub fn add(&mut self,
               msg: &RoutingMessage,
               public_id: PublicId)
               -> Result<Option<RoutingMessage>, RoutingError> {
        if !msg.src.is_group() {
            return Ok(Some(msg.clone()));
        }

        if self.filter.contains(msg) {
            return Err(RoutingError::FilterCheckFailed);
        }

        if let Some(group_msg) = self.accumulate(msg, &public_id) {
            let _ = self.filter.insert(&group_msg);
            let _ = self.filter.insert(&try!(msg.to_grp_msg_hash()));
            Ok(Some(group_msg))
        } else {
            Ok(None)
        }
    }

    pub fn contains(&mut self, msg: &RoutingMessage) -> bool {
        self.filter.contains(msg)
    }

    #[cfg(feature = "use-mock-crust")]
    pub fn clear(&mut self) {
        // self.accumulator.clear();
        self.cache.clear();
        self.filter.clear();
    }

    fn accumulate(&mut self, msg: &RoutingMessage, public_id: &PublicId) -> Option<RoutingMessage> {
        let key = *public_id.signing_public_key();
        let hash_msg = if let Ok(hash_msg) = msg.to_grp_msg_hash() {
            hash_msg
        } else {
            // TODO: return error and let the called handle logging.
            error!("Failed to hash message {:?}", msg);
            return None;
        };

        if let MessageContent::GroupMessageHash(hash, _) = hash_msg.content {
            if hash_msg != *msg {
                let _ = self.cache.insert(hash, msg.clone());
            }
            if self.accumulator.add(hash_msg, key).is_some() {
                self.cache.remove(&hash)
            } else {
                None
            }
        } else {
            self.accumulator.add(hash_msg, key).map(|_| msg.clone())
        }
    }
}
