// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::error::{Error, Result};
use std::collections::{BTreeMap, VecDeque};

/// All the key material needed to sign or combine signature for our section key.
#[derive(Debug)]
pub struct SectionKeyShare {
    /// Public key set to verify threshold signatures and combine shares.
    pub public_key_set: bls::PublicKeySet,
    /// Index of the owner of this key share within the set of all section elders.
    pub index: usize,
    /// Secret Key share.
    pub secret_key_share: bls::SecretKeyShare,
}

/// Struct that holds the current section keys and helps with new key generation.
#[derive(Debug)]
pub struct SectionKeysProvider {
    /// A cache for current and previous section BLS keys.
    cache: KeyCache,
    /// The new keys to use when section update completes.
    pending: Option<SectionKeyShare>,
}

impl SectionKeysProvider {
    pub fn new(cache_size: u8, current: Option<SectionKeyShare>) -> Self {
        let mut provider = Self {
            pending: None,
            cache: KeyCache::with_capacity(cache_size as usize),
        };
        if let Some(share) = current {
            let public_key = share.public_key_set.public_key();
            provider.insert_dkg_outcome(share);
            provider.finalise_dkg(&public_key);
        }
        provider
    }

    pub fn key_share(&self) -> Result<&SectionKeyShare> {
        self.cache.get_most_recent()
    }

    pub fn sign_with(
        &self,
        data: &[u8],
        public_key: &bls::PublicKey,
    ) -> Result<bls::SignatureShare> {
        self.cache.sign_with(data, public_key)
    }

    pub fn has_key_share(&self) -> bool {
        self.cache.has_key_share()
    }

    pub fn insert_dkg_outcome(&mut self, share: SectionKeyShare) {
        self.pending = Some(share);
    }

    pub fn finalise_dkg(&mut self, public_key: &bls::PublicKey) {
        if let Some(share) = &self.pending {
            if *public_key != share.public_key_set.public_key() {
                return;
            }
        }
        if let Some(share) = self.pending.take() {
            if let Some(evicted) = self.cache.add(public_key, share) {
                trace!("evicted old key from cache: {:?}", evicted);
            }
            trace!("finalised DKG: {:?}", public_key);
        }
    }
}

/// Implementation of simple cache.
#[derive(Debug)]
pub struct KeyCache {
    map: BTreeMap<Vec<u8>, SectionKeyShare>,
    list: VecDeque<bls::PublicKey>,
    capacity: usize,
}

impl KeyCache {
    /// Constructor for capacity based `KeyCache`.
    pub fn with_capacity(capacity: usize) -> KeyCache {
        KeyCache {
            map: BTreeMap::new(),
            list: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    ///
    pub fn has_key_share(&self) -> bool {
        !self.list.is_empty()
    }

    ///
    pub fn get_most_recent(&self) -> Result<&SectionKeyShare> {
        if !self.list.is_empty() {
            if let Some(public_key) = self.list.get(self.list.len() - 1) {
                if let Some(share) = self.map.get(&bincode::serialize(public_key)?) {
                    return Ok(share);
                }
            }
        }
        Err(Error::MissingSecretKeyShare)
    }

    /// Uses the secret key from cache, corresponding to
    /// the provided public key.
    pub fn sign_with(
        &self,
        data: &[u8],
        public_key: &bls::PublicKey,
    ) -> Result<bls::SignatureShare> {
        let key = bincode::serialize(public_key)?;
        if let Some(section_key) = self.map.get(&key) {
            Ok(section_key.secret_key_share.sign(data))
        } else {
            Err(Error::MissingSecretKeyShare)
        }
    }

    /// Adds a new key to the cache, and removes + returns the oldest
    /// key if cache size is exceeded.
    pub fn add(
        &mut self,
        public_key: &bls::PublicKey,
        section_key_share: SectionKeyShare,
    ) -> Option<bls::PublicKey> {
        let key = bincode::serialize(public_key).ok()?;
        if self.map.contains_key(&key) {
            return None;
        }

        let mut evicted = None;
        if self.list.capacity() == self.list.len() {
            evicted = self.list.pop_front();
            if let Some(public_key) = evicted {
                let _ = self.map.remove(&bincode::serialize(&public_key).ok()?);
            }
        }

        self.list.push_back(*public_key);
        let _ = self.map.insert(key, section_key_share);

        evicted
    }
}
