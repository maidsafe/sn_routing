// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// TODO: remove this allow
#![allow(unused)]

use crate::{
    crypto::{self, Digest256},
    time::{Duration, Instant},
};
use err_derive::Error;
use serde::Serialize;
use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::{self, Debug, Formatter},
    iter, mem,
};

/// Default duration since their last modification after which all unaccumulated entries expire.
pub const DEFAULT_EXPIRATION: Duration = Duration::from_secs(120);

/// Accumulator for signature shares for arbitrary payloads.
pub struct SignatureAccumulator<T> {
    map: HashMap<Digest256, State<T>>,
    expiration: Duration,
}

impl<T> SignatureAccumulator<T>
where
    T: Debug + Serialize,
{
    /// Create new accumulator with default expiration.
    pub fn new() -> Self {
        Self::with_expiration(DEFAULT_EXPIRATION)
    }

    /// Create new accumulator with the given expiration.
    pub fn with_expiration(expiration: Duration) -> Self {
        Self {
            map: Default::default(),
            expiration,
        }
    }

    /// Add new share into the accumulator.
    pub fn add(
        &mut self,
        payload: T,
        public_key_set: &bls::PublicKeySet,
        signatory_index: usize,
        signature_share: bls::SignatureShare,
    ) -> Result<(T, bls::Signature), AccumulationError> {
        self.remove_expired();

        let mut bytes = bincode::serialize(&payload)?;

        let public_key_share = public_key_set.public_key_share(signatory_index);
        if !public_key_share.verify(&signature_share, &bytes) {
            return Err(AccumulationError::InvalidShare);
        }

        // Use the hash of the payload + the public key as the key in the map to avoid mixing
        // entries that have the same payload but are signed using different keys.
        let public_key = public_key_set.public_key();
        bytes.extend_from_slice(&public_key.to_bytes());
        let hash = crypto::sha3_256(&bytes);

        self.map
            .entry(hash)
            .or_insert_with(|| State::new(payload))
            .add(public_key_set, signatory_index, signature_share)
    }

    fn remove_expired(&mut self) {
        let expiration = self.expiration;
        self.map.retain(|_, state| {
            if state.modified().elapsed() < expiration {
                true
            } else {
                if let State::Accumulating { payload, .. } = state {
                    error!("Expired signature accumulation of {:?}", payload)
                }

                false
            }
        })
    }
}

impl<T> Default for SignatureAccumulator<T>
where
    T: Debug + Serialize,
{
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Error)]
pub enum AccumulationError {
    #[error(display = "not enough signature shares")]
    NotEnoughShares,
    #[error(display = "signature already accumulated")]
    AlreadyAccumulated,
    #[error(display = "signature share is invalid")]
    InvalidShare,
    #[error(display = "failed to serialise payload: {}", _0)]
    Serialise(#[error(source)] bincode::Error),
    #[error(display = "failed to combine signature shares: {}", _0)]
    Combine(#[error(from)] bls::error::Error),
}

enum State<T> {
    Accumulating {
        payload: T,
        shares: HashMap<usize, bls::SignatureShare>,
        modified: Instant,
    },
    Accumulated {
        modified: Instant,
    },
}

impl<T> State<T> {
    fn new(payload: T) -> Self {
        Self::Accumulating {
            payload,
            shares: Default::default(),
            modified: Instant::now(),
        }
    }

    fn add(
        &mut self,
        public_key_set: &bls::PublicKeySet,
        signatory_index: usize,
        signature_share: bls::SignatureShare,
    ) -> Result<(T, bls::Signature), AccumulationError> {
        match self {
            Self::Accumulating {
                shares, modified, ..
            } => {
                if shares.insert(signatory_index, signature_share).is_none() {
                    *modified = Instant::now();
                }

                if shares.len() > public_key_set.threshold() {
                    let signature = public_key_set
                        .combine_signatures(shares.iter().map(|(&index, share)| (index, share)))?;

                    let modified = *modified;
                    let state = mem::replace(self, State::Accumulated { modified });

                    if let State::Accumulating { payload, .. } = state {
                        Ok((payload, signature))
                    } else {
                        unreachable!()
                    }
                } else {
                    Err(AccumulationError::NotEnoughShares)
                }
            }
            Self::Accumulated { .. } => Err(AccumulationError::AlreadyAccumulated),
        }
    }

    fn modified(&self) -> Instant {
        match self {
            Self::Accumulating { modified, .. } | Self::Accumulated { modified } => *modified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng;

    #[test]
    fn smoke() {
        let mut rng = rng::new();
        let threshold = 3;
        let sk_set = bls::SecretKeySet::random(threshold, &mut rng);
        let pk_set = sk_set.public_keys();

        let mut accumulator = SignatureAccumulator::new();
        let payload = "hello".to_string();

        // Not enough shares yet
        for index in 0..threshold {
            let sk_share = sk_set.secret_key_share(index);
            let signature_share = sk_share.sign(&bincode::serialize(&payload).unwrap());
            let result = accumulator.add(payload.clone(), &pk_set, index, signature_share);

            match result {
                Err(AccumulationError::NotEnoughShares) => (),
                _ => panic!("unexpected result: {:?}", result),
            }
        }

        // Enough shares now
        let sk_share = sk_set.secret_key_share(threshold);
        let signature_share = sk_share.sign(&bincode::serialize(&payload).unwrap());
        let (accumulated_payload, signature) = accumulator
            .add(payload.clone(), &pk_set, threshold, signature_share)
            .unwrap();

        assert_eq!(accumulated_payload, payload);

        let pk = pk_set.public_key();
        assert!(pk.verify(
            &signature,
            bincode::serialize(&accumulated_payload).unwrap()
        ));

        // Extra shares are ignored
        let sk_share = sk_set.secret_key_share(threshold + 1);
        let signature_share = sk_share.sign(&bincode::serialize(&payload).unwrap());
        let result = accumulator.add(payload, &pk_set, threshold + 1, signature_share);

        match result {
            Err(AccumulationError::AlreadyAccumulated) => (),
            _ => panic!("unexpected result: {:?}", result),
        }
    }

    #[test]
    fn invalid_share() {
        let mut rng = rng::new();
        let threshold = 3;
        let sk_set = bls::SecretKeySet::random(threshold, &mut rng);
        let pk_set = sk_set.public_keys();

        let mut accumulator = SignatureAccumulator::new();
        let payload = "good".to_string();

        // First insert less than threshold + 1 valid shares.
        for index in 0..threshold {
            let sk_share = sk_set.secret_key_share(index);
            let signature_share = sk_share.sign(&bincode::serialize(&payload).unwrap());
            let _ = accumulator.add(payload.clone(), &pk_set, index, signature_share);
        }

        // Then try to insert invalid share.
        let sk_share = sk_set.secret_key_share(threshold);
        let invalid_signature_share = sk_share.sign(&bincode::serialize("bad").unwrap());
        let result = accumulator.add(payload.clone(), &pk_set, threshold, invalid_signature_share);

        match result {
            Err(AccumulationError::InvalidShare) => (),
            _ => panic!("unexpected result: {:?}", result),
        }

        // The invalid share doesn't spoil the accumulation - we can still accumulate once enough
        // valid shares are inserted.
        let sk_share = sk_set.secret_key_share(threshold + 1);
        let signature_share = sk_share.sign(&bincode::serialize(&payload).unwrap());
        let (accumulated_payload, signature) = accumulator
            .add(payload, &pk_set, threshold + 1, signature_share)
            .unwrap();

        let pk = pk_set.public_key();
        assert!(pk.verify(
            &signature,
            bincode::serialize(&accumulated_payload).unwrap()
        ))
    }

    #[cfg(feature = "mock_base")]
    #[test]
    fn expiration() {
        use fake_clock::FakeClock;

        let mut rng = rng::new();
        let threshold = 3;
        let sk_set = bls::SecretKeySet::random(threshold, &mut rng);
        let pk_set = sk_set.public_keys();

        let mut accumulator = SignatureAccumulator::new();
        let payload = "hello".to_string();

        for index in 0..threshold {
            let sk_share = sk_set.secret_key_share(index);
            let signature_share = sk_share.sign(&bincode::serialize(&payload).unwrap());
            let _ = accumulator.add(payload.clone(), &pk_set, index, signature_share);
        }

        FakeClock::advance_time(DEFAULT_EXPIRATION.as_secs() * 1000 + 1);

        // Adding another share does nothing now, because the previous shares expired.
        let sk_share = sk_set.secret_key_share(threshold);
        let signature_share = sk_share.sign(&bincode::serialize(&payload).unwrap());
        let result = accumulator.add(payload, &pk_set, threshold, signature_share);

        match result {
            Err(AccumulationError::NotEnoughShares) => (),
            _ => panic!("unexpected result: {:?}", result),
        }
    }
}
