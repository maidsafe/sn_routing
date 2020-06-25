// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::proof::{Proof, ProofShare};
use crate::{
    crypto::{self, Digest256},
    time::{Duration, Instant},
};
use err_derive::Error;
use serde::Serialize;
use std::{collections::HashMap, fmt::Debug, mem};

/// Default duration since their last modification after which all unaccumulated entries expire.
pub const DEFAULT_EXPIRATION: Duration = Duration::from_secs(120);

/// Accumulator for signature shares for arbitrary payloads.
///
/// This accumulator allows to collect BLS signature shares for some payload one by one until enough
/// of them are collected. At that point it combines them into a full BLS signature of the given
/// payload. It also automatically rejects invalid signature shares and expires entries that did not
/// collect enough signature shares within a given time.
///
/// The accumulated payload needs to implement `Serialize` which is used in two ways:
///
/// 1. to calculate a cryptographic hash of the payload which is then used to compute the
///    accumulation key.
///    This means that two signature shares with payloads that serialize into the same byte sequence
///    are accumulated together.
/// 2. to verify the signature share - the serialized payload is what is passed to the `verify`
///    function.
///
/// The serialization is performed using `bincode::serialize` which also needs to be used to
/// create the signature share.
///
/// This accumulator also handles the case when the same payload is signed with a signature share
/// corresponding to a different BLS public key. In that case, the payloads will be accumulated
/// separately. This avoids mixing signature shares created from different curves which would
/// otherwise lead to invalid signature being produces event though all the shares are valid.
///
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

    /// Add new share into the accumulator. If enough valid signature shares were collected, returns
    /// the payload and its corresponding `Proof` (signature + public key). Otherwise returns error
    /// which details why the accumulation did not succeed yet.
    ///
    /// Note: returned `AccumulationError::NotEnoughShares` does not indicate a failure. It simply
    /// means more shares still need to be added for that particular payload. Similarly,
    /// `AccumulationError::AlreadyAccumulated` means the signature was already accumulated and
    /// adding more shares has no effect. These two errors could be safely ignored (they might
    /// still be useful perhaps for debugging). The other error variants, however, indicate
    /// failures and should be treated a such. See [AccumulationError](enum.AccumulationError.html)
    /// for more info.
    ///
    /// Note: the `signature_share` field in the `proof_share` must be created by serializing the
    /// `payload` with `bincode::serialize` and signing the resulting bytes. Other serialization
    /// formats are not currently supported.
    pub fn add(
        &mut self,
        payload: T,
        proof_share: ProofShare,
    ) -> Result<(T, Proof), AccumulationError> {
        self.remove_expired();

        let mut bytes = bincode::serialize(&payload)?;

        if !proof_share.verify(&bytes) {
            return Err(AccumulationError::InvalidShare);
        }

        // Use the hash of the payload + the public key as the key in the map to avoid mixing
        // entries that have the same payload but are signed using different keys.
        let public_key = proof_share.public_key_set.public_key();
        bytes.extend_from_slice(&public_key.to_bytes());
        let hash = crypto::sha3_256(&bytes);

        self.map
            .entry(hash)
            .or_insert_with(|| State::new(payload))
            .add(proof_share)
            .map(|(payload, signature)| {
                (
                    payload,
                    Proof {
                        public_key,
                        signature,
                    },
                )
            })
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

/// Error returned from SignatureAccumulator::add.
#[derive(Debug, Error)]
pub enum AccumulationError {
    /// There are not enough signature shares yet, more need to be added. This is not a failure.
    #[error(display = "not enough signature shares")]
    NotEnoughShares,
    /// Enough signature share were already collected before and adding more has no effect. This is
    /// not a failure.
    #[error(display = "signature already accumulated")]
    AlreadyAccumulated,
    /// The signature share being added is invalid. Such share is rejected but the already collected
    /// shares are kept intact. If enough new valid shares are collected afterwards, the
    /// accumulation might still succeed.
    #[error(display = "signature share is invalid")]
    InvalidShare,
    /// The payload failed to be serialised and can't be inserted into the accumulator. This doesn't
    /// affect other entries already present and the accumulator can still be used normally
    /// afterwards.
    #[error(display = "failed to serialise payload: {}", _0)]
    Serialise(#[error(source)] bincode::Error),
    /// The signature combination failed even though there are enough valid signature shares. This
    /// should probably never happen.
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

    fn add(&mut self, proof_share: ProofShare) -> Result<(T, bls::Signature), AccumulationError> {
        match self {
            Self::Accumulating {
                shares, modified, ..
            } => {
                if shares
                    .insert(proof_share.index, proof_share.signature_share)
                    .is_none()
                {
                    *modified = Instant::now();
                }

                if shares.len() > proof_share.public_key_set.threshold() {
                    let signature = proof_share
                        .public_key_set
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

        let mut accumulator = SignatureAccumulator::new();
        let payload = "hello".to_string();

        // Not enough shares yet
        for index in 0..threshold {
            let proof_share = create_proof_share(&sk_set, index, &payload);
            let result = accumulator.add(payload.clone(), proof_share);

            match result {
                Err(AccumulationError::NotEnoughShares) => (),
                _ => panic!("unexpected result: {:?}", result),
            }
        }

        // Enough shares now
        let proof_share = create_proof_share(&sk_set, threshold, &payload);
        let (accumulated_payload, proof) = accumulator.add(payload.clone(), proof_share).unwrap();

        assert_eq!(accumulated_payload, payload);
        assert!(proof.verify(&bincode::serialize(&accumulated_payload).unwrap()));

        // Extra shares are ignored
        let proof_share = create_proof_share(&sk_set, threshold + 1, &payload);
        let result = accumulator.add(payload, proof_share);

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

        let mut accumulator = SignatureAccumulator::new();
        let payload = "good".to_string();

        // First insert less than threshold + 1 valid shares.
        for index in 0..threshold {
            let proof_share = create_proof_share(&sk_set, index, &payload);
            let _ = accumulator.add(payload.clone(), proof_share);
        }

        // Then try to insert invalid share.
        let invalid_proof_share = create_proof_share(&sk_set, threshold, &"bad".to_string());
        let result = accumulator.add(payload.clone(), invalid_proof_share);

        match result {
            Err(AccumulationError::InvalidShare) => (),
            _ => panic!("unexpected result: {:?}", result),
        }

        // The invalid share doesn't spoil the accumulation - we can still accumulate once enough
        // valid shares are inserted.
        let proof_share = create_proof_share(&sk_set, threshold + 1, &payload);
        let (accumulated_payload, proof) = accumulator.add(payload, proof_share).unwrap();
        assert!(proof.verify(&bincode::serialize(&accumulated_payload).unwrap()))
    }

    #[cfg(feature = "mock_base")]
    #[test]
    fn expiration() {
        use fake_clock::FakeClock;

        let mut rng = rng::new();
        let threshold = 3;
        let sk_set = bls::SecretKeySet::random(threshold, &mut rng);

        let mut accumulator = SignatureAccumulator::new();
        let payload = "hello".to_string();

        for index in 0..threshold {
            let proof_share = create_proof_share(&sk_set, index, &payload);
            let _ = accumulator.add(payload.clone(), proof_share);
        }

        FakeClock::advance_time(DEFAULT_EXPIRATION.as_secs() * 1000 + 1);

        // Adding another share does nothing now, because the previous shares expired.
        let proof_share = create_proof_share(&sk_set, threshold, &payload);
        let result = accumulator.add(payload, proof_share);

        match result {
            Err(AccumulationError::NotEnoughShares) => (),
            _ => panic!("unexpected result: {:?}", result),
        }
    }

    fn create_proof_share<T: Serialize>(
        sk_set: &bls::SecretKeySet,
        index: usize,
        payload: &T,
    ) -> ProofShare {
        let sk_share = sk_set.secret_key_share(index);
        let signature_share = sk_share.sign(&bincode::serialize(&payload).unwrap());

        ProofShare {
            public_key_set: sk_set.public_keys(),
            index,
            signature_share,
        }
    }
}
