// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Types emulating the BLS functionality until proper BLS lands
use super::EldersInfo;
#[cfg(feature = "mock_base")]
use super::ProofSet;
use crate::{
    crypto,
    id::{FullId, PublicId},
};
use std::{collections::BTreeMap, fmt};

/// The BLS scheme will require more than `THRESHOLD_NUMERATOR / THRESHOLD_DENOMINATOR`
/// shares in order to construct a full key or signature.
pub const THRESHOLD_NUMERATOR: usize = 1;
/// See `THRESHOLD_NUMERATOR`.
pub const THRESHOLD_DENOMINATOR: usize = 3;

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct PublicKeySet {
    elders_info: EldersInfo,
    threshold: usize,
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct PublicKey(PublicKeySet);

pub type SignatureShare = crypto::signing::Signature;

pub struct SecretKeyShare(FullId);

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy, Hash, Serialize, Deserialize, Debug)]
pub struct PublicKeyShare(pub PublicId);

#[derive(Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct Signature {
    sigs: BTreeMap<PublicId, SignatureShare>,
}

impl Signature {
    #[cfg(feature = "mock_base")]
    pub fn from_proof_set(proofs: ProofSet) -> Self {
        Self { sigs: proofs.sigs }
    }
}

impl SecretKeyShare {
    #[allow(unused)]
    pub fn public_key_share(&self) -> PublicKeyShare {
        PublicKeyShare(*self.0.public_id())
    }

    #[allow(unused)]
    pub fn sign<M: AsRef<[u8]>>(&self, message: M) -> SignatureShare {
        self.0.sign(message.as_ref())
    }
}

impl PublicKeyShare {
    pub fn verify<M: AsRef<[u8]>>(&self, sig: &SignatureShare, msg: M) -> bool {
        self.0.verify(msg.as_ref(), sig)
    }
}

impl PublicKeySet {
    pub fn from_elders_info(elders_info: EldersInfo) -> Self {
        let threshold = elders_info.members().len() * THRESHOLD_NUMERATOR / THRESHOLD_DENOMINATOR;
        Self {
            threshold,
            elders_info,
        }
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn combine_signatures<'a, I>(&self, shares: I) -> Option<Signature>
    where
        I: IntoIterator<Item = (PublicKeyShare, &'a SignatureShare)>,
    {
        let sigs: BTreeMap<_, _> = shares
            .into_iter()
            .filter(|(pk, _ss)| self.elders_info.members().contains(&pk.0))
            .map(|(pk, ss)| (pk.0, *ss))
            .collect();
        // In the BLS scheme, more than `threshold` valid signatures are needed to obtain a
        // combined signature - copy this behaviour
        if sigs.len() <= self.threshold {
            None
        } else {
            Some(Signature { sigs })
        }
    }

    #[cfg(test)]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.clone())
    }
}

impl PublicKey {
    pub fn from_elders_info(elders_info: &EldersInfo) -> Self {
        PublicKey(PublicKeySet::from_elders_info(elders_info.clone()))
    }

    pub fn verify<M: AsRef<[u8]>>(&self, sig: &Signature, msg: M) -> bool {
        sig.sigs
            .iter()
            .filter(|&(pk, ss)| {
                self.0.elders_info.members().contains(pk)
                    && PublicKeyShare(*pk).verify(ss, msg.as_ref())
            })
            .count()
            > self.0.threshold
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "BLS-PublicKey({:?})", self.0.elders_info)
    }
}

/// Allow SectionKeyInfo to access internal until we switch to real BLS where
/// the signature verification will be done on the full SectionKeyInfo.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub(super) struct BlsPublicKeyForSectionKeyInfo(PublicKey);

impl BlsPublicKeyForSectionKeyInfo {
    pub fn from_elders_info(elders_info: &EldersInfo) -> Self {
        Self(PublicKey::from_elders_info(elders_info))
    }

    pub fn key(&self) -> &PublicKey {
        &self.0
    }

    pub fn internal_elders_info(&self) -> &EldersInfo {
        &(self.0).0.elders_info
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        id::{FullId, P2pNode},
        ConnectionInfo,
    };
    use unwrap::unwrap;

    fn gen_section(size: usize) -> (PublicKeySet, Vec<SecretKeyShare>) {
        let ids: Vec<_> = (0..size).map(|_| FullId::new()).collect();
        let p2p_nodes = ids
            .iter()
            .enumerate()
            .map(|(index, full_id)| {
                (
                    *full_id.public_id().name(),
                    P2pNode::new(
                        *full_id.public_id(),
                        ConnectionInfo {
                            peer_addr: ([127, 0, 0, 1], (index + 9000) as u16).into(),
                            peer_cert_der: vec![],
                        },
                    ),
                )
            })
            .collect();
        let elders_info = unwrap!(EldersInfo::new(p2p_nodes, Default::default(), None));
        let pk_set = PublicKeySet::from_elders_info(elders_info);

        (pk_set, ids.into_iter().map(SecretKeyShare).collect())
    }

    #[test]
    fn test_signature() {
        let section_size = 10;
        let min_sigs = section_size * THRESHOLD_NUMERATOR / THRESHOLD_DENOMINATOR + 1;

        let (pk_set, sk_shares) = gen_section(section_size);

        let data = [1u8, 2, 3, 4, 5, 6];

        let mut sigs: Vec<_> = sk_shares
            .iter()
            .take(min_sigs - 1)
            .map(|sk| (sk.public_key_share(), sk.sign(&data)))
            .collect();

        assert!(sigs.iter().all(|(pks, sig)| pks.verify(sig, &data)));

        assert!(pk_set
            .combine_signatures(sigs.iter().map(|(pk, sig)| (*pk, sig)))
            .is_none());

        sigs.push((
            sk_shares[min_sigs - 1].public_key_share(),
            sk_shares[min_sigs - 1].sign(&data),
        ));

        let sig = unwrap!(pk_set.combine_signatures(sigs.iter().map(|(pk, sig)| (*pk, sig))));

        assert!(pk_set.public_key().verify(&sig, &data));
    }
}
