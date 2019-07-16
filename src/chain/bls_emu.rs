// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Types emulating the BLS functionality until proper BLS lands
use super::{delivery_group_size, NetworkEvent, ProofSet, SectionInfo};
use crate::id::{FullId, PublicId};
use parsec;
use std::{collections::BTreeMap, fmt};

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKeySet {
    sec_info: SectionInfo,
    threshold: usize,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(PublicKeySet);

pub type SignatureShare = ::safe_crypto::Signature;

pub struct SecretKeyShare(FullId);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKeyShare(PublicId);

#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    sigs: BTreeMap<PublicId, SignatureShare>,
}

impl Signature {
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
        self.0.signing_private_key().sign_detached(message.as_ref())
    }
}

impl PublicKeyShare {
    #[allow(unused)]
    pub fn verify<M: AsRef<[u8]>>(&self, sig: &SignatureShare, msg: M) -> bool {
        self.0
            .signing_public_key()
            .verify_detached(sig, msg.as_ref())
    }
}

impl PublicKeySet {
    #[allow(unused)]
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    #[allow(unused)]
    pub fn combine_signatures<'a, I>(&self, shares: I) -> Option<Signature>
    where
        I: IntoIterator<Item = (PublicKeyShare, &'a SignatureShare)>,
    {
        let sigs: BTreeMap<_, _> = shares
            .into_iter()
            .filter(|(pk, _ss)| self.sec_info.members().contains(&pk.0))
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

    #[allow(unused)]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.clone())
    }
}

impl PublicKey {
    pub fn from_section_info(sec_info: &SectionInfo) -> Self {
        let threshold = delivery_group_size(sec_info.members().len());
        PublicKey(PublicKeySet {
            sec_info: sec_info.clone(),
            threshold,
        })
    }

    pub fn verify<M: AsRef<[u8]>>(&self, sig: &Signature, msg: M) -> bool {
        sig.sigs
            .iter()
            .filter(|&(pk, ss)| {
                self.0.sec_info.members().contains(pk)
                    && PublicKeyShare(*pk).verify(ss, msg.as_ref())
            })
            .count()
            > self.0.threshold
    }

    pub fn as_event(&self) -> parsec::Observation<NetworkEvent, PublicId> {
        parsec::Observation::OpaquePayload(NetworkEvent::SectionInfo(self.0.sec_info.clone()))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "BLS-PublicKey({:?})", self.0.sec_info)
    }
}
