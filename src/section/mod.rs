// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod elders_info;
mod member_info;
mod section_keys;
mod section_peers;
mod section_proof_chain;

#[cfg(test)]
pub(crate) use self::elders_info::test_utils;
pub(crate) use self::section_peers::SectionPeers;
pub use self::{
    elders_info::EldersInfo,
    member_info::{MemberInfo, PeerState, MIN_AGE},
    section_keys::{SectionKeyShare, SectionKeysProvider},
    section_proof_chain::{ExtendError, SectionProofChain, TrustStatus},
};

use crate::{
    consensus::Proven,
    error::{Error, Result},
    peer::Peer,
    ELDER_SIZE, RECOMMENDED_SECTION_SIZE,
};
use bls_signature_aggregator::Proof;
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::BTreeSet, convert::TryInto, iter, net::SocketAddr};
use xor_name::{Prefix, XorName};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct Section {
    members: SectionPeers,
    elders_info: Proven<EldersInfo>,
    chain: SectionProofChain,
}

impl Section {
    /// Creates a minimal `Section` initially containing only info about our elders
    /// (`elders_info`).
    pub fn new(chain: SectionProofChain, elders_info: Proven<EldersInfo>) -> Result<Self, Error> {
        if !chain.has_key(&elders_info.proof.public_key) {
            return Err(Error::UntrustedMessage);
        }

        Ok(Self {
            elders_info,
            chain,
            members: SectionPeers::default(),
        })
    }

    /// Creates `Section` for the first node in the network
    pub fn first_node(peer: Peer) -> Result<(Self, SectionKeyShare)> {
        let secret_key_set = bls::SecretKeySet::random(0, &mut rand::thread_rng());
        let public_key_set = secret_key_set.public_keys();
        let secret_key_share = secret_key_set.secret_key_share(0);

        // Note: `ElderInfo` is normally signed with the previous key, but as we are the first node
        // of the network there is no previous key. Sign with the current key instead.
        let elders_info = create_first_elders_info(&public_key_set, &secret_key_share, peer)?;

        let mut section = Self::new(
            SectionProofChain::new(elders_info.proof.public_key),
            elders_info,
        )?;

        for peer in section.elders_info.value.peers() {
            let member_info = MemberInfo::joined(*peer);
            let proof = create_first_proof(&public_key_set, &secret_key_share, &member_info)?;
            let _ = section.members.update(Proven {
                value: member_info,
                proof,
            });
        }

        let section_key_share = SectionKeyShare {
            public_key_set,
            index: 0,
            secret_key_share,
        };

        Ok((section, section_key_share))
    }

    pub fn merge(&mut self, other: Self) -> Result<()> {
        if !other.chain.self_verify() {
            return Err(Error::InvalidMessage);
        }

        self.chain
            .merge(other.chain)
            .map_err(|_| Error::UntrustedMessage)?;

        match cmp_section_chain_position(&self.elders_info, &other.elders_info, &self.chain) {
            Some(Ordering::Less) => {
                self.elders_info = other.elders_info;
            }
            Some(Ordering::Equal)
                if self.elders_info.value.elders.len() < other.elders_info.value.elders.len() =>
            {
                // Note: our `EldersInfo` is normally signed with the previous key, except the very
                // first one which is signed with the latest key. This means that the first and
                // second `EldersInfo`s are signed with the same key and so comparing only the keys
                // is not enough to decide which one is newer. To break the ties, we use the fact
                // that the first `EldersInfo` always has only one elder and the second one has
                // two.
                self.elders_info = other.elders_info;
            }
            Some(Ordering::Greater) | Some(Ordering::Equal) | None => (),
        }

        for info in other.members {
            let _ = self.update_member(info);
        }

        self.members
            .prune_not_matching(&self.elders_info.value.prefix);

        Ok(())
    }

    /// Update the `EldersInfo` of our section.
    pub fn update_elders(&mut self, new_elders_info: Proven<EldersInfo>) -> bool {
        if !new_elders_info.verify(&self.chain) {
            return false;
        }

        if new_elders_info != self.elders_info {
            self.elders_info = new_elders_info;
            self.members
                .prune_not_matching(&self.elders_info.value.prefix);

            true
        } else {
            false
        }
    }

    pub fn update_chain(&mut self, key: Proven<bls::PublicKey>) -> bool {
        self.chain.push(key.value, key.proof.signature)
    }

    /// Update the member. Returns whether it actually changed anything.
    pub fn update_member(&mut self, member_info: Proven<MemberInfo>) -> bool {
        if !member_info.verify(&self.chain) {
            return false;
        }

        self.members.update(member_info)
    }

    pub fn to_minimal(&self) -> Self {
        let first_key_index = self.elders_info_signing_key_index();

        Self {
            elders_info: self.elders_info.clone(),
            chain: self.chain.slice(first_key_index..),
            members: SectionPeers::default(),
        }
    }

    pub fn chain(&self) -> &SectionProofChain {
        &self.chain
    }

    // Creates the shortest proof chain that includes both the key at `their_knowledge`
    // (if provided) and the key our current `elders_info` was signed with.
    pub fn create_proof_chain_for_our_info(
        &self,
        their_knowledge: Option<u64>,
    ) -> SectionProofChain {
        let first_index = self.elders_info_signing_key_index();
        let first_index = their_knowledge.unwrap_or(first_index).min(first_index);
        self.chain.slice(first_index..)
    }

    pub fn elders_info(&self) -> &EldersInfo {
        &self.elders_info.value
    }

    pub fn proven_elders_info(&self) -> &Proven<EldersInfo> {
        &self.elders_info
    }

    pub fn is_elder(&self, name: &XorName) -> bool {
        self.elders_info().elders.contains_key(name)
    }

    /// Generate a new section info(s) based on the current set of members.
    /// Returns a set of EldersInfos to vote for.
    pub fn promote_and_demote_elders(&self, our_name: &XorName) -> Vec<EldersInfo> {
        if let Some((our_info, other_info)) = self.try_split(our_name) {
            return vec![our_info, other_info];
        }

        let expected_peers = self.elder_candidates(ELDER_SIZE);
        let expected_names: BTreeSet<_> = expected_peers.iter().map(Peer::name).collect();
        let current_names: BTreeSet<_> = self.elders_info().elders.keys().collect();

        if expected_names == current_names {
            vec![]
        } else if expected_names.len() < crate::majority(current_names.len()) {
            warn!("ignore attempt to reduce the number of elders too much");
            vec![]
        } else {
            let new_info = EldersInfo::new(expected_peers, self.elders_info().prefix);
            vec![new_info]
        }
    }

    /// Returns whether the given peer adult or elder.
    pub fn is_adult_or_elder(&self, name: &XorName) -> bool {
        self.members.is_mature(name) || self.is_elder(name)
    }

    // Prefix of our section.
    pub fn prefix(&self) -> &Prefix {
        &self.elders_info().prefix
    }

    pub fn members(&self) -> &SectionPeers {
        &self.members
    }

    /// Returns members that are either joined or are left but still elders.
    pub fn active_members(&self) -> impl Iterator<Item = &Peer> {
        self.members
            .all()
            .filter(move |info| {
                self.members.is_joined(info.peer.name()) || self.is_elder(info.peer.name())
            })
            .map(|info| &info.peer)
    }

    /// Returns adults from our section.
    pub fn adults(&self) -> impl Iterator<Item = &Peer> {
        self.members
            .mature()
            .filter(move |peer| !self.is_elder(peer.name()))
    }

    pub fn find_joined_member_by_addr(&self, addr: &SocketAddr) -> Option<&Peer> {
        self.members
            .joined()
            .find(|info| info.peer.addr() == addr)
            .map(|info| &info.peer)
    }

    fn elders_info_signing_key_index(&self) -> u64 {
        // NOTE: we assume that the key the current `EldersInfo` is signed with is always
        // present in our section proof chain. This is currently guaranteed, because we use the
        // `UpdateBarrier` and so we always update the current `EldersInfo` and the current
        // section key at the same time.
        self.chain
            .index_of(&self.elders_info.proof.public_key)
            .unwrap_or_else(|| unreachable!("EldersInfo signed with unknown key"))
    }

    // Tries to split our section.
    // If we have enough mature nodes for both subsections, returns the elders infos of the two
    // subsections. Otherwise returns `None`.
    fn try_split(&self, our_name: &XorName) -> Option<(EldersInfo, EldersInfo)> {
        let next_bit_index = if let Ok(index) = self.prefix().bit_count().try_into() {
            index
        } else {
            // Already at the longest prefix, can't split further.
            return None;
        };

        let next_bit = our_name.bit(next_bit_index);

        let (our_new_size, sibling_new_size) = self
            .members
            .mature()
            .map(|peer| peer.name().bit(next_bit_index) == next_bit)
            .fold((0, 0), |(ours, siblings), is_our_prefix| {
                if is_our_prefix {
                    (ours + 1, siblings)
                } else {
                    (ours, siblings + 1)
                }
            });

        // If none of the two new sections would contain enough entries, return `None`.
        if our_new_size < RECOMMENDED_SECTION_SIZE || sibling_new_size < RECOMMENDED_SECTION_SIZE {
            return None;
        }

        let our_prefix = self.prefix().pushed(next_bit);
        let other_prefix = self.prefix().pushed(!next_bit);

        let our_elders = self.members.elder_candidates_matching_prefix(
            &our_prefix,
            ELDER_SIZE,
            self.elders_info(),
        );
        let other_elders = self.members.elder_candidates_matching_prefix(
            &other_prefix,
            ELDER_SIZE,
            self.elders_info(),
        );

        let our_info = EldersInfo::new(our_elders, our_prefix);
        let other_info = EldersInfo::new(other_elders, other_prefix);

        Some((our_info, other_info))
    }

    // Returns the candidates for elders out of all the nodes in the section, even out of the
    // relocating nodes if there would not be enough instead.
    fn elder_candidates(&self, elder_size: usize) -> Vec<Peer> {
        self.members
            .elder_candidates(elder_size, self.elders_info())
    }
}

// Create `EldersInfo` for the first node.
fn create_first_elders_info(
    pk_set: &bls::PublicKeySet,
    sk_share: &bls::SecretKeyShare,
    peer: Peer,
) -> Result<Proven<EldersInfo>> {
    let elders_info = EldersInfo::new(iter::once(peer), Prefix::default());
    let proof = create_first_proof(pk_set, sk_share, &elders_info)?;
    Ok(Proven::new(elders_info, proof))
}

fn create_first_proof<T: Serialize>(
    pk_set: &bls::PublicKeySet,
    sk_share: &bls::SecretKeyShare,
    payload: &T,
) -> Result<Proof> {
    let bytes = bincode::serialize(payload)?;
    let signature_share = sk_share.sign(&bytes);
    let signature = pk_set
        .combine_signatures(iter::once((0, &signature_share)))
        .map_err(|_| Error::InvalidSignatureShare)?;

    Ok(Proof {
        public_key: pk_set.public_key(),
        signature,
    })
}

fn cmp_section_chain_position<T: Serialize>(
    lhs: &Proven<T>,
    rhs: &Proven<T>,
    section_chain: &SectionProofChain,
) -> Option<Ordering> {
    match (lhs.self_verify(), rhs.self_verify()) {
        (true, true) => (),
        (true, false) => return Some(Ordering::Greater),
        (false, true) => return Some(Ordering::Less),
        (false, false) => return None,
    }

    let lhs_index = section_chain.index_of(&lhs.proof.public_key);
    let rhs_index = section_chain.index_of(&rhs.proof.public_key);

    match (lhs_index, rhs_index) {
        (Some(lhs_index), Some(rhs_index)) => Some(lhs_index.cmp(&rhs_index)),
        (Some(_), None) => Some(Ordering::Greater),
        (None, Some(_)) => Some(Ordering::Less),
        (None, None) => None,
    }
}
