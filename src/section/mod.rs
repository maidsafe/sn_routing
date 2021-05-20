// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod node_op;
mod online_nodes;
mod section_authority_provider;
mod section_chain;
mod section_keys;
mod section_peers;

#[cfg(test)]
pub(crate) use self::section_authority_provider::test_utils;
pub(crate) use self::section_peers::SectionPeers;
pub use self::{
    node_op::{
        NodeOp, PeerState, FIRST_SECTION_MAX_AGE, FIRST_SECTION_MIN_AGE, MIN_ADULT_AGE, MIN_AGE,
    },
    online_nodes::OnlineNodes,
    section_authority_provider::{ElderCandidates, SectionAuthorityProvider},
    section_chain::{Error as SectionChainError, SectionChain},
    section_keys::{SectionKeyShare, SectionKeysProvider},
};

use crate::{
    agreement::SectionSigned,
    error::{Error, Result},
    peer::Peer,
    ELDER_SIZE, RECOMMENDED_SECTION_SIZE,
};
use bls_signature_aggregator::Proof;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, convert::TryInto, iter, net::SocketAddr};
use xor_name::{Prefix, XorName};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct Section {
    genesis_key: bls::PublicKey,
    chain: SectionChain,
    online_nodes: OnlineNodes,
    // Can come back but will be relocated
    offline_nodes: SectionPeers,
    // Can never come back here (we killed or relocated them)
    dead_nodes: SectionPeers,
}

impl Section {
    /// Creates a minimal `Section` initially containing only info about our elders
    /// (`section_auth`).
    ///
    /// Returns error if `section_auth` is not signed with the last key of `chain`.
    pub fn new(
        genesis_key: bls::PublicKey,
        chain: SectionChain,
        section_auth: SectionSigned<SectionAuthorityProvider>,
    ) -> Result<Self, Error> {
        if section_auth.proof.public_key != *chain.last_key() {
            error!("can't create section: section_auth signed with incorrect key");
            // TODO: consider more specific error here.
            return Err(Error::InvalidMessage);
        }

        Ok(Self {
            genesis_key,
            chain,
            online_nodes: OnlineNodes::new(section_auth),
            offline_nodes: SectionPeers::default(),
            dead_nodes: SectionPeers::default(),
        })
    }

    /// Creates `Section` for the first node in the network
    pub fn first_node(peer: Peer) -> Result<(Self, SectionKeyShare)> {
        let secret_key_set = bls::SecretKeySet::random(0, &mut rand::thread_rng());
        let public_key_set = secret_key_set.public_keys();
        let secret_key_share = secret_key_set.secret_key_share(0);

        let section_auth =
            create_first_section_authority_provider(&public_key_set, &secret_key_share, peer)?;

        let mut section = Self::new(
            section_auth.proof.public_key,
            SectionChain::new(section_auth.proof.public_key),
            section_auth,
        )?;

        let node_op = NodeOp::joined(peer);
        let proof = create_first_proof(&public_key_set, &secret_key_share, &node_op)?;
        let _ = section.update_member(SectionSigned {
            value: node_op,
            proof,
        });

        let section_key_share = SectionKeyShare {
            public_key_set,
            index: 0,
            secret_key_share,
        };

        Ok((section, section_key_share))
    }

    pub fn genesis_key(&self) -> &bls::PublicKey {
        &self.genesis_key
    }

    /// Try to merge this `Section` with `other`. Returns `InvalidMessage` if `other` is invalid or
    /// its chain is not compatible with the chain of `self`.
    pub fn merge(&mut self, other: Self) -> Result<()> {
        other.self_verify()?;

        // The `SectionChain::merge` function carries out the check whether the incoming chain is
        // trust-worthy.
        self.chain.merge(other.chain.clone())?;

        if &other.signed_authority_provider().proof.public_key == self.chain.last_key() {
            self.online_nodes
                .set_section_auth(other.signed_authority_provider());
        }

        let incoming = other
            .online_nodes
            .members()
            .chain(other.offline_nodes.members())
            .chain(other.dead_nodes.members());

        for entry in incoming {
            let _ = self.update_member(entry.clone());
        }

        self.prune_not_matching();

        Ok(())
    }

    // TODO: use more specific error variant.
    fn self_verify(&self) -> Result<()> {
        if !self.signed_authority_provider().self_verify() {
            error!(
                "cannot verify the signed authority_provider {:?}",
                self.signed_authority_provider()
            );
            return Err(Error::InvalidMessage);
        }
        if &self.signed_authority_provider().proof.public_key != self.chain.last_key() {
            error!(
                "authority_provider is not signed by the last key in chain {:?} - {:?}",
                self.signed_authority_provider(),
                self.chain.last_key()
            );
            return Err(Error::InvalidMessage);
        }

        if self
            .online_nodes
            .all()
            .any(|op| op.state != PeerState::Joined)
        {
            error!(
                "online_nodes contains non-Joined node {:?}",
                self.online_nodes.peers()
            );
            return Err(Error::InvalidMessage);
        }
        if self
            .offline_nodes
            .all()
            .any(|op| op.state != PeerState::Left)
        {
            error!(
                "offline_nodes contains non-Left node {:?}",
                self.offline_nodes
            );
            return Err(Error::InvalidMessage);
        }
        if self
            .dead_nodes
            .all()
            .any(|op| !matches!(op.state, PeerState::Relocated(_)))
        {
            error!(
                "dead_nodes contains non-Relocated node {:?}",
                self.dead_nodes
            );
            return Err(Error::InvalidMessage);
        }

        let not_has_key = |entry: &SectionSigned<NodeOp>| {
            let not_has_key = !self.chain.has_key(&entry.proof.public_key);
            if not_has_key {
                error!(
                    "contains entry signed by unknown key {:?} - {:?}",
                    entry, self.chain
                );
            }
            not_has_key
        };
        let mut entries = self
            .online_nodes
            .members()
            .chain(self.offline_nodes.members())
            .chain(self.dead_nodes.members());

        if entries.any(|entry| not_has_key(entry)) {
            return Err(Error::InvalidMessage);
        }

        Ok(())
    }

    fn prune_not_matching(&mut self) {
        let prefix = self.authority_provider().prefix;
        self.online_nodes.prune_not_matching(&prefix);
        self.offline_nodes.prune_not_matching(&prefix);
        self.dead_nodes.prune_not_matching(&prefix);
    }

    /// Update the `SectionAuthorityProvider` of our section.
    pub fn update_elders(
        &mut self,
        new_section_auth: SectionSigned<SectionAuthorityProvider>,
        new_key_proof: Proof,
    ) -> bool {
        if new_section_auth.value.prefix() != *self.prefix()
            && !new_section_auth
                .value
                .prefix()
                .is_extension_of(self.prefix())
        {
            return false;
        }

        if !new_section_auth.self_verify() {
            return false;
        }

        if let Err(error) = self.chain.insert(
            &new_key_proof.public_key,
            new_section_auth.proof.public_key,
            new_key_proof.signature,
        ) {
            error!(
                "failed to insert key {:?} (signed with {:?}) into the section chain: {}",
                new_section_auth.proof.public_key, new_key_proof.public_key, error,
            );
            return false;
        }

        if &new_section_auth.proof.public_key == self.chain.last_key() {
            self.online_nodes.set_section_auth(&new_section_auth);
        }

        self.prune_not_matching();

        true
    }

    /// Update the member. Returns whether it actually changed anything.
    pub fn update_member(&mut self, new_op: SectionSigned<NodeOp>) -> bool {
        if !new_op.verify(&self.chain) {
            error!("can't merge member {:?}", new_op.value);
            return false;
        }

        // To maintain commutativity, the only allowed transitions are:
        // - Joined -> Joined if the new age is greater than the old age
        // - Joined -> Left
        // - Joined -> Relocated
        // - Relocated -> Left (should not happen, but needed for consistency)
        let cur_op = self
            .online_nodes
            .take(new_op.value.peer.name())
            .or_else(|| self.dead_nodes.take(new_op.value.peer.name()))
            .or_else(|| self.offline_nodes.take(new_op.value.peer.name()));

        if let Some(cur_op) = cur_op {
            match (cur_op.value.state, new_op.value.state) {
                (PeerState::Joined, PeerState::Joined) => {
                    if new_op.value.peer.age() > cur_op.value.peer.age() {
                        self.online_nodes.add(new_op);
                    } else {
                        self.online_nodes.add(cur_op);
                        return false;
                    }
                }
                (PeerState::Joined, PeerState::Left) => {
                    // TODO: differentiate left and killed
                    self.offline_nodes.add(new_op);
                }
                (PeerState::Joined, PeerState::Relocated(_))
                | (PeerState::Left, PeerState::Relocated(_)) => {
                    self.dead_nodes.add(new_op);
                }
                (PeerState::Left, PeerState::Joined) | (PeerState::Left, PeerState::Left) => {
                    self.offline_nodes.add(cur_op);
                    return false;
                }
                (PeerState::Relocated(_), _) => {
                    self.dead_nodes.add(cur_op);
                    return false;
                }
            };
        } else {
            match new_op.value.state {
                PeerState::Joined => self.online_nodes.add(new_op),
                PeerState::Left => self.offline_nodes.add(new_op),
                PeerState::Relocated(_) => self.dead_nodes.add(new_op),
            }
        }

        true
    }

    pub fn chain(&self) -> &SectionChain {
        &self.chain
    }

    // Extend the section chain so it starts at `trusted_key` while keeping the last key intact.
    pub(crate) fn extend_chain(
        &self,
        trusted_key: &bls::PublicKey,
        full_chain: &SectionChain,
    ) -> Result<Self, SectionChainError> {
        let chain = match self.chain.extend(trusted_key, full_chain) {
            Ok(chain) => chain,
            Err(SectionChainError::InvalidOperation) => {
                // This means the tip of the chain is not reachable from `trusted_key`.
                // Use the full chain instead as it is always trusted.
                self.chain.clone()
            }
            Err(error) => return Err(error),
        };

        Ok(Self {
            genesis_key: self.genesis_key,
            chain,
            online_nodes: self.online_nodes.clone(),
            offline_nodes: self.offline_nodes.clone(),
            dead_nodes: self.dead_nodes.clone(),
        })
    }

    pub fn authority_provider(&self) -> &SectionAuthorityProvider {
        &self.signed_authority_provider().value
    }

    pub fn signed_authority_provider(&self) -> &SectionSigned<SectionAuthorityProvider> {
        self.online_nodes.section_auth()
    }

    pub fn is_elder(&self, name: &XorName) -> bool {
        self.authority_provider().contains_elder(name)
    }

    pub fn online_nodes(&self) -> &OnlineNodes {
        &self.online_nodes
    }

    /// Generate a new section info(s) based on the current set of members.
    /// Returns a set of candidate SectionAuthorityProviders.
    pub fn promote_and_demote_elders(&self, our_name: &XorName) -> Vec<ElderCandidates> {
        if let Some((our_elder_candidates, other_elder_candidates)) = self.try_split(our_name) {
            return vec![our_elder_candidates, other_elder_candidates];
        }

        let expected_peers = self.elder_candidates(ELDER_SIZE);
        let expected_names: BTreeSet<_> = expected_peers.iter().map(Peer::name).cloned().collect();
        let current_names: BTreeSet<_> = self.authority_provider().names();

        if expected_names == current_names {
            vec![]
        } else if expected_names.len() < crate::supermajority(current_names.len()) {
            warn!("ignore attempt to reduce the number of elders too much");
            vec![]
        } else {
            let elder_candidates =
                ElderCandidates::new(expected_peers, self.authority_provider().prefix());
            vec![elder_candidates]
        }
    }

    // Prefix of our section.
    pub fn prefix(&self) -> &Prefix {
        &self.authority_provider().prefix
    }

    // Members of adults AND elders.
    pub fn members(&self) -> &SectionPeers {
        self.online_nodes.peers()
    }

    /// Returns adults from our section.
    pub fn adults(&self) -> impl Iterator<Item = &Peer> {
        self.online_nodes.adults()
    }

    pub fn find_joined_member_by_addr(&self, addr: &SocketAddr) -> Option<&Peer> {
        self.online_nodes
            .all()
            .find(|info| info.peer.addr() == addr)
            .map(|info| &info.peer)
    }

    // Tries to split our section.
    // If we have enough mature nodes for both subsections, returns the SectionAuthorityProviders
    // of the two subsections. Otherwise returns `None`.
    fn try_split(&self, our_name: &XorName) -> Option<(ElderCandidates, ElderCandidates)> {
        let next_bit_index = if let Ok(index) = self.prefix().bit_count().try_into() {
            index
        } else {
            // Already at the longest prefix, can't split further.
            return None;
        };

        let next_bit = our_name.bit(next_bit_index);

        let (our_new_size, sibling_new_size) = self
            .online_nodes
            .all()
            .map(|op| op.peer.name().bit(next_bit_index) == next_bit)
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

        let our_elders = self.online_nodes.elder_candidates_matching_prefix(
            &our_prefix,
            ELDER_SIZE,
            self.authority_provider(),
        );
        let other_elders = self.online_nodes.elder_candidates_matching_prefix(
            &other_prefix,
            ELDER_SIZE,
            self.authority_provider(),
        );

        let our_elder_candidates = ElderCandidates::new(our_elders, our_prefix);
        let other_elder_candidates = ElderCandidates::new(other_elders, other_prefix);

        Some((our_elder_candidates, other_elder_candidates))
    }

    // Returns the candidates for elders out of all the nodes in the section, even out of the
    // relocating nodes if there would not be enough instead.
    fn elder_candidates(&self, elder_size: usize) -> Vec<Peer> {
        self.online_nodes
            .elder_candidates(elder_size, self.authority_provider())
    }
}

// Create `SectionAuthorityProvider` for the first node.
fn create_first_section_authority_provider(
    pk_set: &bls::PublicKeySet,
    sk_share: &bls::SecretKeyShare,
    mut peer: Peer,
) -> Result<SectionSigned<SectionAuthorityProvider>> {
    peer.set_reachable(true);
    let section_auth =
        SectionAuthorityProvider::new(iter::once(peer), Prefix::default(), pk_set.clone());
    let proof = create_first_proof(pk_set, sk_share, &section_auth)?;
    Ok(SectionSigned::new(section_auth, proof))
}

fn create_first_proof<T: Serialize>(
    pk_set: &bls::PublicKeySet,
    sk_share: &bls::SecretKeyShare,
    payload: &T,
) -> Result<Proof> {
    let bytes = bincode::serialize(payload).map_err(|_| Error::InvalidPayload)?;
    let signature_share = sk_share.sign(&bytes);
    let signature = pk_set
        .combine_signatures(iter::once((0, &signature_share)))
        .map_err(|_| Error::InvalidSignatureShare)?;

    Ok(Proof {
        public_key: pk_set.public_key(),
        signature,
    })
}
