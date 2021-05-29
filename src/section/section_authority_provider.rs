// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{peer::PeerUtils, Prefix, XorName};
use bls::PublicKey;
use sn_data_types::ReplicaPublicKeySet;
use sn_messaging::node::{ElderCandidates, Peer, SectionAuthorityProvider};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
};

/// The information about elder candidates in a DKG round.
pub trait ElderCandidatesUtils {
    /// Creates a new `ElderCandidates` with the given members and prefix.
    fn new<I: IntoIterator<Item = Peer>>(elders: I, prefix: Prefix) -> Self;

    fn peers(&'_ self) -> Box<dyn Iterator<Item = Peer> + '_>;

    /// Returns the index of the elder with `name` in this set of elders.
    /// This is useful for BLS signatures where the signature share needs to be mapped to a
    /// "field element" which is typically a numeric index.
    fn position(&self, name: &XorName) -> Option<usize>;
}

impl ElderCandidatesUtils for ElderCandidates {
    /// Creates a new `ElderCandidates` with the given members and prefix.
    fn new<I>(elders: I, prefix: Prefix) -> Self
    where
        I: IntoIterator<Item = Peer>,
    {
        Self {
            elders: elders
                .into_iter()
                .map(|peer| (*peer.name(), *peer.addr()))
                .collect(),
            prefix,
        }
    }

    fn peers(&'_ self) -> Box<dyn Iterator<Item = Peer> + '_> {
        // The `reachable` flag of Peer is defaulted to `false` during the construction.
        // As the SectionAuthorityProvider only holds the list of alive elders, it shall be safe
        // to set the flag as true here during the mapping.
        Box::new(self.elders.iter().map(|(name, addr)| {
            let mut peer = Peer::new(*name, *addr);
            peer.set_reachable(true);
            peer
        }))
    }

    /// Returns the index of the elder with `name` in this set of elders.
    /// This is useful for BLS signatures where the signature share needs to be mapped to a
    /// "field element" which is typically a numeric index.
    fn position(&self, name: &XorName) -> Option<usize> {
        self.elders.keys().position(|other_name| other_name == name)
    }
}

/// A new `SectionAuthorityProvider` is created whenever the elders change,
/// due to an elder being added or removed, or the section splitting or merging.
pub trait SectionAuthorityProviderUtils {
    /// Creates a new `SectionAuthorityProvider` with the given members, prefix and public keyset.
    fn new<I: IntoIterator<Item = Peer>>(
        elders: I,
        prefix: Prefix,
        pk_set: ReplicaPublicKeySet,
    ) -> Self;

    /// Creates a new `SectionAuthorityProvider` from ElderCandidates and public keyset.
    fn from_elder_candidates(
        elder_candidates: ElderCandidates,
        pk_set: ReplicaPublicKeySet,
    ) -> SectionAuthorityProvider;

    /// Returns `ElderCandidates`, which doesn't have key related infos.
    fn elder_candidates(&self) -> ElderCandidates;

    /// Returns an iterator to the list of peers.
    fn peers(&'_ self) -> Box<dyn Iterator<Item = Peer> + '_>;

    /// Returns the number of elders in the section.
    fn elder_count(&self) -> usize;

    /// Returns a map of name to socket_addr.
    fn contains_elder(&self, name: &XorName) -> bool;

    /// Returns a socket_addr of an elder.
    fn get_addr(&self, name: &XorName) -> Option<SocketAddr>;

    /// Returns the set of elder names.
    fn names(&self) -> BTreeSet<XorName>;

    /// Returns a map of name to socket_addr.
    fn elders(&self) -> BTreeMap<XorName, SocketAddr>;

    /// Returns the list of socket addresses.
    fn addresses(&self) -> Vec<SocketAddr>;

    /// Returns its prefix.
    fn prefix(&self) -> Prefix;

    /// Key of the section.
    fn section_key(&self) -> PublicKey;
}

impl SectionAuthorityProviderUtils for SectionAuthorityProvider {
    /// Creates a new `SectionAuthorityProvider` with the given members, prefix and public keyset.
    fn new<I>(elders: I, prefix: Prefix, pk_set: ReplicaPublicKeySet) -> Self
    where
        I: IntoIterator<Item = Peer>,
    {
        let elders = elders
            .into_iter()
            .enumerate()
            .map(|(index, peer)| (*peer.name(), (pk_set.public_key_share(index), *peer.addr())))
            .collect();

        Self {
            prefix,
            section_key: pk_set.public_key(),
            elders,
        }
    }

    /// Creates a new `SectionAuthorityProvider` from ElderCandidates and public keyset.
    fn from_elder_candidates(
        elder_candidates: ElderCandidates,
        pk_set: ReplicaPublicKeySet,
    ) -> SectionAuthorityProvider {
        let elders = elder_candidates
            .elders
            .iter()
            .enumerate()
            .map(|(index, (name, addr))| (*name, (pk_set.public_key_share(index), *addr)))
            .collect();
        SectionAuthorityProvider {
            prefix: elder_candidates.prefix,
            section_key: pk_set.public_key(),
            elders,
        }
    }

    /// Returns `ElderCandidates`, which doesn't have key related infos.
    fn elder_candidates(&self) -> ElderCandidates {
        ElderCandidates {
            elders: self.elders(),
            prefix: self.prefix,
        }
    }

    fn peers(&'_ self) -> Box<dyn Iterator<Item = Peer> + '_> {
        // The `reachable` flag of Peer is defaulted to `false` during the construction.
        // As the SectionAuthorityProvider only holds the list of alive elders, it shall be safe
        // to set the flag as true here during the mapping.
        Box::new(self.elders.iter().map(|(name, (_, addr))| {
            let mut peer = Peer::new(*name, *addr);
            peer.set_reachable(true);
            peer
        }))
    }

    /// Returns the number of elders in the section.
    fn elder_count(&self) -> usize {
        self.elders.len()
    }

    /// Returns a map of name to socket_addr.
    fn contains_elder(&self, name: &XorName) -> bool {
        self.elders.contains_key(name)
    }

    /// Returns a socket_addr of an elder.
    fn get_addr(&self, name: &XorName) -> Option<SocketAddr> {
        self.elders.get(name).map(|(_, addr)| *addr)
    }

    /// Returns the set of elder names.
    fn names(&self) -> BTreeSet<XorName> {
        self.elders.keys().copied().collect()
    }

    /// Returns a map of name to socket_addr.
    fn elders(&self) -> BTreeMap<XorName, SocketAddr> {
        self.elders
            .iter()
            .map(|(name, (_, addr))| (*name, *addr))
            .collect()
    }

    fn addresses(&self) -> Vec<SocketAddr> {
        self.elders.values().map(|(_, addr)| *addr).collect()
    }

    fn prefix(&self) -> Prefix {
        self.prefix
    }

    /// Key of the section.
    fn section_key(&self) -> PublicKey {
        self.section_key
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use crate::{crypto, node::Node, supermajority, MIN_ADULT_AGE, MIN_AGE};
    use itertools::Itertools;
    use std::{cell::Cell, net::SocketAddr};
    use xor_name::Prefix;

    // Generate unique SocketAddr for testing purposes
    pub(crate) fn gen_addr() -> SocketAddr {
        thread_local! {
            static NEXT_PORT: Cell<u16> = Cell::new(1000);
        }

        let port = NEXT_PORT.with(|cell| cell.replace(cell.get().wrapping_add(1)));

        ([192, 0, 2, 0], port).into()
    }

    // Create `count` Nodes sorted by their names.
    // The `age_diff` flag is used to trigger nodes being generated with different age pattern.
    // The test of `handle_agreement_on_online_of_elder_candidate` requires most nodes to be with
    // age of MIN_AGE + 2 and one node with age of MIN_ADULT_AGE.
    pub(crate) fn gen_sorted_nodes(prefix: &Prefix, count: usize, age_diff: bool) -> Vec<Node> {
        (0..count)
            .map(|index| {
                let age = if age_diff && index < count - 1 {
                    MIN_AGE + 2
                } else {
                    MIN_ADULT_AGE
                };
                Node::new(
                    crypto::gen_keypair(&prefix.range_inclusive(), age),
                    gen_addr(),
                )
            })
            .sorted_by_key(|node| node.name())
            .collect()
    }

    // Generate random `SectionAuthorityProvider` for testing purposes.
    pub(crate) fn gen_section_authority_provider(
        prefix: Prefix,
        count: usize,
    ) -> (SectionAuthorityProvider, Vec<Node>, bls::SecretKeySet) {
        let nodes = gen_sorted_nodes(&prefix, count, false);
        let elders = nodes
            .iter()
            .map(Node::peer)
            .map(|mut peer| {
                peer.set_reachable(true);
                (*peer.name(), *peer.addr())
            })
            .collect();

        let threshold = supermajority(count) - 1;
        let secret_key_set = bls::SecretKeySet::random(threshold, &mut rand::thread_rng());
        let section_auth = SectionAuthorityProvider::from_elder_candidates(
            ElderCandidates { elders, prefix },
            secret_key_set.public_keys(),
        );

        (section_auth, nodes, secret_key_set)
    }
}
