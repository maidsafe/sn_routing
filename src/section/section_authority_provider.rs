// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{peer::Peer, Prefix, XorName};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Borrow,
    collections::BTreeMap,
    fmt::{self, Debug, Display, Formatter},
};

/// The information about all elders of a section at one point in time. Each elder is always a
/// member of exactly one current section, but a new `SectionAuthorityProvider` is created whenever the elders
/// change, due to an elder being added or removed, or the section splitting or merging.
#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Serialize, Deserialize)]
pub struct SectionAuthorityProvider {
    /// The section's complete set of elders as a map from their name to a `Peer`.
    pub elders: BTreeMap<XorName, Peer>,
    /// The section prefix. It matches all the members' names.
    pub prefix: Prefix,
}

impl SectionAuthorityProvider {
    /// Creates a new `SectionAuthorityProvider` with the given members, prefix and version.
    pub fn new<I>(elders: I, prefix: Prefix) -> Self
    where
        I: IntoIterator<Item = Peer>,
    {
        Self {
            elders: elders
                .into_iter()
                .map(|peer| (*peer.name(), peer))
                .collect(),
            prefix,
        }
    }

    pub(crate) fn peers(
        &self,
    ) -> impl Iterator<Item = &Peer> + DoubleEndedIterator + ExactSizeIterator + Clone {
        self.elders.values()
    }

    /// Returns the index of the elder with `name` in this set of elders.
    /// This is useful for BLS signatures where the signature share needs to be mapped to a
    /// "field element" which is typically a numeric index.
    pub(crate) fn position(&self, name: &XorName) -> Option<usize> {
        self.elders.keys().position(|other_name| other_name == name)
    }
}

impl Borrow<Prefix> for SectionAuthorityProvider {
    fn borrow(&self) -> &Prefix {
        &self.prefix
    }
}

impl Debug for SectionAuthorityProvider {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "SectionAuthorityProvider {{ prefix: ({:b}), elders: {{{:?}}} }}",
            self.prefix,
            self.elders.values().format(", "),
        )
    }
}

impl Display for SectionAuthorityProvider {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{{{}}}/({:b})",
            self.elders.keys().format(", "),
            self.prefix,
        )
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::SectionAuthorityProvider;
    use crate::{crypto, node::Node, MIN_ADULT_AGE, MIN_AGE};
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
    ) -> (SectionAuthorityProvider, Vec<Node>) {
        let nodes = gen_sorted_nodes(&prefix, count, false);
        let elders = nodes
            .iter()
            .map(Node::peer)
            .map(|mut peer| {
                peer.set_reachable(true);
                (*peer.name(), peer)
            })
            .collect();
        let section_auth = SectionAuthorityProvider { elders, prefix };

        (section_auth, nodes)
    }
}
