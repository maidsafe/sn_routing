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
/// member of exactly one current section, but a new `EldersInfo` is created whenever the elders
/// change, due to an elder being added or removed, or the section splitting or merging.
#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Serialize, Deserialize)]
pub struct EldersInfo {
    /// The section's complete set of elders as a map from their name to a `Peer`.
    pub elders: BTreeMap<XorName, Peer>,
    /// The section prefix. It matches all the members' names.
    pub prefix: Prefix,
}

impl EldersInfo {
    /// Creates a new `EldersInfo` with the given members, prefix and version.
    pub fn new(elders: BTreeMap<XorName, Peer>, prefix: Prefix) -> Self {
        Self { elders, prefix }
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

impl Borrow<Prefix> for EldersInfo {
    fn borrow(&self) -> &Prefix {
        &self.prefix
    }
}

impl Debug for EldersInfo {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "EldersInfo {{ prefix: ({:b}), elders: {{{:?}}} }}",
            self.prefix,
            self.elders.values().format(", "),
        )
    }
}

impl Display for EldersInfo {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{{{}}}/({:b})",
            self.elders.keys().format(", "),
            self.prefix,
        )
    }
}

/// Returns the number of vote for a majority of this section such that:
/// majority_count * MAJORITY_DENOMINATOR > elder_size * MAJORITY_NUMERATOR
#[inline]
pub const fn majority_count(elder_size: usize) -> usize {
    use crate::{MAJORITY_DENOMINATOR, MAJORITY_NUMERATOR};
    1 + (elder_size * MAJORITY_NUMERATOR) / MAJORITY_DENOMINATOR
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::EldersInfo;
    use crate::{
        crypto::{self, Keypair},
        peer::Peer,
        MIN_AGE,
    };
    use itertools::Itertools;
    use rand::rngs::OsRng;
    use std::{cell::Cell, net::SocketAddr};
    use xor_name::Prefix;

    // Generate unique SocketAddr for testing purposes
    pub fn gen_addr() -> SocketAddr {
        thread_local! {
            static NEXT_PORT: Cell<u16> = Cell::new(1000);
        }

        let port = NEXT_PORT.with(|cell| cell.replace(cell.get().wrapping_add(1)));

        ([192, 0, 2, 0], port).into()
    }

    // Create ELDER_SIZE Keypairs sorted by their names.
    pub fn gen_sorted_keypairs(count: usize) -> Vec<Keypair> {
        let mut rng = OsRng;
        (0..count)
            .map(|_| Keypair::generate(&mut rng))
            .sorted_by_key(|keypair| crypto::name(&keypair.public))
            .collect()
    }

    // Generate random `EldersInfo` for testing purposes.
    pub fn gen_elders_info(prefix: Prefix, count: usize) -> (EldersInfo, Vec<Keypair>) {
        let keypairs = gen_sorted_keypairs(count);
        let elders = keypairs
            .iter()
            .map(|keypair| Peer::new(crypto::name(&keypair.public), gen_addr(), MIN_AGE + 1))
            .map(|peer| (*peer.name(), peer))
            .collect();
        let elders_info = EldersInfo { elders, prefix };

        (elders_info, keypairs)
    }
}
