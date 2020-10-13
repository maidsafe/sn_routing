// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(test)]
use crate::{crypto::Keypair, rng::MainRng};
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

// Generate random `EldersInfo` for testing purposes.
#[cfg(test)]
pub(crate) fn gen_elders_info(
    rng: &mut MainRng,
    prefix: Prefix,
    count: usize,
) -> (EldersInfo, Vec<Keypair>) {
    use crate::{crypto::name, MIN_AGE};
    use rand::Rng;
    use std::net::SocketAddr;

    fn gen_socket_addr(rng: &mut MainRng) -> SocketAddr {
        let ip: [u8; 4] = rng.gen();
        let port: u16 = rng.gen();
        SocketAddr::from((ip, port))
    }

    let mut keypairs: Vec<_> = (0..count).map(|_| Keypair::generate(rng)).collect();

    // Clippy false positive - https://github.com/rust-lang/rust-clippy/issues/5754
    // (note the issue is closed, but it probably hasn't been merged into stable yet)
    #[allow(clippy::unnecessary_sort_by)]
    keypairs.sort_by(|lhs, rhs| name(&lhs.public).cmp(&name(&rhs.public)));

    let elders = keypairs
        .iter()
        .map(|keypair| {
            let addr = gen_socket_addr(rng);
            let peer = Peer::new(name(&keypair.public), addr, MIN_AGE);
            (*peer.name(), peer)
        })
        .collect();

    (EldersInfo::new(elders, prefix), keypairs)
}
