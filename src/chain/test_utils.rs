// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Chain, EldersInfo};
use crate::{Prefix, XorName};
use std::collections::BTreeMap;
use std::iter;

/// Verifies that the given chains satisfy the network invariant.
#[allow(unused)]
pub fn verify_chain_invariant<'a, T>(chains: T, min_section_size: usize)
where
    T: IntoIterator<Item = &'a Chain>,
{
    let mut sections: BTreeMap<Prefix<XorName>, (XorName, EldersInfo)> = BTreeMap::new();

    for chain in chains {
        for prefix in iter::once(chain.our_info().prefix())
            .chain(chain.neighbour_infos().map(EldersInfo::prefix))
        {
            let section_content = chain
                .get_section(prefix)
                .expect("section for prefix")
                .clone();
            let our_name = chain.our_id().name();
            if let Some(&(ref src, ref info)) = sections.get(prefix) {
                assert_eq!(
                    section_content.members(),
                    info.members(),
                    "Section with prefix {:?} doesn't agree between nodes {:?} and {:?}\n\
                     {:?}: {:?},\n{:?}: {:?}",
                    prefix,
                    our_name,
                    src,
                    our_name,
                    section_content.members(),
                    src,
                    info.members()
                );
                assert_eq!(
                    section_content.version(),
                    info.version(),
                    "Section with prefix {:?} has a different version in nodes {:?} and {:?}\n\
                     {:?}: {:?}, {:?}: {:?}",
                    prefix,
                    our_name,
                    src,
                    our_name,
                    section_content.version(),
                    src,
                    info.version()
                );
                continue;
            }
            let _ = sections.insert(*prefix, (*our_name, section_content));
        }
    }

    // check that prefixes are disjoint
    for prefix1 in sections.keys() {
        for prefix2 in sections.keys() {
            if prefix1 == prefix2 {
                continue;
            }
            if prefix1.is_compatible(prefix2) {
                panic!(
                    "Section prefixes should be disjoint, but these are not:\n\
                     Section {:?}, according to node {:?}: {:?}\n\
                     Section {:?}, according to node {:?}: {:?}",
                    prefix1,
                    sections[prefix1].0,
                    sections[prefix1].1,
                    prefix2,
                    sections[prefix2].0,
                    sections[prefix2].1
                );
            }
        }
    }

    // check that each section contains names agreeing with its prefix
    for (prefix, &(_, ref info)) in &sections {
        for name in info.members() {
            if !prefix.matches(name.name()) {
                panic!(
                    "Section members should match the prefix, but {:?} \
                     does not match {:?}",
                    name.name(),
                    prefix
                );
            }
        }
    }

    // check that sections cover the whole namespace
    assert!(Prefix::default().is_covered_by(sections.keys()));
}
