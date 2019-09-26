// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Chain, EldersInfo, PrefixChange};
use crate::{Prefix, XorName};
use std::collections::{BTreeMap, BTreeSet};
use std::iter;

fn verify_single_chain(chain: &Chain, min_section_size: usize) {
    assert!(
        chain.our_info().prefix().matches(chain.our_id().name()),
        "Our prefix doesn't match our name: {:?}, {:?}",
        chain.our_info().prefix(),
        chain.our_id().name()
    );

    assert_eq!(
        chain.prefix_change(),
        PrefixChange::None,
        "{} has an unexpected prefix change: {:?}",
        chain.our_id(),
        chain.prefix_change()
    );

    if !chain.our_info().prefix().is_empty() {
        assert!(
            chain.our_info().members().len() >= min_section_size,
            "Our section {:?} is below the minimum size!",
            chain.our_info().prefix()
        );
    }

    if let Some(name) = chain
        .our_info()
        .members()
        .iter()
        .find(|name| !chain.our_info().prefix().matches(name.name()))
    {
        panic!(
            "A name in our section doesn't match its prefix! {:?}, {:?}",
            name,
            chain.our_info().prefix()
        );
    }

    if let Some(info) = chain
        .neighbour_infos()
        .find(|info| info.prefix().is_compatible(chain.our_info().prefix()))
    {
        panic!(
            "Our prefix is compatible with one of the neighbour prefixes:\
             us: {:?} / neighbour: {:?}",
            chain.our_info().prefix(),
            info.prefix()
        );
    }

    if let Some(info) = chain
        .neighbour_infos()
        .find(|info| info.members().len() < min_section_size)
    {
        panic!(
            "A section is below the minimum size: size({:?}) = {}; For ({:?}: {:?})",
            info.prefix(),
            info.members().len(),
            chain.our_id(),
            chain.our_info().prefix(),
        );
    }

    for info in chain.neighbour_infos() {
        if let Some(name) = info
            .members()
            .iter()
            .find(|name| !info.prefix().matches(name.name()))
        {
            panic!(
                "A name in a section doesn't match its prefix! {:?}, {:?}",
                name,
                info.prefix()
            );
        }
    }

    let all_are_neighbours = chain
        .neighbour_infos()
        .all(|x| chain.our_info().prefix().is_neighbour(x.prefix()));
    let all_neighbours_covered = {
        let prefixes: BTreeSet<_> = chain.neighbour_infos().map(|info| *info.prefix()).collect();
        (0..chain.our_info().prefix().bit_count()).all(|i| {
            chain
                .our_info()
                .prefix()
                .with_flipped_bit(i)
                .is_covered_by(&prefixes)
        })
    };
    if !all_are_neighbours {
        panic!(
            "Some sections in the chain aren't neighbours of our section: {:?}",
            iter::once(chain.our_info().prefix())
                .chain(chain.neighbour_infos().map(EldersInfo::prefix))
                .collect::<Vec<_>>()
        );
    }
    if !all_neighbours_covered {
        panic!(
            "Some neighbours aren't fully covered by the chain: {:?}",
            iter::once(chain.our_info().prefix())
                .chain(chain.neighbour_infos().map(EldersInfo::prefix))
                .collect::<Vec<_>>()
        );
    }
}

/// Verifies that the given chains satisfy the network invariant.
#[allow(unused)]
pub fn verify_chain_invariant<'a, T>(chains: T, min_section_size: usize)
where
    T: IntoIterator<Item = &'a Chain>,
{
    let mut sections: BTreeMap<Prefix<XorName>, (XorName, EldersInfo)> = BTreeMap::new();

    for chain in chains {
        verify_single_chain(chain, min_section_size);
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
