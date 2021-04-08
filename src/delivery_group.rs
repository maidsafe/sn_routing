// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Utilities for sn_routing messages through the network.

use crate::{
    error::{Error, Result},
    network::Network,
    peer::Peer,
    section::Section,
    ELDER_SIZE,
};
use itertools::Itertools;
use sn_messaging::DstLocation;
use std::{cmp, iter};
use xor_name::XorName;

/// Returns a set of nodes to which a message for the given `DstLocation` could be sent
/// onwards, sorted by priority, along with the number of targets the message should be sent to.
/// If the total number of targets returned is larger than this number, the spare targets can
/// be used if the message can't be delivered to some of the initial ones.
///
/// * If the destination is a `DstLocation::Section` OR `DstLocation::EndUser`:
///     - if our section is the closest on the network (i.e. our section's prefix is a prefix of
///       the destination), returns all other members of our section; otherwise
///     - returns the `N/3` closest members to the target
///
/// * If the destination is an individual node:
///     - if our name *is* the destination, returns an empty set; otherwise
///     - if the destination name is an entry in the routing table, returns it; otherwise
///     - returns the `N/3` closest members of the RT to the target
pub(crate) fn delivery_targets(
    dst: &DstLocation,
    our_name: &XorName,
    section: &Section,
    network: &Network,
) -> Result<(Vec<Peer>, usize)> {
    if !section.is_elder(our_name) {
        // We are not Elder - return all the elders of our section, so the message can be properly
        // relayed through them.
        let targets: Vec<_> = section.elders_info().peers().copied().collect();
        let dg_size = targets.len();
        return Ok((targets, dg_size));
    }

    let (best_section, dg_size) = match dst {
        DstLocation::Section(target_name) => {
            section_candidates(target_name, our_name, section, network)?
        }
        DstLocation::EndUser(user) => {
            let target_name = user.name();
            section_candidates(&target_name, our_name, section, network)?
        }
        DstLocation::Node(target_name) => {
            if target_name == our_name {
                return Ok((Vec::new(), 0));
            }
            if let Some(node) = get_peer(target_name, section, network) {
                return Ok((vec![*node], 1));
            }

            candidates(target_name, our_name, section, network)?
        }
        DstLocation::Direct => return Err(Error::CannotRoute),
    };

    Ok((best_section, dg_size))
}

fn section_candidates(
    target_name: &XorName,
    our_name: &XorName,
    section: &Section,
    network: &Network,
) -> Result<(Vec<Peer>, usize)> {
    // Find closest section to `target_name` out of the ones we know (including our own)
    let info = iter::once(section.elders_info())
        .chain(network.all())
        .min_by(|lhs, rhs| lhs.prefix.cmp_distance(&rhs.prefix, target_name))
        .unwrap_or_else(|| section.elders_info());

    if info.prefix == *section.prefix() {
        // Exclude our name since we don't need to send to ourself
        let section: Vec<_> = info
            .peers()
            .filter(|node| node.name() != our_name)
            .copied()
            .collect();
        let dg_size = section.len();
        return Ok((section, dg_size));
    }

    candidates(target_name, our_name, section, network)
}

// Obtain the delivery group candidates for this target
fn candidates(
    target_name: &XorName,
    our_name: &XorName,
    section: &Section,
    network: &Network,
) -> Result<(Vec<Peer>, usize)> {
    // All sections we know (including our own), sorted by distance to `target_name`.
    let sections = iter::once(section.elders_info())
        .chain(network.all())
        .sorted_by(|lhs, rhs| lhs.prefix.cmp_distance(&rhs.prefix, target_name))
        .map(|info| (&info.prefix, info.elders.len(), info.elders.values()));

    let mut dg_size = ELDER_SIZE;
    let mut nodes_to_send = Vec::new();
    for (idx, (prefix, len, connected)) in sections.enumerate() {
        nodes_to_send.extend(connected.cloned());
        // If we don't have enough contacts send to as many as possible
        // up to majority of Elders
        dg_size = cmp::min(len, dg_size);
        if len < ELDER_SIZE {
            warn!(
                "Delivery group only {:?} when it should be {:?}",
                len, ELDER_SIZE
            )
        }

        if prefix == section.prefix() {
            // Send to all connected targets so they can forward the message
            nodes_to_send.retain(|node| node.name() != our_name);
            dg_size = nodes_to_send.len();
            break;
        }
        if idx == 0 && nodes_to_send.len() >= dg_size {
            // can deliver to enough of the closest section
            break;
        }
    }
    nodes_to_send.sort_by(|lhs, rhs| target_name.cmp_distance(lhs.name(), rhs.name()));

    if dg_size > 0 && nodes_to_send.len() >= dg_size {
        Ok((nodes_to_send, dg_size))
    } else {
        Err(Error::CannotRoute)
    }
}

// Returns a `Peer` for a known node.
fn get_peer<'a>(name: &XorName, section: &'a Section, network: &'a Network) -> Option<&'a Peer> {
    section
        .members()
        .get(name)
        .map(|info| &info.peer)
        .or_else(|| network.get_elder(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agreement::test_utils::proven,
        crypto,
        section::{
            test_utils::{gen_addr, gen_elders_info},
            EldersInfo, MemberInfo, SectionChain, MIN_ADULT_AGE,
        },
    };
    use anyhow::{Context, Result};
    use rand::seq::IteratorRandom;
    use xor_name::Prefix;

    #[test]
    fn delivery_targets_elder_to_our_elder() -> Result<()> {
        let (our_name, section, network, _) = setup_elder()?;

        let dst_name = *section
            .elders_info()
            .elders
            .keys()
            .filter(|&&name| name != our_name)
            .choose(&mut rand::thread_rng())
            .context("too few elders")?;

        let dst = DstLocation::Node(dst_name);
        let (recipients, dg_size) = delivery_targets(&dst, &our_name, &section, &network)?;

        // Send only to the dst node.
        assert_eq!(dg_size, 1);
        assert_eq!(recipients[0].name(), &dst_name);

        Ok(())
    }

    #[test]
    fn delivery_targets_elder_to_our_adult() -> Result<()> {
        let (our_name, mut section, network, sk) = setup_elder()?;

        let name = crypto::gen_name_with_age(MIN_ADULT_AGE);
        let dst_name = section.prefix().substituted_in(name);
        let peer = Peer::new(dst_name, gen_addr());
        let member_info = MemberInfo::joined(peer);
        let member_info = proven(&sk, member_info)?;
        assert!(section.update_member(member_info));

        let dst = DstLocation::Node(dst_name);
        let (recipients, dg_size) = delivery_targets(&dst, &our_name, &section, &network)?;

        // Send only to the dst node.
        assert_eq!(dg_size, 1);
        assert_eq!(recipients[0].name(), &dst_name);

        Ok(())
    }

    #[test]
    fn delivery_targets_elder_to_our_section() -> Result<()> {
        let (our_name, section, network, _) = setup_elder()?;

        let dst_name = section.prefix().substituted_in(rand::random());
        let dst = DstLocation::Section(dst_name);
        let (recipients, dg_size) = delivery_targets(&dst, &our_name, &section, &network)?;

        // Send to all our elders except us.
        let expected_recipients = section
            .elders_info()
            .peers()
            .filter(|peer| peer.name() != &our_name);
        assert_eq!(dg_size, expected_recipients.clone().count());
        itertools::assert_equal(&recipients, expected_recipients);

        Ok(())
    }

    #[test]
    fn delivery_targets_elder_to_known_remote_peer() -> Result<()> {
        let (our_name, section, network, _) = setup_elder()?;

        let elders_info1 = network
            .get(&Prefix::default().pushed(true))
            .context("unknown section")?;

        let dst_name = choose_elder_name(elders_info1)?;
        let dst = DstLocation::Node(dst_name);
        let (recipients, dg_size) = delivery_targets(&dst, &our_name, &section, &network)?;

        // Send only to the dst node.
        assert_eq!(dg_size, 1);
        assert_eq!(recipients[0].name(), &dst_name);

        Ok(())
    }

    #[test]
    fn delivery_targets_elder_to_unknown_remote_peer() -> Result<()> {
        let (our_name, section, network, _) = setup_elder()?;

        let elders_info1 = network
            .get(&Prefix::default().pushed(true))
            .context("unknown section")?;

        let dst_name = elders_info1.prefix.substituted_in(rand::random());
        let dst = DstLocation::Node(dst_name);
        let (recipients, dg_size) = delivery_targets(&dst, &our_name, &section, &network)?;

        // Send to all elders in the dst section
        let expected_recipients = elders_info1
            .peers()
            .sorted_by(|lhs, rhs| dst_name.cmp_distance(lhs.name(), rhs.name()));
        assert_eq!(dg_size, elders_info1.elders.len());
        itertools::assert_equal(&recipients, expected_recipients);

        Ok(())
    }

    #[test]
    fn delivery_targets_elder_to_remote_section() -> Result<()> {
        let (our_name, section, network, _) = setup_elder()?;

        let elders_info1 = network
            .get(&Prefix::default().pushed(true))
            .context("unknown section")?;

        let dst_name = elders_info1.prefix.substituted_in(rand::random());
        let dst = DstLocation::Section(dst_name);
        let (recipients, dg_size) = delivery_targets(&dst, &our_name, &section, &network)?;

        // Send to all elders in the dst section
        let expected_recipients = elders_info1
            .peers()
            .sorted_by(|lhs, rhs| dst_name.cmp_distance(lhs.name(), rhs.name()));
        assert_eq!(dg_size, elders_info1.elders.len());
        itertools::assert_equal(&recipients, expected_recipients);

        Ok(())
    }

    #[test]
    fn delivery_targets_adult_to_our_elder() -> Result<()> {
        let (our_name, section, network) = setup_adult()?;

        let dst_name = choose_elder_name(section.elders_info())?;
        let dst = DstLocation::Node(dst_name);
        let (recipients, dg_size) = delivery_targets(&dst, &our_name, &section, &network)?;

        // Send to all elders
        assert_eq!(dg_size, section.elders_info().elders.len());
        itertools::assert_equal(&recipients, section.elders_info().peers());

        Ok(())
    }

    #[test]
    fn delivery_targets_adult_to_our_adult() -> Result<()> {
        let (our_name, section, network) = setup_adult()?;

        let dst_name = section.prefix().substituted_in(rand::random());
        let dst = DstLocation::Node(dst_name);
        let (recipients, dg_size) = delivery_targets(&dst, &our_name, &section, &network)?;

        // Send to all elders
        assert_eq!(dg_size, section.elders_info().elders.len());
        itertools::assert_equal(&recipients, section.elders_info().peers());

        Ok(())
    }

    #[test]
    fn delivery_targets_adult_to_our_section() -> Result<()> {
        let (our_name, section, network) = setup_adult()?;

        let dst_name = section.prefix().substituted_in(rand::random());
        let dst = DstLocation::Section(dst_name);
        let (recipients, dg_size) = delivery_targets(&dst, &our_name, &section, &network)?;

        // Send to all elders
        assert_eq!(dg_size, section.elders_info().elders.len());
        itertools::assert_equal(&recipients, section.elders_info().peers());

        Ok(())
    }

    #[test]
    fn delivery_targets_adult_to_remote_peer() -> Result<()> {
        let (our_name, section, network) = setup_adult()?;

        let dst_name = Prefix::default()
            .pushed(true)
            .substituted_in(rand::random());
        let dst = DstLocation::Node(dst_name);
        let (recipients, dg_size) = delivery_targets(&dst, &our_name, &section, &network)?;

        // Send to all elders
        assert_eq!(dg_size, section.elders_info().elders.len());
        itertools::assert_equal(&recipients, section.elders_info().peers());

        Ok(())
    }

    #[test]
    fn delivery_targets_adult_to_remote_section() -> Result<()> {
        let (our_name, section, network) = setup_adult()?;

        let dst_name = Prefix::default()
            .pushed(true)
            .substituted_in(rand::random());
        let dst = DstLocation::Section(dst_name);
        let (recipients, dg_size) = delivery_targets(&dst, &our_name, &section, &network)?;

        // Send to all elders
        assert_eq!(dg_size, section.elders_info().elders.len());
        itertools::assert_equal(&recipients, section.elders_info().peers());

        Ok(())
    }

    fn setup_elder() -> Result<(XorName, Section, Network, bls::SecretKey)> {
        let prefix0 = Prefix::default().pushed(false);
        let prefix1 = Prefix::default().pushed(true);

        let sk = bls::SecretKey::random();
        let pk = sk.public_key();
        let chain = SectionChain::new(pk);

        let (elders_info0, _) = gen_elders_info(prefix0, ELDER_SIZE);
        let elders0: Vec<_> = elders_info0.peers().copied().collect();
        let elders_info0 = proven(&sk, elders_info0)?;

        let mut section = Section::new(pk, chain, elders_info0)?;

        for peer in elders0 {
            let member_info = MemberInfo::joined(peer);
            let member_info = proven(&sk, member_info)?;
            assert!(section.update_member(member_info));
        }

        let mut network = Network::new();

        let (elders_info1, _) = gen_elders_info(prefix1, ELDER_SIZE);
        let elders_info1 = proven(&sk, elders_info1)?;
        assert!(network.update_section(elders_info1, None, section.chain()));

        let our_name = choose_elder_name(section.elders_info())?;

        Ok((our_name, section, network, sk))
    }

    fn setup_adult() -> Result<(XorName, Section, Network)> {
        let prefix0 = Prefix::default().pushed(false);

        let sk = bls::SecretKey::random();
        let pk = sk.public_key();
        let chain = SectionChain::new(pk);

        let (elders_info, _) = gen_elders_info(prefix0, ELDER_SIZE);
        let elders_info = proven(&sk, elders_info)?;
        let section = Section::new(pk, chain, elders_info)?;

        let network = Network::new();
        let our_name = section.prefix().substituted_in(rand::random());

        Ok((our_name, section, network))
    }

    fn choose_elder_name(elders_info: &EldersInfo) -> Result<XorName> {
        elders_info
            .elders
            .keys()
            .choose(&mut rand::thread_rng())
            .copied()
            .context("no elders")
    }
}
