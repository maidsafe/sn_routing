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
    network::NetworkUtils,
    peer::PeerUtils,
    section::{SectionAuthorityProviderUtils, SectionPeersUtils, SectionUtils},
    supermajority, ELDER_SIZE,
};
use itertools::Itertools;
use sn_messaging::{
    node::{Network, Peer, Section},
    DstLocation,
};
use std::{cmp, iter};
use xor_name::XorName;

/// Returns a set of nodes and their section PublicKey to which a message for the given
/// `DstLocation` could be sent onwards, sorted by priority, along with the number of targets the
/// message should be sent to. If the total number of targets returned is larger than this number,
/// the spare targets can be used if the message can't be delivered to some of the initial ones.
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
        let targets: Vec<_> = section.authority_provider().peers().collect();
        let dg_size = targets.len();
        return Ok((targets, dg_size));
    }

    let (best_section, dg_size) = match dst {
        DstLocation::Section(target_name) => {
            section_candidates(target_name, our_name, section, network)?
        }
        DstLocation::EndUser(user) => {
            section_candidates(&user.xorname, our_name, section, network)?
        }
        DstLocation::Node(target_name) => {
            if target_name == our_name {
                return Ok((Vec::new(), 0));
            }
            if let Some(node) = get_peer(target_name, section, network) {
                return Ok((vec![node], 1));
            }

            candidates(target_name, our_name, section, network)?
        }
        DstLocation::DirectAndUnrouted => return Err(Error::CannotRoute),
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
    let info = iter::once(section.authority_provider())
        .chain(network.all())
        .min_by(|lhs, rhs| lhs.prefix.cmp_distance(&rhs.prefix, target_name))
        .unwrap_or_else(|| section.authority_provider());

    if info.prefix == *section.prefix() {
        // Exclude our name since we don't need to send to ourself
        let chosen_section: Vec<_> = info
            .peers()
            .filter(|node| node.name() != our_name)
            .collect();
        let dg_size = chosen_section.len();
        return Ok((chosen_section, dg_size));
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
    let sections = iter::once(section.authority_provider())
        .chain(network.all())
        .sorted_by(|lhs, rhs| lhs.prefix.cmp_distance(&rhs.prefix, target_name))
        .map(|info| (&info.prefix, info.elder_count(), info.peers()));

    // gives at least 1 honest target among recipients.
    let min_dg_size = 1 + ELDER_SIZE - supermajority(ELDER_SIZE);
    let mut dg_size = min_dg_size;
    let mut candidates = Vec::new();
    for (idx, (prefix, len, connected)) in sections.enumerate() {
        candidates.extend(connected);
        if prefix.matches(target_name) {
            // If we are last hop before final dst, send to all candidates.
            dg_size = len;
        } else {
            // If we don't have enough contacts send to as many as possible
            // up to dg_size of Elders
            dg_size = cmp::min(len, dg_size);
        }
        if len < min_dg_size {
            warn!(
                "Delivery group only {:?} when it should be {:?}",
                len, min_dg_size
            )
        }

        if prefix == section.prefix() {
            // Send to all connected targets so they can forward the message
            candidates.retain(|node| node.name() != our_name);
            dg_size = candidates.len();
            break;
        }
        if idx == 0 && candidates.len() >= dg_size {
            // can deliver to enough of the closest section
            break;
        }
    }
    candidates.sort_by(|lhs, rhs| target_name.cmp_distance(lhs.name(), rhs.name()));

    if dg_size > 0 && candidates.len() >= dg_size {
        Ok((candidates, dg_size))
    } else {
        Err(Error::CannotRoute)
    }
}

// Returns a `Peer` for a known node.
fn get_peer(name: &XorName, section: &Section, network: &Network) -> Option<Peer> {
    section
        .members()
        .get(name)
        .map(|info| info.peer)
        .or_else(|| network.get_elder(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agreement::test_utils::proven,
        crypto,
        section::{
            test_utils::{gen_addr, gen_section_authority_provider},
            MemberInfoUtils, SectionAuthorityProviderUtils, MIN_ADULT_AGE,
        },
    };
    use anyhow::{Context, Result};
    use rand::seq::IteratorRandom;
    use secured_linked_list::SecuredLinkedList;
    use sn_messaging::node::{MemberInfo, SectionAuthorityProvider};
    use xor_name::Prefix;

    #[test]
    fn delivery_targets_elder_to_our_elder() -> Result<()> {
        let (our_name, section, network, _) = setup_elder()?;

        let dst_name = *section
            .authority_provider()
            .names()
            .iter()
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
            .authority_provider()
            .peers()
            .filter(|peer| peer.name() != &our_name);
        assert_eq!(dg_size, expected_recipients.count());

        let expected_recipients = section
            .authority_provider()
            .peers()
            .filter(|peer| peer.name() != &our_name);
        itertools::assert_equal(recipients, expected_recipients);

        Ok(())
    }

    #[test]
    fn delivery_targets_elder_to_known_remote_peer() -> Result<()> {
        let (our_name, section, network, _) = setup_elder()?;

        let section_auth1 = network
            .get(&Prefix::default().pushed(true))
            .context("unknown section")?;

        let dst_name = choose_elder_name(section_auth1)?;
        let dst = DstLocation::Node(dst_name);
        let (recipients, dg_size) = delivery_targets(&dst, &our_name, &section, &network)?;

        // Send only to the dst node.
        assert_eq!(dg_size, 1);
        assert_eq!(recipients[0].name(), &dst_name);

        Ok(())
    }

    #[test]
    fn delivery_targets_elder_to_final_hop_unknown_remote_peer() -> Result<()> {
        let (our_name, section, network, _) = setup_elder()?;

        let section_auth1 = network
            .get(&Prefix::default().pushed(true))
            .context("unknown section")?;

        let dst_name = section_auth1.prefix.substituted_in(rand::random());
        let dst = DstLocation::Node(dst_name);
        let (recipients, dg_size) = delivery_targets(&dst, &our_name, &section, &network)?;

        // Send to all elders in the dst section
        let expected_recipients = section_auth1
            .peers()
            .sorted_by(|lhs, rhs| dst_name.cmp_distance(lhs.name(), rhs.name()));
        assert_eq!(dg_size, section_auth1.elder_count());
        itertools::assert_equal(recipients, expected_recipients);

        Ok(())
    }

    #[test]
    #[ignore = "Need to setup network so that we do not locate final dst, as to trigger correct outcome."]
    fn delivery_targets_elder_to_intermediary_hop_unknown_remote_peer() -> Result<()> {
        let (our_name, section, network, _) = setup_elder()?;

        let elders_info1 = network
            .get(&Prefix::default().pushed(true))
            .context("unknown section")?;

        let dst_name = elders_info1
            .prefix
            .pushed(false)
            .substituted_in(rand::random());
        let dst = DstLocation::Node(dst_name);
        let (recipients, dg_size) = delivery_targets(&dst, &our_name, &section, &network)?;

        // Send to all elders in the dst section
        let expected_recipients = elders_info1
            .peers()
            .sorted_by(|lhs, rhs| dst_name.cmp_distance(lhs.name(), rhs.name()));
        let min_dg_size =
            1 + elders_info1.elder_count() - supermajority(elders_info1.elder_count());
        assert_eq!(dg_size, min_dg_size);
        itertools::assert_equal(recipients, expected_recipients);

        Ok(())
    }

    #[test]
    fn delivery_targets_elder_final_hop_to_remote_section() -> Result<()> {
        let (our_name, section, network, _) = setup_elder()?;

        let section_auth1 = network
            .get(&Prefix::default().pushed(true))
            .context("unknown section")?;

        let dst_name = section_auth1.prefix.substituted_in(rand::random());
        let dst = DstLocation::Section(dst_name);
        let (recipients, dg_size) = delivery_targets(&dst, &our_name, &section, &network)?;

        // Send to all elders in the final dst section
        let expected_recipients = section_auth1
            .peers()
            .sorted_by(|lhs, rhs| dst_name.cmp_distance(lhs.name(), rhs.name()));
        assert_eq!(dg_size, section_auth1.elder_count());
        itertools::assert_equal(recipients, expected_recipients);

        Ok(())
    }

    #[test]
    #[ignore = "Need to setup network so that we do not locate final dst, as to trigger correct outcome."]
    fn delivery_targets_elder_intermediary_hop_to_remote_section() -> Result<()> {
        let (our_name, section, network, _) = setup_elder()?;

        let elders_info1 = network
            .get(&Prefix::default().pushed(true))
            .context("unknown section")?;

        let dst_name = elders_info1
            .prefix
            .pushed(false)
            .substituted_in(rand::random());
        let dst = DstLocation::Section(dst_name);
        let (recipients, dg_size) = delivery_targets(&dst, &our_name, &section, &network)?;

        // Send to a subset of elders in the intermediary dst section
        let min_dg_size =
            1 + elders_info1.elder_count() - supermajority(elders_info1.elder_count());
        let expected_recipients = elders_info1
            .peers()
            .sorted_by(|lhs, rhs| dst_name.cmp_distance(lhs.name(), rhs.name()))
            .take(min_dg_size);

        assert_eq!(dg_size, min_dg_size);
        itertools::assert_equal(recipients, expected_recipients);

        Ok(())
    }

    #[test]
    fn delivery_targets_adult_to_our_elder() -> Result<()> {
        let (our_name, section, network) = setup_adult()?;

        let dst_name = choose_elder_name(section.authority_provider())?;
        let dst = DstLocation::Node(dst_name);
        let (recipients, dg_size) = delivery_targets(&dst, &our_name, &section, &network)?;

        // Send to all elders
        assert_eq!(dg_size, section.authority_provider().elder_count());
        itertools::assert_equal(recipients, section.authority_provider().peers());

        Ok(())
    }

    #[test]
    fn delivery_targets_adult_to_our_adult() -> Result<()> {
        let (our_name, section, network) = setup_adult()?;

        let dst_name = section.prefix().substituted_in(rand::random());
        let dst = DstLocation::Node(dst_name);
        let (recipients, dg_size) = delivery_targets(&dst, &our_name, &section, &network)?;

        // Send to all elders
        assert_eq!(dg_size, section.authority_provider().elder_count());
        itertools::assert_equal(recipients, section.authority_provider().peers());

        Ok(())
    }

    #[test]
    fn delivery_targets_adult_to_our_section() -> Result<()> {
        let (our_name, section, network) = setup_adult()?;

        let dst_name = section.prefix().substituted_in(rand::random());
        let dst = DstLocation::Section(dst_name);
        let (recipients, dg_size) = delivery_targets(&dst, &our_name, &section, &network)?;

        // Send to all elders
        assert_eq!(dg_size, section.authority_provider().elder_count());
        itertools::assert_equal(recipients, section.authority_provider().peers());

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
        assert_eq!(dg_size, section.authority_provider().elder_count());
        itertools::assert_equal(recipients, section.authority_provider().peers());

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
        assert_eq!(dg_size, section.authority_provider().elder_count());
        itertools::assert_equal(recipients, section.authority_provider().peers());

        Ok(())
    }

    fn setup_elder() -> Result<(XorName, Section, Network, bls::SecretKey)> {
        let prefix0 = Prefix::default().pushed(false);
        let prefix1 = Prefix::default().pushed(true);

        let sk = bls::SecretKey::random();
        let pk = sk.public_key();
        let chain = SecuredLinkedList::new(pk);

        let (section_auth0, _, _) = gen_section_authority_provider(prefix0, ELDER_SIZE);
        let elders0: Vec<_> = section_auth0.peers().collect();
        let section_auth0 = proven(&sk, section_auth0)?;

        let mut section = Section::new(pk, chain, section_auth0)?;

        for peer in elders0 {
            let member_info = MemberInfo::joined(peer);
            let member_info = proven(&sk, member_info)?;
            assert!(section.update_member(member_info));
        }

        let mut network = Network::new();

        let (section_auth1, _, _) = gen_section_authority_provider(prefix1, ELDER_SIZE);
        let section_auth1 = proven(&sk, section_auth1)?;
        assert!(network.update_section(section_auth1, None, section.chain()));

        let our_name = choose_elder_name(section.authority_provider())?;

        Ok((our_name, section, network, sk))
    }

    fn setup_adult() -> Result<(XorName, Section, Network)> {
        let prefix0 = Prefix::default().pushed(false);

        let sk = bls::SecretKey::random();
        let pk = sk.public_key();
        let chain = SecuredLinkedList::new(pk);

        let (section_auth, _, _) = gen_section_authority_provider(prefix0, ELDER_SIZE);
        let section_auth = proven(&sk, section_auth)?;
        let section = Section::new(pk, chain, section_auth)?;

        let network = Network::new();
        let our_name = section.prefix().substituted_in(rand::random());

        Ok((our_name, section, network))
    }

    fn choose_elder_name(section_auth: &SectionAuthorityProvider) -> Result<XorName> {
        section_auth
            .elders()
            .keys()
            .choose(&mut rand::thread_rng())
            .copied()
            .context("no elders")
    }
}
