// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Utilities for routing messages through the network.

use crate::{
    error::{Result, RoutingError},
    id::{P2pNode, PublicId},
    location::DstLocation,
    section::{EldersInfo, SectionMap, SectionMembers},
    xor_space::{XorName, Xorable},
};
use itertools::Itertools;

/// Returns the delivery group size based on the section size `n`
pub const fn delivery_group_size(n: usize) -> usize {
    // this is an integer that is ≥ n/3
    (n + 2) / 3
}

/// Returns a set of nodes to which a message for the given `DstLocation` could be sent
/// onwards, sorted by priority, along with the number of targets the message should be sent to.
/// If the total number of targets returned is larger than this number, the spare targets can
/// be used if the message can't be delivered to some of the initial ones.
///
/// * If the destination is an `DstLocation::Section`:
///     - if our section is the closest on the network (i.e. our section's prefix is a prefix of
///       the destination), returns all other members of our section; otherwise
///     - returns the `N/3` closest members to the target
///
/// * If the destination is an `DstLocation::PrefixSection`:
///     - if the prefix is compatible with our prefix and is fully-covered by prefixes in our
///       RT, returns all members in these prefixes except ourself; otherwise
///     - if the prefix is compatible with our prefix and is *not* fully-covered by prefixes in
///       our RT, returns `Err(Error::CannotRoute)`; otherwise
///     - returns the `N/3` closest members of the RT to the lower bound of the target
///       prefix
///
/// * If the destination is an individual node:
///     - if our name *is* the destination, returns an empty set; otherwise
///     - if the destination name is an entry in the routing table, returns it; otherwise
///     - returns the `N/3` closest members of the RT to the target
pub fn delivery_targets(
    dst: &DstLocation,
    our_id: &PublicId,
    our_members: &SectionMembers,
    sections: &SectionMap,
) -> Result<(Vec<P2pNode>, usize)> {
    if !sections.is_elder(our_id) {
        // We are not Elder - return all the elders of our section, so the message can be properly
        // relayed through them.
        let targets: Vec<_> = sections.our_elders().cloned().collect();
        let dg_size = targets.len();
        return Ok((targets, dg_size));
    }

    let (best_section, dg_size) = match dst {
        DstLocation::Node(target_name) => {
            if target_name == our_id.name() {
                return Ok((Vec::new(), 0));
            }
            if let Some(node) = get_p2p_node(target_name, our_members, sections) {
                return Ok((vec![node.clone()], 1));
            }

            candidates(target_name, our_id, sections)?
        }
        DstLocation::Section(target_name) => {
            let (prefix, section) = sections.closest(target_name);
            if prefix == sections.our().prefix() || prefix.is_neighbour(sections.our().prefix()) {
                // Exclude our name since we don't need to send to ourself

                // FIXME: only doing this for now to match RT.
                // should confirm if needed esp after msg_relay changes.
                let section: Vec<_> = section
                    .member_nodes()
                    .filter(|node| node.name() != our_id.name())
                    .cloned()
                    .collect();
                let dg_size = section.len();
                return Ok((section, dg_size));
            }

            candidates(target_name, our_id, sections)?
        }
        DstLocation::Prefix(prefix) => {
            if prefix.is_compatible(sections.our().prefix())
                || prefix.is_neighbour(sections.our().prefix())
            {
                // only route the message when we have all the targets in our chain -
                // this is to prevent spamming the network by sending messages with
                // intentionally short prefixes
                if prefix.is_compatible(sections.our().prefix())
                    && !prefix.is_covered_by(sections.prefixes())
                {
                    return Err(RoutingError::CannotRoute);
                }

                let is_compatible = |(pfx, section)| {
                    if prefix.is_compatible(pfx) {
                        Some(section)
                    } else {
                        None
                    }
                };

                // Exclude our name since we don't need to send to ourself
                let targets: Vec<_> = sections
                    .all()
                    .filter_map(is_compatible)
                    .flat_map(EldersInfo::member_nodes)
                    .filter(|node| node.name() != our_id.name())
                    .cloned()
                    .collect();
                let dg_size = targets.len();
                return Ok((targets, dg_size));
            }

            candidates(&prefix.lower_bound(), our_id, sections)?
        }
        DstLocation::Direct => return Err(RoutingError::CannotRoute),
    };

    Ok((best_section, dg_size))
}

// Obtain the delivery group candidates for this target
fn candidates(
    target_name: &XorName,
    our_id: &PublicId,
    sections: &SectionMap,
) -> Result<(Vec<P2pNode>, usize)> {
    let filtered_sections = sections
        .sorted_by_distance_to(target_name)
        .into_iter()
        .map(|(prefix, members)| (prefix, members.len(), members.member_nodes()));

    let mut dg_size = 0;
    let mut nodes_to_send = Vec::new();
    for (idx, (prefix, len, connected)) in filtered_sections.enumerate() {
        nodes_to_send.extend(connected.cloned());
        dg_size = delivery_group_size(len);

        if prefix == sections.our().prefix() {
            // Send to all connected targets so they can forward the message
            nodes_to_send.retain(|node| node.name() != our_id.name());
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
        Err(RoutingError::CannotRoute)
    }
}

// Returns a `P2pNode` for a known node.
fn get_p2p_node<'a>(
    name: &XorName,
    our_members: &'a SectionMembers,
    sections: &'a SectionMap,
) -> Option<&'a P2pNode> {
    our_members
        .get_p2p_node(name)
        .or_else(|| sections.get_elder(name))
}

// Returns the set of peers that are responsible for collecting signatures to verify a message;
// this may contain us or only other nodes.
pub fn signature_targets<I>(dst: &DstLocation, our_elders: I) -> Vec<P2pNode>
where
    I: IntoIterator<Item = P2pNode>,
{
    let dst_name = match dst {
        DstLocation::Node(name) => *name,
        DstLocation::Section(name) => *name,
        DstLocation::Prefix(prefix) => prefix.name(),
        DstLocation::Direct => {
            log_or_panic!(
                log::Level::Error,
                "Invalid destination for signature targets: {:?}",
                dst
            );
            return vec![];
        }
    };

    let mut list = our_elders
        .into_iter()
        .sorted_by(|lhs, rhs| dst_name.cmp_distance(lhs.name(), rhs.name()));
    list.truncate(delivery_group_size(list.len()));
    list
}
