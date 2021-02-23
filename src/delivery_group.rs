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
    majority,
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
        DstLocation::Node(target_name) | DstLocation::AccumulatingNode(target_name) => {
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

    if info.prefix == *section.prefix() || info.prefix.is_neighbour(section.prefix()) {
        // Exclude our name since we don't need to send to ourself

        // FIXME: only doing this for now to match RT.
        // should confirm if needed esp after msg_relay changes.
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

    let mut dg_size = majority(ELDER_SIZE);
    let mut nodes_to_send = Vec::new();
    for (idx, (prefix, len, connected)) in sections.enumerate() {
        nodes_to_send.extend(connected.cloned());
        // If we don't have enough contacts send to as many as possible
        // up to majority of Elders
        dg_size = cmp::min(len, dg_size);
        if len < majority(ELDER_SIZE) {
            warn!(
                "Delivery group only {:?} when it should be {:?}",
                len,
                majority(ELDER_SIZE)
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

// Returns the set of peers that are responsible for collecting signatures to verify a message;
// this may contain us or only other nodes.
pub fn signature_targets<I>(dst: &DstLocation, our_elders: I) -> Vec<Peer>
where
    I: IntoIterator<Item = Peer>,
{
    let dst_name = match dst {
        DstLocation::Node(name) => *name,
        DstLocation::AccumulatingNode(name) => *name,
        DstLocation::Section(name) => *name,
        DstLocation::EndUser(_) | DstLocation::Direct => {
            error!("Invalid destination for signature targets: {:?}", dst);
            return vec![];
        }
    };

    let mut list: Vec<_> = our_elders
        .into_iter()
        .sorted_by(|lhs, rhs| dst_name.cmp_distance(lhs.name(), rhs.name()))
        .collect();
    list.truncate(cmp::min(list.len(), majority(ELDER_SIZE)));
    list
}
