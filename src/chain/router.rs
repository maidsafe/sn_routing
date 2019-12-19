// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{delivery_group_size, shared_state::SharedState, EldersInfo, MemberInfo};
use crate::{Authority, P2pNode, Prefix, XorName, Xorable};
use err_derive::Error;
use std::{cmp::Ordering, collections::BTreeMap, iter};

/// Utility for routing messages and obtaining information about our network neighbourhood.
pub struct Router<'a> {
    our_name: &'a XorName,
    our_info: &'a EldersInfo,
    our_members: &'a BTreeMap<XorName, MemberInfo>,
    neighbour_infos: &'a BTreeMap<Prefix<XorName>, EldersInfo>,
    post_split_sibling_members: &'a BTreeMap<XorName, MemberInfo>,
}

impl<'a> Router<'a> {
    pub fn new(our_name: &'a XorName, state: &'a SharedState) -> Self {
        Self {
            our_name,
            our_info: state.our_info(),
            our_members: &state.our_members,
            neighbour_infos: &state.neighbour_infos,
            post_split_sibling_members: &state.post_split_sibling_members,
        }
    }

    /// Returns a set of nodes to which a message for the given `Authority` could be sent
    /// onwards, sorted by priority, along with the number of targets the message should be sent to.
    /// If the total number of targets returned is larger than this number, the spare targets can
    /// be used if the message can't be delivered to some of the initial ones.
    ///
    /// * If the destination is an `Authority::Section`:
    ///     - if our section is the closest on the network (i.e. our section's prefix is a prefix of
    ///       the destination), returns all other members of our section; otherwise
    ///     - returns the `N/3` closest members of the RT to the target
    ///
    /// * If the destination is an `Authority::PrefixSection`:
    ///     - if the prefix is compatible with our prefix and is fully-covered by prefixes in our
    ///       RT, returns all members in these prefixes except ourself; otherwise
    ///     - if the prefix is compatible with our prefix and is *not* fully-covered by prefixes in
    ///       our RT, returns `Err(Error::CannotRoute)`; otherwise
    ///     - returns the `N/3` closest members of the RT to the lower bound of the target
    ///       prefix
    ///
    /// * If the destination is an `Authority::Node`:
    ///     - if our name *is* the destination, returns an empty set; otherwise
    ///     - if the destination name is an entry in the routing table, returns it; otherwise
    ///     - returns the `N/3` closest members of the RT to the target
    pub fn targets(&self, dst: &Authority<XorName>) -> Result<(Vec<P2pNode>, usize), RouterError> {
        let candidates = |target_name: &XorName| {
            let filtered_sections = self
                .closest_sections_info(target_name)
                .into_iter()
                .map(|(prefix, members)| (prefix, members.len(), members.member_nodes().cloned()));

            let mut dg_size = 0;
            let mut nodes_to_send = Vec::new();
            for (idx, (prefix, len, connected)) in filtered_sections.enumerate() {
                nodes_to_send.extend(connected);
                dg_size = delivery_group_size(len);

                if prefix == self.our_prefix() {
                    // Send to all connected targets so they can forward the message
                    nodes_to_send.retain(|node| node.name() != self.our_name);
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
                Ok((dg_size, nodes_to_send))
            } else {
                Err(RouterError)
            }
        };

        let (dg_size, best_section) = match dst {
            Authority::Node(target_name) => {
                if target_name == self.our_name {
                    return Ok((Vec::new(), 0));
                }
                if let Some(node) = self.get_node(target_name) {
                    return Ok((vec![node.clone()], 1));
                }
                candidates(target_name)?
            }
            Authority::Section(target_name) => {
                let (prefix, section) = self.closest_section_info(target_name);
                if prefix == self.our_prefix() || prefix.is_neighbour(self.our_prefix()) {
                    // Exclude our name since we don't need to send to ourself
                    let our_name = self.our_name;

                    // FIXME: only doing this for now to match RT.
                    // should confirm if needed esp after msg_relay changes.
                    let section: Vec<_> = section
                        .member_nodes()
                        .filter(|node| node.name() != our_name)
                        .cloned()
                        .collect();
                    let dg_size = section.len();
                    return Ok((section, dg_size));
                }
                candidates(target_name)?
            }
            Authority::PrefixSection(prefix) => {
                if prefix.is_compatible(self.our_prefix()) || prefix.is_neighbour(self.our_prefix())
                {
                    // only route the message when we have all the targets in our routing table -
                    // this is to prevent spamming the network by sending messages with
                    // intentionally short prefixes
                    if prefix.is_compatible(self.our_prefix())
                        && !prefix.is_covered_by(self.all_prefixes())
                    {
                        return Err(RouterError);
                    }

                    let is_compatible = |(pfx, section)| {
                        if prefix.is_compatible(pfx) {
                            Some(section)
                        } else {
                            None
                        }
                    };

                    // Exclude our name since we don't need to send to ourself
                    let our_name = self.our_name;

                    let targets = self
                        .all_sections()
                        .filter_map(is_compatible)
                        .flat_map(EldersInfo::member_nodes)
                        .filter(|node| node.name() != our_name)
                        .cloned()
                        .collect::<Vec<_>>();
                    let dg_size = targets.len();
                    return Ok((targets, dg_size));
                }
                candidates(&prefix.lower_bound())?
            }
        };

        Ok((best_section, dg_size))
    }

    /// All prefixes of all sections known to us.
    pub fn all_prefixes(&'a self) -> impl Iterator<Item = &'a Prefix<XorName>> + Clone {
        self.other_prefixes()
            .chain(iter::once(self.our_info.prefix()))
    }

    /// Prefixes of all our neighbours.
    pub fn other_prefixes(&self) -> impl Iterator<Item = &Prefix<XorName>> + Clone {
        self.neighbour_infos.keys()
    }

    /// Returns an iterator over all neighbouring sections and our own, together with their prefix.
    pub fn all_sections(&self) -> impl Iterator<Item = (&'a Prefix<XorName>, &'a EldersInfo)> {
        self.neighbour_infos
            .iter()
            .chain(iter::once((self.our_info.prefix(), self.our_info)))
    }

    /// Returns the `P2pNode` struct for a known node with the given name.
    pub fn get_node(&self, name: &XorName) -> Option<&'a P2pNode> {
        self.get_member_node(name)
            .or_else(|| self.get_our_elder_node(name))
            .or_else(|| self.get_neighbour_node(name))
            .or_else(|| self.get_post_split_sibling_member_node(name))
    }

    /// Returns our section member `P2pNode`.
    pub fn get_member_node(&self, name: &XorName) -> Option<&'a P2pNode> {
        self.our_members
            .get(name)
            .map(|member_info| &member_info.p2p_node)
    }

    /// Returns the prefix of the closest non-empty section to `name`, regardless of whether `name`
    /// belongs in that section or not, and the section itself.
    pub fn closest_section_info(&self, name: &XorName) -> (&'a Prefix<XorName>, &'a EldersInfo) {
        let mut best_pfx = self.our_prefix();
        let mut best_info = self.our_info;
        for (pfx, info) in self.neighbour_infos {
            // TODO: Remove the first check after verifying that section infos are never empty.
            if !info.is_empty() && best_pfx.cmp_distance(pfx, name) == Ordering::Greater {
                best_pfx = pfx;
                best_info = info;
            }
        }

        (best_pfx, best_info)
    }

    fn get_our_elder_node(&self, name: &XorName) -> Option<&'a P2pNode> {
        self.our_info.member_map().get(name)
    }

    fn get_neighbour_node(&self, name: &XorName) -> Option<&'a P2pNode> {
        self.neighbour_infos
            .iter()
            .find(|(pfx, _)| pfx.matches(name))
            .and_then(|(_, elders_info)| elders_info.member_map().get(name))
    }

    fn get_post_split_sibling_member_node(&self, name: &XorName) -> Option<&'a P2pNode> {
        self.post_split_sibling_members
            .get(name)
            .map(|member_info| &member_info.p2p_node)
    }

    /// Returns the known sections sorted by the distance from a given XorName.
    fn closest_sections_info(&self, name: &XorName) -> Vec<(&Prefix<XorName>, &EldersInfo)> {
        let mut result: Vec<_> = iter::once((self.our_prefix(), self.our_info))
            .chain(self.neighbour_infos.iter())
            .collect();
        result.sort_by(|lhs, rhs| lhs.0.cmp_distance(rhs.0, name));
        result
    }

    fn our_prefix(&self) -> &'a Prefix<XorName> {
        self.our_info.prefix()
    }
}

/// Router error.
#[derive(Debug, Error)]
#[allow(missing_docs)]
#[error(display = "Cannot route.")]
pub struct RouterError;
