// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    consensus::Proven,
    network::Network,
    section::{EldersInfo, Section},
};
use bls_signature_aggregator::Proof;
use xor_name::{Prefix, XorName};

/// Helper structure to make sure that during splits, our and the sibling sections are updated
/// consistently.
///
/// # Usage
///
/// Each mutation to be applied to our `Section` or `Network` must pass through this barrier
/// first. Call the corresponding handler (`handle_our_section`, `handle_their_key`) and then call
/// `take`. If it returns `Some` for our and/or sibling section, apply it to the corresponding
/// state, otherwise do nothing.
#[derive(Default)]
pub(crate) struct SplitBarrier {
    our: Option<State>,
    sibling: Option<State>,
}

impl SplitBarrier {
    pub fn handle_our_section(
        &mut self,
        our_name: &XorName,
        current_section: &Section,
        current_network: &Network,
        elders_info: Proven<EldersInfo>,
        key_proof: Proof,
    ) {
        if elders_info
            .value
            .prefix
            .is_extension_of(current_section.prefix())
        {
            if elders_info.value.prefix.matches(our_name) {
                update(&mut self.our, current_section, current_network, |state| {
                    state.update_elders(elders_info.clone(), key_proof)
                });
                update(
                    &mut self.sibling,
                    current_section,
                    current_network,
                    |state| state.update_neighbour_info(elders_info),
                );
            } else {
                update(
                    &mut self.sibling,
                    current_section,
                    current_network,
                    |state| state.update_elders(elders_info.clone(), key_proof),
                );
                update(&mut self.our, current_section, current_network, |state| {
                    state.update_neighbour_info(elders_info)
                });
            }
        } else {
            update(&mut self.our, current_section, current_network, |state| {
                state.update_elders(elders_info, key_proof)
            });
        }
    }

    pub fn handle_their_key(
        &mut self,
        our_name: &XorName,
        current_section: &Section,
        current_network: &Network,
        key: Proven<(Prefix, bls::PublicKey)>,
    ) {
        if key.value.0.matches(our_name) {
            update(
                &mut self.sibling,
                current_section,
                current_network,
                |state| state.update_their_key(key),
            )
        } else {
            update(&mut self.our, current_section, current_network, |state| {
                state.update_their_key(key)
            })
        }
    }

    // Takes out the `State` diffs to be applied to our (and siblings, in case of a split)
    // `Section` and `Network` if the invariants described above are met.
    // Returns `(our_state, sibling_state)`.
    pub fn take(&mut self, current_prefix: &Prefix) -> (Option<State>, Option<State>) {
        let our = if let Some(state) = &self.our {
            state
        } else {
            return (None, None);
        };

        if our.section.prefix() == current_prefix {
            if let Some(sibling) = &self.sibling {
                if sibling.section.prefix().is_extension_of(current_prefix) {
                    return (None, None);
                }
            } else {
                return (self.our.take(), None);
            }
        }

        let sibling = if let Some(state) = &self.sibling {
            state
        } else {
            return (None, None);
        };

        if !our.network.has_key(sibling.section.chain().last_key()) {
            return (None, None);
        }

        if our.network.get(sibling.section.prefix()) != Some(sibling.section.elders_info()) {
            return (None, None);
        }

        if !sibling.network.has_key(our.section.chain().last_key()) {
            return (None, None);
        }

        if sibling.network.get(our.section.prefix()) != Some(our.section.elders_info()) {
            return (None, None);
        }

        (self.our.take(), self.sibling.take())
    }
}

pub(crate) struct State {
    /// Info about our section.
    pub section: Section,
    /// Info about the rest of the network.
    pub network: Network,
}

impl State {
    fn update_elders(&mut self, elders_info: Proven<EldersInfo>, key_proof: Proof) -> bool {
        if self.section.update_elders(elders_info, key_proof) {
            self.network.prune_neighbours(self.section.prefix());
            true
        } else {
            false
        }
    }

    fn update_neighbour_info(&mut self, elders_info: Proven<EldersInfo>) -> bool {
        if self.network.update_neighbour_info(elders_info) {
            self.network.prune_neighbours(self.section.prefix());
            true
        } else {
            false
        }
    }

    fn update_their_key(&mut self, key: Proven<(Prefix, bls::PublicKey)>) -> bool {
        if key.value.0 == *self.section.prefix() {
            // Ignore our keys. Use `update_elders` for that.
            return false;
        }

        self.network.update_their_key(key)
    }
}

fn update(
    barrier_state: &mut Option<State>,
    current_section: &Section,
    current_network: &Network,
    f: impl FnOnce(&mut State) -> bool,
) {
    if let Some(state) = barrier_state {
        let _ = f(state);
    } else {
        let mut state = State {
            section: current_section.clone(),
            network: current_network.clone(),
        };
        if f(&mut state) {
            *barrier_state = Some(state);
        }
    }
}

// TODO: write tests
#[cfg(test)]
mod tests {}
