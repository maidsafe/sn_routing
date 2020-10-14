// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{EldersInfo, SharedState};
use crate::consensus::Proven;
use std::collections::HashSet;
use xor_name::{Prefix, XorName};

/// Helper structure to synchronize updates to `SharedState` in order to keep certain useful
/// invariants:
///
/// - our `EldersInfo` corresponds to the latest section chain key.
/// - in case of split, both siblings know each others latest keys
///
/// Usage: each mutation to be applied to our `SharedState` must pass through this barrier first.
/// Call the corresponding handler (`handle_section_info`, `handle_our_key`, ...) and then call
/// `take`. If it returns `Some` for our and/or sibling section, apply it to the corresponding
/// state, otherwise do nothing.
///
/// TODO: this whole machinery might not be necessary. It's possible the above invariants are not
/// really needed. Investigate whether that is the case.
#[derive(Default)]
pub(crate) struct SectionUpdateBarrier {
    our: Option<SharedState>,
    sibling: Option<SharedState>,
    pending_updates: HashSet<Prefix>,
}

impl SectionUpdateBarrier {
    // Mark the section update for the given prefix as started. This prevents starting another
    // update while one is still in progress.
    //
    // FIXME: this is not bullet-proof. In case of a heavy churn, it can happen that we get two or
    // more successful DKG results around the same time, but they will not necessary be received in
    // the same order by everyone. So it can happen that some nodes will start the section update
    // based on one DKG result while others will use another one and neither one will reach
    // consensus which would currently stall the section. Even though this situation might be
    // unlikely, we should still find a solution to this problem.
    pub fn start_update(&mut self, prefix: Prefix) -> bool {
        self.pending_updates.insert(prefix)
    }

    pub fn handle_section_info(
        &mut self,
        current: &SharedState,
        our_name: &XorName,
        elders_info: Proven<EldersInfo>,
    ) {
        if elders_info
            .value
            .prefix
            .is_extension_of(current.section.prefix())
        {
            if elders_info.value.prefix.matches(our_name) {
                update(&mut self.our, current, |state| {
                    state.update_our_info(elders_info.clone())
                });
                update(&mut self.sibling, current, |state| {
                    state.update_neighbour_info(elders_info)
                });
            } else {
                update(&mut self.sibling, current, |state| {
                    state.update_our_info(elders_info.clone())
                });
                update(&mut self.our, current, |state| {
                    state.update_neighbour_info(elders_info)
                });
            }
        } else {
            update(&mut self.our, current, |state| {
                state.update_our_info(elders_info.clone())
            });
        }
    }

    pub fn handle_our_key(
        &mut self,
        current: &SharedState,
        our_name: &XorName,
        prefix: &Prefix,
        key: Proven<bls::PublicKey>,
    ) {
        if prefix.matches(our_name) {
            update(&mut self.our, current, |state| {
                state.section.update_chain(key)
            })
        } else {
            update(&mut self.sibling, current, |state| {
                state.section.update_chain(key)
            })
        }
    }

    pub fn handle_their_key(
        &mut self,
        current: &SharedState,
        our_name: &XorName,
        key: Proven<(Prefix, bls::PublicKey)>,
    ) {
        if key.value.0.matches(our_name) {
            update(&mut self.sibling, current, |state| {
                state.update_their_key(key)
            })
        } else {
            update(&mut self.our, current, |state| state.update_their_key(key))
        }
    }

    // Takes out the `SharedState` diffs to be applied to our (and siblings, in case of a split)
    // shared state if the invariants described above are met.
    // Returns `(our_state, sibling_state)`.
    pub fn take(&mut self, current_prefix: &Prefix) -> (Option<SharedState>, Option<SharedState>) {
        let our = if let Some(state) = &self.our {
            state
        } else {
            return (None, None);
        };

        if !is_our_info_in_sync_with_our_key(our) {
            return (None, None);
        }

        if our.section.prefix() == current_prefix {
            if let Some(sibling) = &self.sibling {
                if sibling.section.prefix().is_extension_of(current_prefix) {
                    return (None, None);
                }
            } else {
                self.pending_updates.clear();

                return (self.our.take(), None);
            }
        }

        let sibling = if let Some(state) = &self.sibling {
            state
        } else {
            return (None, None);
        };

        if !is_our_info_in_sync_with_our_key(sibling) {
            return (None, None);
        }

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

        self.pending_updates.clear();

        (self.our.take(), self.sibling.take())
    }
}

fn update(
    barrier_state: &mut Option<SharedState>,
    current: &SharedState,
    f: impl FnOnce(&mut SharedState) -> bool,
) {
    if let Some(state) = barrier_state {
        let _ = f(state);
    } else {
        let mut state = current.clone();
        if f(&mut state) {
            *barrier_state = Some(state);
        }
    }
}

fn is_our_info_in_sync_with_our_key(state: &SharedState) -> bool {
    // Note: the first key in the chain is signed with itself, so we need to special-case this to
    // avoid returning incomplete state prematurely when there is only one node in the network.
    if state.section.elders_info().prefix == Prefix::default()
        && state.section.elders_info().elders.len() <= 1
    {
        return false;
    }

    state
        .section
        .chain()
        .index_of(&state.section.proven_elders_info().proof.public_key)
        .map(|index| index + 1 == state.section.chain().last_key_index())
        .unwrap_or(false)
}

// TODO: write tests
#[cfg(test)]
mod tests {}
