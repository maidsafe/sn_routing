// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{EldersInfo, SharedState};
use crate::consensus::Proven;
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
}

impl SectionUpdateBarrier {
    pub fn handle_section_info(
        &mut self,
        current: &SharedState,
        our_name: &XorName,
        elders_info: Proven<EldersInfo>,
    ) {
        if elders_info
            .value
            .prefix
            .is_extension_of(current.our_prefix())
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
            update(&mut self.our, current, |state| state.update_our_key(key))
        } else {
            update(&mut self.sibling, current, |state| {
                state.update_our_key(key)
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

        if our.our_prefix() == current_prefix {
            if let Some(sibling) = &self.sibling {
                if sibling.our_prefix().is_extension_of(current_prefix) {
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

        if !is_our_info_in_sync_with_our_key(sibling) {
            return (None, None);
        }

        if !our.sections.has_key(sibling.our_history.last_key()) {
            return (None, None);
        }

        if our.sections.get(sibling.our_prefix()) != Some(sibling.our_info()) {
            return (None, None);
        }

        if !sibling.sections.has_key(our.our_history.last_key()) {
            return (None, None);
        }

        if sibling.sections.get(our.our_prefix()) != Some(our.our_info()) {
            return (None, None);
        }

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
    if state.our_info().prefix == Prefix::default() && state.our_info().elders.len() <= 1 {
        return false;
    }

    state
        .our_history
        .index_of(&state.sections.proven_our().proof.public_key)
        .map(|index| index + 1 == state.our_history.last_key_index())
        .unwrap_or(false)
}

// TODO: write tests
#[cfg(test)]
mod tests {}
