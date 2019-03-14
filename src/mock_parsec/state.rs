// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Shared state for all mock parsec instances within a single test.

use super::{
    observation::{ObservationHolder, ObservationState},
    Block, NetworkEvent, PublicId,
};
use crate::{VersionedPrefix, XorName};
use std::{
    any::Any,
    cell::RefCell,
    collections::{BTreeMap, HashMap},
};

pub(super) struct SectionState<T: NetworkEvent, P: PublicId> {
    pub observations: BTreeMap<ObservationHolder<T, P>, ObservationState<P>>,
    pub blocks: Vec<(Block<T, P>, ObservationHolder<T, P>)>,
}

impl<T: NetworkEvent, P: PublicId> SectionState<T, P> {
    fn new() -> Self {
        Self {
            observations: BTreeMap::new(),
            blocks: Vec::new(),
        }
    }
}

type NetworkState<T, P> = HashMap<VersionedPrefix<XorName>, SectionState<T, P>>;

thread_local! {
    static STATE: RefCell<Option<Box<dyn Any>>> = RefCell::new(None);
}

pub(super) fn reset() {
    STATE.with(|state| {
        *state.borrow_mut() = None;
    })
}

pub(super) fn with<T, P, F, R>(section_info: VersionedPrefix<XorName>, f: F) -> R
where
    T: NetworkEvent + 'static,
    P: PublicId + 'static,
    F: FnOnce(&mut SectionState<T, P>) -> R,
{
    STATE.with(|cell| {
        let mut opt_network_state = cell.borrow_mut();
        match opt_network_state.as_mut() {
            None => {
                let mut section_state = SectionState::new();
                let result = f(&mut section_state);

                let mut network_state = HashMap::new();
                let _ = network_state.insert(section_info, section_state);
                *opt_network_state = Some(Box::new(network_state));

                result
            }
            Some(dyn_network_state) => {
                let network_state: &mut NetworkState<T, P> =
                    unwrap!(dyn_network_state.downcast_mut());
                let section_state = network_state
                    .entry(section_info)
                    .or_insert_with(SectionState::new);
                f(section_state)
            }
        }
    })
}
