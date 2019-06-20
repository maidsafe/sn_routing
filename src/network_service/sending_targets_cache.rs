// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::ConnectionInfo;
use log::LogLevel;
use std::collections::HashMap;
use std::net::SocketAddr;

const MAX_RESENDS: u8 = 3;

enum TargetState {
    Sending(u8),
    Failed(u8),
    Sent,
}

impl TargetState {
    pub fn is_complete(&self) -> bool {
        match *self {
            TargetState::Failed(x) => x > MAX_RESENDS,
            TargetState::Sent => true,
            TargetState::Sending(_) => false,
        }
    }
}

pub struct SendingTargetsCache {
    cache: HashMap<u64, Vec<(ConnectionInfo, TargetState)>>,
}

impl SendingTargetsCache {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    pub fn insert_message(
        &mut self,
        msg_id: u64,
        initial_targets: Vec<ConnectionInfo>,
        dg_size: usize,
    ) {
        let targets = initial_targets
            .into_iter()
            .enumerate()
            .map(|(idx, tgt_info)| {
                (
                    tgt_info,
                    if idx < dg_size {
                        TargetState::Sending(0)
                    } else {
                        TargetState::Failed(0)
                    },
                )
            })
            .collect();
        let _ = self.cache.insert(msg_id, targets);
    }

    fn target_states<'a>(
        &'a self,
        msg_id: u64,
    ) -> impl Iterator<Item = &'a (ConnectionInfo, TargetState)> {
        self.cache.get(&msg_id).into_iter().flatten()
    }

    fn target_states_mut<'a>(
        &'a mut self,
        msg_id: u64,
    ) -> impl Iterator<Item = &'a mut (ConnectionInfo, TargetState)> {
        self.cache.get_mut(&msg_id).into_iter().flatten()
    }

    fn fail_target(&mut self, msg_id: u64, target: SocketAddr) {
        let _ = self
            .target_states_mut(msg_id)
            .find(|(info, _state)| info.peer_addr() == target)
            .map(|(_info, state)| match *state {
                TargetState::Failed(_) => {
                    log_or_panic!(LogLevel::Error, "Got a failure from a failed target!");
                }
                TargetState::Sending(x) => {
                    *state = TargetState::Failed(x + 1);
                }
                TargetState::Sent => {
                    log_or_panic!(
                        LogLevel::Error,
                        "A target that should no longer fail - failed!"
                    );
                }
            });
    }

    fn take_next_target(&mut self, msg_id: u64) -> Option<ConnectionInfo> {
        self.target_states_mut(msg_id)
            .filter(|(_info, state)| !state.is_complete())
            .filter_map(|(info, state)| match state {
                TargetState::Failed(x) => Some((info, *x, state)),
                _ => None,
            })
            .min_by_key(|(_info, num, _state)| *num)
            .map(|(info, num, state)| {
                *state = TargetState::Sending(num);
                info
            })
            .cloned()
    }

    fn should_drop(&self, msg_id: u64) -> bool {
        self.target_states(msg_id)
            .all(|(_info, state)| state.is_complete())
    }

    pub fn target_failed(&mut self, msg_id: u64, target: SocketAddr) -> Option<ConnectionInfo> {
        self.fail_target(msg_id, target);
        if self.should_drop(msg_id) {
            let _ = self.cache.remove(&msg_id);
        }
        // if we dropped the msg_id above, this would have returned None even if we hadn't
        self.take_next_target(msg_id)
    }

    pub fn target_succeeded(&mut self, msg_id: u64, target: SocketAddr) {
        let _ = self
            .target_states_mut(msg_id)
            .find(|(info, _state)| info.peer_addr() == target)
            .map(|(_info, state)| {
                *state = TargetState::Sent;
            });
        if self.should_drop(msg_id) {
            let _ = self.cache.remove(&msg_id);
        }
    }
}
