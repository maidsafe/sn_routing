// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{quic_p2p::Token, ConnectionInfo};
use log::LogLevel;
use std::collections::HashMap;
use std::net::SocketAddr;

const MAX_RESENDS: u8 = 3;

enum TargetState {
    /// we don't know whether the last send attempt suceeded or failed
    /// the stored number of attempts already failed before
    Sending(u8),
    /// the last sending attempt (if any) failed; in total, the stored number of attempts failed
    Failed(u8),
    /// sending to this target succeeded
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

    pub fn is_sending(&self) -> bool {
        match *self {
            TargetState::Failed(_) | TargetState::Sent => false,
            TargetState::Sending(_) => true,
        }
    }
}

#[derive(Default)]
pub struct SendingTargetsCache {
    cache: HashMap<Token, Vec<(ConnectionInfo, TargetState)>>,
}

impl SendingTargetsCache {
    pub fn insert_message(
        &mut self,
        token: Token,
        initial_targets: &[ConnectionInfo],
        dg_size: usize,
    ) {
        // When a message is inserted into the cache initially, we are only sending it to `dg_size`
        // targets with the highest priority - thus, we will set the first `dg_size` targets'
        // states to Sending(0), and the rest to Failed(0) (indicating that we haven't sent to
        // them, and so they haven't failed yet)
        let targets = initial_targets
            .iter()
            .enumerate()
            .map(|(idx, tgt_info)| {
                (
                    tgt_info.clone(),
                    if idx < dg_size {
                        TargetState::Sending(0)
                    } else {
                        TargetState::Failed(0)
                    },
                )
            })
            .collect();
        let _ = self.cache.insert(token, targets);
    }

    fn target_states(&self, token: Token) -> impl Iterator<Item = &(ConnectionInfo, TargetState)> {
        self.cache.get(&token).into_iter().flatten()
    }

    fn target_states_mut(
        &mut self,
        token: Token,
    ) -> impl Iterator<Item = &mut (ConnectionInfo, TargetState)> {
        self.cache.get_mut(&token).into_iter().flatten()
    }

    fn fail_target(&mut self, token: Token, target: SocketAddr) {
        let _ = self
            .target_states_mut(token)
            .find(|(info, _state)| info.peer_addr == target)
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

    /// Finds a Failed target with the lowest number of failed attempts so far, among the ones that
    /// failed at most MAX_RESENDS times. If there are multiple possibilities, the one with the
    /// highest priority (earliest in the list) is taken. Returns None if no such targets exist.
    fn take_next_target(&mut self, token: Token) -> Option<ConnectionInfo> {
        self.target_states_mut(token)
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

    fn should_drop(&self, token: Token) -> bool {
        // Other methods maintain the invariant that exactly one of these is true:
        // - some target is in the Sending state
        // - we succeeded (no further sending needed)
        // - we failed (no more targets available)
        // So if none are sending, the handling of the message is finished and we can drop it
        self.target_states(token)
            .all(|(_info, state)| !state.is_sending())
    }

    pub fn target_failed(&mut self, token: Token, target: SocketAddr) -> Option<ConnectionInfo> {
        self.fail_target(token, target);
        let result = self.take_next_target(token);
        if self.should_drop(token) {
            let _ = self.cache.remove(&token);
        }
        result
    }

    pub fn target_succeeded(&mut self, token: Token, target: SocketAddr) {
        let _ = self
            .target_states_mut(token)
            .find(|(info, _state)| info.peer_addr == target)
            .map(|(_info, state)| {
                *state = TargetState::Sent;
            });
        if self.should_drop(token) {
            let _ = self.cache.remove(&token);
        }
    }
}
