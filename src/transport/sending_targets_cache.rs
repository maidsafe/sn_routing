// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{quic_p2p::Token, time::Duration};
use std::{collections::HashMap, net::SocketAddr};

/// Maximal number of resend attempts to the same target.
pub const RESEND_MAX_ATTEMPTS: u8 = 3;
/// Delay before attempting to resend a previously failed message.
pub const RESEND_DELAY: Duration = Duration::from_secs(10);

enum TargetState {
    /// we don't know whether the last send attempt succeeded or failed
    /// the stored number of attempts already failed before
    Sending(u8),
    /// the last sending attempt (if any) failed; in total, the stored number of attempts failed
    Failed(u8),
    /// sending to this target succeeded
    Sent,
}

impl TargetState {
    pub fn is_sending(&self) -> bool {
        match *self {
            Self::Failed(_) | Self::Sent => false,
            Self::Sending(_) => true,
        }
    }
}

#[derive(Default)]
pub struct SendingTargetsCache {
    cache: HashMap<Token, Vec<(SocketAddr, TargetState)>>,
}

impl SendingTargetsCache {
    pub fn insert_message(&mut self, token: Token, initial_targets: &[SocketAddr], dg_size: usize) {
        // When a message is inserted into the cache initially, we are only sending it to `dg_size`
        // targets with the highest priority - thus, we will set the first `dg_size` targets'
        // states to Sending(0), and the rest to Failed(0) (indicating that we haven't sent to
        // them, and so they haven't failed yet)
        let targets = initial_targets
            .iter()
            .enumerate()
            .map(|(idx, tgt_info)| {
                (
                    *tgt_info,
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

    fn target_states(&self, token: Token) -> impl Iterator<Item = &(SocketAddr, TargetState)> {
        self.cache.get(&token).into_iter().flatten()
    }

    fn target_states_mut(
        &mut self,
        token: Token,
    ) -> impl Iterator<Item = &mut (SocketAddr, TargetState)> {
        self.cache.get_mut(&token).into_iter().flatten()
    }

    fn fail_target(&mut self, token: Token, target: SocketAddr) {
        if let Some((_addr, state)) = self
            .target_states_mut(token)
            .find(|(addr, _state)| *addr == target)
        {
            match *state {
                TargetState::Failed(_) => {
                    log_or_panic!(log::Level::Error, "Got a failure from a failed target!");
                }
                TargetState::Sending(x) => {
                    *state = TargetState::Failed(x + 1);
                }
                TargetState::Sent => {
                    log_or_panic!(
                        log::Level::Error,
                        "A target that should no longer fail - failed!"
                    );
                }
            }
        }
    }

    /// Finds a Failed target with the lowest number of failed attempts so far. If there are
    /// multiple possibilities, the one with the highest priority (earliest in the list) is taken.
    /// Returns `Never` if no such targets exist.
    fn take_next_target(&mut self, token: Token) -> Resend {
        if let Some((addr, failed_attempts, state)) = self
            .target_states_mut(token)
            .filter_map(|(addr, state)| match state {
                TargetState::Failed(x) if *x < RESEND_MAX_ATTEMPTS => Some((*addr, *x, state)),
                TargetState::Failed(_) | TargetState::Sending(_) | TargetState::Sent => None,
            })
            .min_by_key(|(_addr, failed_attempts, _state)| *failed_attempts)
        {
            *state = TargetState::Sending(failed_attempts);

            if failed_attempts == 0 {
                Resend::Now(addr)
            } else {
                Resend::Later(addr, RESEND_DELAY)
            }
        } else {
            Resend::Never
        }
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

    pub fn target_failed(&mut self, token: Token, target: SocketAddr) -> Resend {
        self.fail_target(token, target);

        let next_target = self.take_next_target(token);

        if self.should_drop(token) {
            let _ = self.cache.remove(&token);
        }

        next_target
    }

    pub fn target_succeeded(&mut self, token: Token, target: SocketAddr) {
        let _ = self
            .target_states_mut(token)
            .find(|(addr, _state)| *addr == target)
            .map(|(_addr, state)| {
                *state = TargetState::Sent;
            });
        if self.should_drop(token) {
            let _ = self.cache.remove(&token);
        }
    }
}

// How to resend a previously failed message.
pub enum Resend {
    // Resend it now to the given target.
    Now(SocketAddr),
    // Resend it to the given target after the given delay.
    Later(SocketAddr, Duration),
    // Don't resend - all attempts failed.
    Never,
}
