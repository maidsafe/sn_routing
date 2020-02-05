// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{quic_p2p::Token, ConnectionInfo};
use log::LogLevel;
use std::{
    collections::{hash_map::Entry, HashMap},
    net::SocketAddr,
};

const MAX_RESENDS: u8 = 3;

enum TargetState {
    /// we don't know whether the last send attempt succeeded or failed
    /// the stored number of attempts already failed before
    Sending(u8),
    /// the last sending attempt (if any) failed; in total, the stored number of attempts failed
    Failed(u8),
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

    /// Mark the given target as failed and returns the next target to try to resend the message
    /// to, if available.
    ///
    /// The next target will be selected from the Failed targets with the lowest number of failed
    /// attempts so far, among the ones that failed at most MAX_RESENDS times. If there are
    /// multiple possibilities, the one with the highest priority (earliest in the list) is taken.
    /// Returns None if no such targets exist.
    pub fn target_failed(&mut self, token: Token, target: SocketAddr) -> Option<ConnectionInfo> {
        let mut entry = if let Entry::Occupied(entry) = self.cache.entry(token) {
            entry
        } else {
            return None;
        };

        set_target_failed(entry.get_mut(), &target);

        if entry.get().is_empty() {
            let _ = entry.remove();
            return None;
        }

        let (info, num, state) = entry
            .get_mut()
            .iter_mut()
            .filter_map(|(info, state)| match state {
                TargetState::Failed(x) => Some((info, *x, state)),
                TargetState::Sending(_) => None,
            })
            .min_by_key(|(_info, num, _state)| *num)?;
        *state = TargetState::Sending(num);

        Some(info.clone())
    }

    /// Mark the given target as succeeded in sending the given message.
    pub fn target_succeeded(&mut self, token: Token, target: SocketAddr) {
        let mut entry = if let Entry::Occupied(entry) = self.cache.entry(token) {
            entry
        } else {
            return;
        };

        entry.get_mut().retain(|(info, _)| info.peer_addr != target);

        if entry.get().is_empty() {
            let _ = entry.remove();
        }
    }
}

fn set_target_failed(targets: &mut Vec<(ConnectionInfo, TargetState)>, target: &SocketAddr) {
    let (index, state) = if let Some((index, (_, state))) = targets
        .iter_mut()
        .enumerate()
        .find(|(_, (info, _))| info.peer_addr == *target)
    {
        (index, state)
    } else {
        return;
    };

    match *state {
        TargetState::Failed(_) => {
            log_or_panic!(LogLevel::Error, "Got a failure from a failed target!");
            let _ = targets.remove(index);
        }
        TargetState::Sending(x) => {
            if x < MAX_RESENDS {
                *state = TargetState::Failed(x + 1);
            } else {
                let _ = targets.remove(index);
            }
        }
    }
}
