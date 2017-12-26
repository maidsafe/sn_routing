// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use ack_manager::ACK_TIMEOUT_SECS;
use action::Action;
use event::Event;
#[cfg(feature = "use-mock-crust")]
use fake_clock::FakeClock as Instant;
use id::PublicId;
use itertools::Itertools;
use maidsafe_utilities::thread;
use messages::{DirectMessage, MAX_PART_LEN};
use outbox::EventBox;
use resource_proof::ResourceProof;
use signature_accumulator::ACCUMULATION_TIMEOUT_SECS;
use state_machine::Transition;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
#[cfg(not(feature = "use-mock-crust"))]
use std::time::Instant;
use timer::Timer;
use types::RoutingActionSender;
use utils::DisplayDuration;

/// Time (in seconds) between accepting a new candidate (i.e. receiving an `AcceptAsCandidate` from
/// our section) and sending a `CandidateApproval` for this candidate. If the candidate cannot
/// satisfy the proof of resource challenge within this time, no `CandidateApproval` is sent.
pub const RESOURCE_PROOF_DURATION_SECS: u64 = 300;
/// Maximum time a new node will wait to receive `NodeApproval` after receiving a
/// `RelocateResponse`. This covers the built-in delay of the process and also allows time for the
/// message to accumulate and be sent via four different routes.
const APPROVAL_TIMEOUT_SECS: u64 = RESOURCE_PROOF_DURATION_SECS + ACCUMULATION_TIMEOUT_SECS +
    (4 * ACK_TIMEOUT_SECS);
/// Interval between displaying info about ongoing approval progress, in seconds.
const APPROVAL_PROGRESS_INTERVAL_SECS: u64 = 30;

/// Handles resource proofs
pub struct ResourceProver {
    /// Copy of the action sender, used to allow worker threads to contact us
    action_sender: RoutingActionSender,
    get_approval_timer_token: Option<u64>,
    approval_progress_timer_token: Option<u64>,
    approval_expiry_time: Instant,
    approval_timeout_secs: u64,
    /// Number of expected resource proof challengers.
    challenger_count: usize,
    /// Map of ResourceProofResponse parts.
    response_parts: HashMap<PublicId, Vec<DirectMessage>>,
    /// Map of workers
    workers: HashMap<PublicId, (Arc<AtomicBool>, thread::Joiner)>,
    timer: Timer,
}

impl ResourceProver {
    /// Create an instance.
    pub fn new(action_sender: RoutingActionSender, timer: Timer, challenger_count: usize) -> Self {
        ResourceProver {
            action_sender: action_sender,
            get_approval_timer_token: None,
            approval_progress_timer_token: None,
            approval_expiry_time: Instant::now(),
            approval_timeout_secs: APPROVAL_TIMEOUT_SECS,
            challenger_count: challenger_count,
            response_parts: Default::default(),
            workers: Default::default(),
            timer: timer,
        }
    }

    /// Start timers when receiving a new name (after relocation, before resource proof)
    pub fn start(&mut self, resource_proof_disabled: bool) {
        // Reduced waiting time when resource proof is disabled.
        if resource_proof_disabled {
            self.approval_timeout_secs = 30;
        }
        let duration = Duration::from_secs(self.approval_timeout_secs);
        self.approval_expiry_time = Instant::now() + duration;
        self.get_approval_timer_token = Some(self.timer.schedule(duration));
        self.approval_progress_timer_token = Some(self.timer.schedule(Duration::from_secs(
            APPROVAL_PROGRESS_INTERVAL_SECS,
        )));
    }

    /// Start generating a resource proof in a background thread
    pub fn handle_request(
        &mut self,
        pub_id: PublicId,
        seed: Vec<u8>,
        target_size: usize,
        difficulty: u8,
        log_ident: String,
    ) {
        if self.response_parts.is_empty() {
            info!(
                "{} Starting approval process to test this node's resources. This will take \
                   at least {} seconds.",
                log_ident,
                RESOURCE_PROOF_DURATION_SECS
            );
        }

        let atomic_cancel = Arc::new(AtomicBool::new(false));
        let atomic_cancel_clone = Arc::clone(&atomic_cancel);
        let action_sender = self.action_sender.clone();
        let joiner = thread::named("resource_prover", move || {
            let start = Instant::now();
            let rp_object = ResourceProof::new(target_size, difficulty);
            let proof_data = rp_object.create_proof_data(&seed);
            let mut prover = rp_object.create_prover(proof_data.clone());
            let leading_zero_bytes;
            loop {
                if let Some(result) = prover.try_step() {
                    // TODO: break with value when Rust #37339 becomes stable
                    leading_zero_bytes = result;
                    break;
                }
                if atomic_cancel_clone.load(Ordering::Relaxed) {
                    info!("{} Approval process cancelled", log_ident);
                    return;
                }
            }
            let elapsed = start.elapsed();

            let parts = proof_data
                .into_iter()
                .chunks(MAX_PART_LEN)
                .into_iter()
                .map(|chunk| chunk.collect_vec())
                .collect_vec();

            let part_count = parts.len();
            let mut messages = parts
                .into_iter()
                .enumerate()
                .rev()
                .map(|(part_index, part)| {
                    DirectMessage::ResourceProofResponse {
                        part_index: part_index,
                        part_count: part_count,
                        proof: part,
                        leading_zero_bytes: leading_zero_bytes,
                    }
                })
                .collect_vec();
            if messages.is_empty() {
                messages.push(DirectMessage::ResourceProofResponse {
                    part_index: 0,
                    part_count: 1,
                    proof: vec![],
                    leading_zero_bytes: leading_zero_bytes,
                });
            }

            trace!(
                "{} created proof data in {} seconds. Target size: {}, \
                    Difficulty: {}, Seed: {:?}",
                log_ident,
                elapsed.display_secs(),
                target_size,
                difficulty,
                seed
            );

            let action = Action::ResourceProofResult(pub_id, messages);
            if action_sender.send(action).is_err() {
                // In theory this means the receiver disconnected, so the main thread stopped/reset
                error!(
                    "{}: resource proof worker thread failed to send result",
                    log_ident
                );
            }
        });
        // If using mock_crust we want the joiner to drop and join immediately
        if cfg!(feature = "use-mock-crust") {
            let _ = joiner;
        } else {
            let old = self.workers.insert(pub_id, (atomic_cancel, joiner));
            if let Some((atomic_cancel, _old_worker)) = old {
                // This is probably a bug if it happens, but in any case the Drop impl on
                // _old_worker will implicitly join the thread.
                atomic_cancel.store(true, Ordering::Relaxed);
            }
        }
    }

    /// When the resource proof is complete, the result is returned to the main thread.
    ///
    /// This function returns the first message to send.
    pub fn handle_action_res_proof(
        &mut self,
        pub_id: PublicId,
        mut messages: Vec<DirectMessage>,
    ) -> DirectMessage {
        // Thread signalled it was complete; implicit join on Joiner thus shouldn't hang.
        let _old = self.workers.remove(&pub_id);

        let first_message = unwrap!(messages.pop()); // Sender guarantees at least one message
        let _ = self.response_parts.insert(pub_id, messages);
        first_message
    }

    /// Get the next part of the proof to be sent, if any.
    pub fn handle_receipt(&mut self, pub_id: PublicId) -> Option<DirectMessage> {
        self.response_parts.get_mut(&pub_id).and_then(Vec::pop)
    }

    /// Reset timers
    pub fn handle_approval(&mut self) {
        self.get_approval_timer_token = None;
        self.approval_progress_timer_token = None;
        self.response_parts.clear();
    }

    /// Try handling a timeout. Return `Some(transition)` iff token was handled.
    pub fn handle_timeout(
        &mut self,
        token: u64,
        log_ident: String,
        outbox: &mut EventBox,
    ) -> Option<Transition> {
        if self.get_approval_timer_token == Some(token) {
            self.handle_approval_timeout(log_ident, outbox);
            Some(Transition::Terminate)
        } else if self.approval_progress_timer_token == Some(token) {
            self.approval_progress_timer_token = Some(self.timer.schedule(Duration::from_secs(
                APPROVAL_PROGRESS_INTERVAL_SECS,
            )));
            let now = Instant::now();
            let remaining_duration = if now < self.approval_expiry_time {
                self.approval_expiry_time - now
            } else {
                Duration::from_secs(0)
            };
            info!(
                "{} {} {}/{} seconds remaining.",
                log_ident,
                self.response_progress(),
                remaining_duration.display_secs(),
                self.approval_timeout_secs
            );

            Some(Transition::Stay)
        } else {
            // Token not recognised: try other handlers
            None
        }
    }

    fn handle_approval_timeout(&mut self, log_ident: String, outbox: &mut EventBox) {
        let completed = self.response_parts
            .values()
            .filter(|parts| parts.is_empty())
            .count();
        if completed == self.challenger_count {
            info!(
                "{} All {} resource proof responses fully sent, but timed out waiting \
                   for approval from the network. This could be due to the target section \
                   experiencing churn. Terminating node.",
                log_ident,
                completed
            );
        } else {
            info!(
                "{} Failed to get approval from the network. {} Terminating node.",
                log_ident,
                self.response_progress()
            );
        }
        outbox.send_event(Event::Terminate);
    }

    // For the ongoing collection of `ResourceProofResponse` messages, returns a tuple comprising:
    // the `part_count` they all use; the number of fully-completed ones; a vector for the
    // incomplete ones specifying how many parts have been sent to each peer; and a `String`
    // containing this info.
    fn response_progress(&self) -> String {
        let mut parts_per_proof = 0;
        let mut completed: usize = 0;
        let mut incomplete = vec![];
        for messages in self.response_parts.values() {
            if let Some(next_message) = messages.last() {
                match *next_message {
                    DirectMessage::ResourceProofResponse {
                        part_index,
                        part_count,
                        ..
                    } => {
                        parts_per_proof = part_count;
                        incomplete.push(part_index);
                    }
                    _ => return String::new(),  // invalid situation
                }
            } else {
                completed += 1;
            }
        }

        if self.response_parts.is_empty() {
            "No resource proof challenges received yet; still establishing connections to peers."
                .to_string()
        } else if self.challenger_count == completed {
            format!("All {} resource proof responses fully sent.", completed)
        } else {
            let progress = if parts_per_proof == 0 {
                // We've completed all challenges for those peers we've connected to, but are still
                // waiting to connect to some more peers and receive their challenges.
                completed * 100 / self.challenger_count
            } else {
                (((parts_per_proof * completed) + incomplete.iter().sum::<usize>()) * 100) /
                    (parts_per_proof * self.challenger_count)
            };
            format!(
                "{}/{} resource proof response(s) complete, {}% of data sent.",
                completed,
                self.challenger_count,
                progress
            )
        }
    }
}

impl Drop for ResourceProver {
    fn drop(&mut self) {
        for &(ref atomic_cancel, _) in self.workers.values() {
            atomic_cancel.store(true, Ordering::Relaxed);
        }
    }
}
