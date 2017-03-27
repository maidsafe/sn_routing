// Copyright 2016 MaidSafe.net limited.
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

pub use self::implementation::Timer;

#[cfg(not(feature = "use-mock-crust"))]
mod implementation {
    use action::Action;
    use itertools::Itertools;
    use maidsafe_utilities::thread;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};
    use types::RoutingActionSender;

    struct Detail {
        next_token: u64,
        deadlines: BTreeMap<Instant, Vec<u64>>,
        use_count: u32,
    }

    /// A device for scheduling wake-ups, delivered via a message sender. This device can be
    /// cloned with all wakeups sent via the same sender.
    ///
    /// The worker thread terminates when all associated `Timer` devices are destroyed.
    pub struct Timer {
        detail_and_cond_var: Arc<(Mutex<Detail>, Condvar)>,
    }

    impl Timer {
        /// Creates a new timer, passing a channel sender used to send `Timeout` events.
        pub fn new(sender: RoutingActionSender) -> Self {
            let detail = Detail {
                next_token: 0,
                deadlines: BTreeMap::new(),
                use_count: 1,
            };
            let detail_and_cond_var = Arc::new((Mutex::new(detail), Condvar::new()));
            let detail_and_cond_var_clone = detail_and_cond_var.clone();

            let worker = thread::named("Timer", move || Self::run(sender, detail_and_cond_var));
            // TODO: confirm whether it is reasonable to disown the worker like this. Rationale is
            // that it allows `Timer` to be cloned without a separate `Joiner`.
            worker.detach();

            Timer { detail_and_cond_var: detail_and_cond_var_clone }
        }

        /// Schedules a timeout event after `duration`. Returns a token that can be used to identify
        /// the timeout event.
        pub fn schedule(&mut self, duration: Duration) -> u64 {
            let &(ref mutex, ref cond_var) = &*self.detail_and_cond_var;
            let mut detail = mutex.lock().expect("Failed to lock.");
            let token = detail.next_token;
            detail.next_token = token.wrapping_add(1);
            detail.deadlines
                .entry(Instant::now() + duration)
                .or_insert_with(Vec::new)
                .push(token);
            cond_var.notify_one();
            token
        }

        fn run(sender: RoutingActionSender, detail_and_cond_var: Arc<(Mutex<Detail>, Condvar)>) {
            let &(ref mutex, ref cond_var) = &*detail_and_cond_var;
            let mut detail = mutex.lock().expect("Failed to lock.");
            // We could _almost_ use Arc::strong_count(&detail_and_cond_var) instead of use_count
            // here, except that Timer::drop() could not decrement the count before calling
            // cond_var.notify_one().
            while detail.use_count > 0 {
                // Handle expired deadlines.
                let now = Instant::now();
                let expired_list = detail.deadlines
                    .keys()
                    .take_while(|&&deadline| deadline < now)
                    .cloned()
                    .collect_vec();
                for expired in expired_list {
                    // Safe to call `expect()` as we just got the key we're removing from
                    // `deadlines`.
                    let tokens = detail.deadlines.remove(&expired).expect("Bug in `BTreeMap`.");
                    for token in tokens {
                        let _ = sender.send(Action::Timeout(token));
                    }
                }

                // If we have no deadlines pending, wait indefinitely.  Otherwise wait until the
                // nearest deadline.
                if detail.deadlines.is_empty() {
                    detail = cond_var.wait(detail).expect("Failed to lock.");
                } else {
                    // Safe to call `expect()` as `deadlines` has at least one entry.
                    let nearest = detail.deadlines
                        .keys()
                        .next()
                        .cloned()
                        .expect("Bug in `BTreeMap`.");
                    let duration = nearest - now;
                    detail = cond_var.wait_timeout(detail, duration).expect("Failed to lock.").0;
                }
            }
        }
    }

    impl Clone for Timer {
        fn clone(&self) -> Self {
            let &(ref mutex, _) = &*self.detail_and_cond_var;
            let mut detail = mutex.lock().expect("Failed to lock.");
            detail.use_count += 1;
            Timer { detail_and_cond_var: self.detail_and_cond_var.clone() }
        }
    }

    impl Drop for Timer {
        fn drop(&mut self) {
            let &(ref mutex, ref cond_var) = &*self.detail_and_cond_var;
            let mut detail = mutex.lock().expect("Failed to lock.");
            detail.use_count -= 1;
            cond_var.notify_one();
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use action::Action;
        use maidsafe_utilities::event_sender::MaidSafeEventCategory;
        use std::sync::mpsc;
        use std::thread;
        use std::time::{Duration, Instant};
        use types::RoutingActionSender;

        #[test]
        fn schedule() {
            let (action_sender, action_receiver) = mpsc::channel();
            let (category_sender, category_receiver) = mpsc::channel();
            let routing_event_category = MaidSafeEventCategory::Routing;
            let sender = RoutingActionSender::new(action_sender,
                                                  routing_event_category,
                                                  category_sender.clone());
            let interval = Duration::from_millis(500);
            let instant_when_added;
            let check_no_events_received = || {
                let category = category_receiver.try_recv();
                assert!(category.is_err(),
                        "Expected no event, but received {:?}",
                        category);
                let action = action_receiver.try_recv();
                assert!(action.is_err(),
                        "Expected no event, but received {:?}",
                        action);
            };
            {
                let mut timer = Timer::new(sender);
                let mut timer2 = timer.clone();

                // Add deadlines, the first to time out after 2.5s, the second after 2.0s, and so on
                // down to 500ms.
                let count = 5;
                for i in 0..count {
                    let timeout = interval * (count - i);
                    let token = timer.schedule(timeout);
                    assert_eq!(token, i as u64);
                }

                // Ensure timeout notifications are received correctly.
                thread::sleep(Duration::from_millis(100));
                for i in 0..count {
                    check_no_events_received();
                    thread::sleep(interval);

                    let category = category_receiver.try_recv();
                    match category.expect("Should have received a category.") {
                        MaidSafeEventCategory::Routing => (),
                        unexpected_category => {
                            panic!("Expected `MaidSafeEventCategory::Routing`, but received {:?}",
                                   unexpected_category);
                        }
                    }
                    let action = action_receiver.try_recv();
                    match action.expect("Should have received an action.") {
                        Action::Timeout(token) => assert_eq!(token, (count - i - 1) as u64),
                        unexpected_action => {
                            panic!("Expected `Action::Timeout`, but received {:?}",
                                   unexpected_action);
                        }
                    }
                }

                // Add deadline and check that dropping `timer` doesn't fire a timeout notification,
                // and that dropping doesn't block until the deadline has expired.
                instant_when_added = Instant::now();
                let _ = timer2.schedule(interval);
            }

            assert!(Instant::now() - instant_when_added < interval,
                    "`Timer::drop()` is blocking.");

            thread::sleep(interval + Duration::from_millis(100));
            check_no_events_received();
        }
    }
}

#[cfg(feature = "use-mock-crust")]
mod implementation {
    use std::time::Duration;

    use types::RoutingActionSender;

    // The mock timer currently never raises timeout events.
    pub struct Timer {
        next_token: u64,
    }

    impl Timer {
        pub fn new(_: RoutingActionSender) -> Self {
            Timer { next_token: 0 }
        }

        pub fn schedule(&mut self, _: Duration) -> u64 {
            let token = self.next_token;
            self.next_token = token.wrapping_add(1);
            token
        }
    }
}
