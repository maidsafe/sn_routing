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
    use maidsafe_utilities::thread::{self, Joiner};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;
    use std::sync::mpsc::{self, Receiver, RecvError, RecvTimeoutError, SyncSender};
    use std::time::{Duration, Instant};
    use types::RoutingActionSender;

    struct Detail {
        expiry: Instant,
        token: u64,
    }

    /// Simple timer.
    #[derive(Clone)]
    pub struct Timer {
        inner: Rc<RefCell<Inner>>,
    }

    struct Inner {
        next_token: u64,
        tx: SyncSender<Detail>,
        _worker: Joiner,
    }

    impl Timer {
        /// Creates a new timer, passing a channel sender used to send `Timeout` events.
        pub fn new(sender: RoutingActionSender) -> Self {
            let (tx, rx) = mpsc::sync_channel(1);

            let worker = thread::named("Timer", move || Self::run(sender, rx));

            Timer {
                inner: Rc::new(RefCell::new(Inner {
                    next_token: 0,
                    tx: tx,
                    _worker: worker,
                })),
            }
        }

        // TODO Do proper error handling here by returning a result - currently complying it with
        // existing code and logging and error
        /// Schedules a timeout event after `duration`. Returns a token that can be used to identify
        /// the timeout event.
        pub fn schedule(&self, duration: Duration) -> u64 {
            let mut inner = self.inner.borrow_mut();

            let token = inner.next_token;
            inner.next_token = token.wrapping_add(1);

            let detail = Detail {
                expiry: Instant::now() + duration,
                token: token,
            };
            inner.tx.send(detail).map(|()| token).unwrap_or_else(|e| {
                error!("Timer could not be scheduled: {:?}", e);
                0
            })
        }

        fn run(sender: RoutingActionSender, rx: Receiver<Detail>) {
            let mut deadlines: BTreeMap<Instant, Vec<u64>> = Default::default();

            loop {
                let r = if let Some(t) = deadlines.keys().next() {
                    let now = Instant::now();
                    if *t > now {
                        let duration = *t - now;
                        match rx.recv_timeout(duration) {
                            Ok(d) => Some(d),
                            Err(RecvTimeoutError::Timeout) => None,
                            Err(RecvTimeoutError::Disconnected) => break,
                        }
                    } else {
                        None
                    }
                } else {
                    match rx.recv() {
                        Ok(d) => Some(d),
                        Err(RecvError) => break,
                    }
                };

                if let Some(Detail { expiry, token }) = r {
                    deadlines.entry(expiry).or_insert_with(Vec::new).push(token);
                }

                let now = Instant::now();
                let expired_list = deadlines
                    .keys()
                    .take_while(|&&deadline| deadline < now)
                    .cloned()
                    .collect_vec();
                for expired in expired_list {
                    // Safe to call `expect()` as we just got the key we're removing from
                    // `deadlines`.
                    let tokens = deadlines.remove(&expired).expect("Bug in `BTreeMap`.");
                    for token in tokens {
                        let _ = sender.send(Action::Timeout(token));
                    }
                }
            }
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
            let sender = RoutingActionSender::new(
                action_sender,
                routing_event_category,
                category_sender.clone(),
            );
            let interval = Duration::from_millis(500);
            let instant_when_added;
            let check_no_events_received = || {
                let category = category_receiver.try_recv();
                assert!(
                    category.is_err(),
                    "Expected no event, but received {:?}",
                    category
                );
                let action = action_receiver.try_recv();
                assert!(
                    action.is_err(),
                    "Expected no event, but received {:?}",
                    action
                );
            };
            {
                let timer = Timer::new(sender);

                // Add deadlines, the first to time out after 2.5s, the second after 2.0s, and so on
                // down to 500ms.
                let count = 5;
                for i in 0..count {
                    let timeout = interval * (count - i);
                    let token = timer.schedule(timeout);
                    assert_eq!(token, u64::from(i));
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
                            panic!(
                                "Expected `MaidSafeEventCategory::Routing`, but received {:?}",
                                unexpected_category
                            );
                        }
                    }
                    let action = action_receiver.try_recv();
                    match action.expect("Should have received an action.") {
                        Action::Timeout(token) => assert_eq!(token, u64::from(count - i - 1)),
                        unexpected_action => {
                            panic!(
                                "Expected `Action::Timeout`, but received {:?}",
                                unexpected_action
                            );
                        }
                    }
                }

                // Add deadline and check that dropping `timer` doesn't fire a timeout notification,
                // and that dropping doesn't block until the deadline has expired.
                instant_when_added = Instant::now();
                let _ = timer.schedule(interval);
            }

            assert!(
                Instant::now() - instant_when_added < interval,
                "`Timer::drop()` is blocking."
            );

            thread::sleep(interval + Duration::from_millis(100));
            check_no_events_received();
        }

        #[test]
        fn heavy_duty_time_out() {
            let (action_sender, _action_receiver) = mpsc::channel();
            let (category_sender, _category_receiver) = mpsc::channel();
            let routing_event_category = MaidSafeEventCategory::Routing;
            let sender = RoutingActionSender::new(
                action_sender,
                routing_event_category,
                category_sender.clone(),
            );
            let timer = Timer::new(sender);
            for _ in 0..1000 {
                let _ = timer.schedule(Duration::new(0, 3000));
            }
        }
    }
}

#[cfg(feature = "use-mock-crust")]
mod implementation {
    use fake_clock::FakeClock as Instant;
    use itertools::Itertools;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;
    use std::time::Duration;
    use types::RoutingActionSender;

    struct Inner {
        next_token: u64,
        deadlines: BTreeMap<Instant, Vec<u64>>,
    }

    #[derive(Clone)]
    pub struct Timer {
        inner: Rc<RefCell<Inner>>,
    }

    impl Timer {
        pub fn new(_action_sender: RoutingActionSender) -> Self {
            Timer {
                inner: Rc::new(RefCell::new(Inner {
                    next_token: 0,
                    deadlines: Default::default(),
                })),
            }
        }

        pub fn schedule(&self, duration: Duration) -> u64 {
            let mut inner = self.inner.borrow_mut();

            let token = inner.next_token;
            inner.next_token = token.wrapping_add(1);

            inner
                .deadlines
                .entry(Instant::now() + duration)
                .or_insert_with(Vec::new)
                .push(token);
            token
        }

        pub fn get_timed_out_tokens(&mut self) -> Vec<u64> {
            let mut inner = self.inner.borrow_mut();
            let now = Instant::now();
            let expired_list = inner
                .deadlines
                .keys()
                .take_while(|&&deadline| deadline < now)
                .cloned()
                .collect_vec();
            let mut expired_tokens = Vec::new();
            for expired in expired_list {
                // Safe to call `unwrap!()` as we just got the key we're removing from
                // `deadlines`.
                let tokens = unwrap!(inner.deadlines.remove(&expired));
                expired_tokens.extend(tokens);
            }
            expired_tokens
        }
    }
}
