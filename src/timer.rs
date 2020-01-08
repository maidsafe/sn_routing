// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action,
    time::{Duration, Instant},
};
use crossbeam_channel as mpmc;
use itertools::Itertools;
#[cfg(not(feature = "mock_base"))]
use maidsafe_utilities::thread::{self, Joiner};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc, sync::mpsc};

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

    #[cfg(not(feature = "mock_base"))]
    tx: mpsc::SyncSender<Detail>,
    #[cfg(not(feature = "mock_base"))]
    _worker: Joiner,

    #[cfg(feature = "mock_base")]
    tx: mpsc::Sender<Detail>,
    #[cfg(feature = "mock_base")]
    _worker: Box<dyn FnMut()>,
}

impl Timer {
    /// Creates a new timer, passing a channel sender used to send `Timeout` events.
    pub fn new(sender: mpmc::Sender<Action>) -> Self {
        #[cfg(not(feature = "mock_base"))]
        let (tx, worker) = {
            let (tx, rx) = mpsc::sync_channel(1);
            let worker = thread::named("Timer", move || Self::run(sender, rx));
            (tx, worker)
        };

        #[cfg(feature = "mock_base")]
        let (tx, worker) = {
            let (tx, mut rx) = mpsc::channel();
            let mut deadlines = BTreeMap::default();
            let worker =
                Box::new(move || Self::do_process_timers(&mut deadlines, &sender, &mut rx));
            (tx, worker)
        };

        Self {
            inner: Rc::new(RefCell::new(Inner {
                next_token: 0,
                tx,
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
            token,
        };
        inner.tx.send(detail).map(|()| token).unwrap_or_else(|e| {
            error!("Timer could not be scheduled: {:?}", e);
            0
        })
    }

    #[cfg(not(feature = "mock_base"))]
    fn run(sender: mpmc::Sender<Action>, rx: mpsc::Receiver<Detail>) {
        let mut deadlines: BTreeMap<Instant, Vec<u64>> = Default::default();

        loop {
            let r = if let Some(t) = deadlines.keys().next() {
                let now = Instant::now();
                if *t > now {
                    let duration = *t - now;
                    match rx.recv_timeout(duration) {
                        Ok(d) => Some(d),
                        Err(mpsc::RecvTimeoutError::Timeout) => None,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                } else {
                    None
                }
            } else {
                match rx.recv() {
                    Ok(d) => Some(d),
                    Err(mpsc::RecvError) => break,
                }
            };

            if let Some(Detail { expiry, token }) = r {
                deadlines.entry(expiry).or_insert_with(Vec::new).push(token);
            }

            Self::process_deadlines(&mut deadlines, &sender);
        }
    }

    fn process_deadlines(
        deadlines: &mut BTreeMap<Instant, Vec<u64>>,
        sender: &mpmc::Sender<Action>,
    ) {
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
                let _ = sender.send(Action::HandleTimeout(token));
            }
        }
    }

    #[cfg(feature = "mock_base")]
    pub fn process_timers(&self) {
        let mut inner = self.inner.borrow_mut();
        let process_timers = &mut *inner._worker;
        process_timers();
    }

    #[cfg(feature = "mock_base")]
    fn do_process_timers(
        deadlines: &mut BTreeMap<Instant, Vec<u64>>,
        sender: &mpmc::Sender<Action>,
        rx: &mut mpsc::Receiver<Detail>,
    ) {
        while let Ok(Detail { expiry, token }) = rx.try_recv() {
            deadlines.entry(expiry).or_insert_with(Vec::new).push(token);
        }

        Self::process_deadlines(deadlines, sender);
    }
}

#[cfg(all(test, not(feature = "mock_base")))]
mod tests {
    use super::*;
    use crate::action::Action;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn schedule() {
        let (action_tx, action_rx) = mpmc::unbounded();
        let interval = Duration::from_millis(500);
        let instant_when_added;
        let check_no_events_received = || {
            let action = action_rx.try_recv();
            assert!(
                action.is_err(),
                "Expected no event, but received {:?}",
                action
            );
        };
        {
            let timer = Timer::new(action_tx);

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

                let action = action_rx.try_recv();
                match action.expect("Should have received an action.") {
                    Action::HandleTimeout(token) => assert_eq!(token, u64::from(count - i - 1)),
                    unexpected_action => {
                        panic!(
                            "Expected `Action::HandleTimeout`, but received {:?}",
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
        let (action_tx, _) = mpmc::unbounded();
        let timer = Timer::new(action_tx);
        for _ in 0..1000 {
            let _ = timer.schedule(Duration::new(0, 3000));
        }
    }
}
