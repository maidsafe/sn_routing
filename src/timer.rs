// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::time::{Duration, Instant};
use crossbeam_channel as mpmc;
use itertools::Itertools;
#[cfg(feature = "mock")]
use std::cell::RefCell;
#[cfg(not(feature = "mock"))]
use std::thread;
use std::{cell::Cell, collections::BTreeMap};

struct Detail {
    expiry: Instant,
    token: u64,
}

/// Simple timer.
pub struct Timer {
    next_token: Cell<u64>,
    tx: mpmc::Sender<Detail>,

    #[cfg(feature = "mock")]
    worker: Worker,
}

impl Timer {
    /// Creates a new timer, passing a channel sender used to send timeouted tokens.
    #[cfg(not(feature = "mock"))]
    pub fn new(sender: mpmc::Sender<u64>) -> Self {
        let (tx, rx) = mpmc::bounded(1);
        let _ = thread::Builder::new()
            .name("Timer".to_string())
            .spawn(move || Self::run(sender, rx))
            .expect("failed to spawn timer thread");
        Self {
            next_token: Cell::new(0),
            tx,
        }
    }

    #[cfg(feature = "mock")]
    pub fn new(sender: mpmc::Sender<u64>) -> Self {
        let (tx, rx) = mpmc::unbounded();
        let worker = Worker {
            deadlines: RefCell::new(BTreeMap::default()),
            sender,
            rx,
        };

        Self {
            next_token: Cell::new(0),
            tx,
            worker,
        }
    }

    // TODO Do proper error handling here by returning a result - currently complying it with
    // existing code and logging and error
    /// Schedules a timeout event after `duration`. Returns a token that can be used to identify
    /// the timeout event.
    pub fn schedule(&self, duration: Duration) -> u64 {
        let token = self.next_token.get();
        self.next_token.set(token.wrapping_add(1));

        let detail = Detail {
            expiry: Instant::now() + duration,
            token,
        };
        self.tx.send(detail).map(|()| token).unwrap_or_else(|e| {
            error!("Timer could not be scheduled: {:?}", e);
            0
        })
    }

    #[cfg(not(feature = "mock"))]
    fn run(sender: mpmc::Sender<u64>, rx: mpmc::Receiver<Detail>) {
        let mut deadlines: BTreeMap<Instant, Vec<u64>> = Default::default();

        loop {
            let r = if let Some(t) = deadlines.keys().next() {
                let now = Instant::now();
                if *t > now {
                    let duration = *t - now;
                    match rx.recv_timeout(duration) {
                        Ok(d) => Some(d),
                        Err(mpmc::RecvTimeoutError::Timeout) => None,
                        Err(mpmc::RecvTimeoutError::Disconnected) => break,
                    }
                } else {
                    None
                }
            } else {
                match rx.recv() {
                    Ok(d) => Some(d),
                    Err(mpmc::RecvError) => break,
                }
            };

            if let Some(Detail { expiry, token }) = r {
                deadlines.entry(expiry).or_insert_with(Vec::new).push(token);
            }

            process_deadlines(&mut deadlines, &sender);
        }
    }

    #[cfg(feature = "mock")]
    pub fn process_timers(&self) {
        self.worker.process()
    }
}

fn process_deadlines(deadlines: &mut BTreeMap<Instant, Vec<u64>>, sender: &mpmc::Sender<u64>) {
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
            let _ = sender.send(token);
        }
    }
}

#[cfg(feature = "mock")]
struct Worker {
    deadlines: RefCell<BTreeMap<Instant, Vec<u64>>>,
    sender: mpmc::Sender<u64>,
    rx: mpmc::Receiver<Detail>,
}

#[cfg(feature = "mock")]
impl Worker {
    fn process(&self) {
        let mut deadlines = self.deadlines.borrow_mut();

        while let Ok(Detail { expiry, token }) = self.rx.try_recv() {
            deadlines.entry(expiry).or_insert_with(Vec::new).push(token);
        }

        process_deadlines(&mut *deadlines, &self.sender);
    }
}

#[cfg(all(test, not(feature = "mock")))]
mod tests {
    use super::*;
    use std::{
        thread,
        time::{Duration, Instant},
    };

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

                let token = action_rx
                    .try_recv()
                    .expect("Should have received a timer token.");
                assert_eq!(token, u64::from(count - i - 1));
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
        let (tx, rx) = mpmc::unbounded();
        let timer = Timer::new(tx);
        let count = 1000;

        for _ in 0..count {
            let _ = timer.schedule(Duration::new(0, 3000));
        }

        assert_eq!(rx.iter().take(count).count(), count);
    }
}
