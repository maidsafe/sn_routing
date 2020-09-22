// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::time::{Duration, Instant};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tokio::{
    self,
    sync::mpsc::{self, Receiver, Sender, UnboundedSender},
    time,
};

struct Detail {
    expiry: Instant,
    token: u64,
}

/// Simple timer.
/// Note: cloning is cheap and crates just another handle to the same underlying timer.
#[derive(Clone)]
pub struct Timer {
    next_token: Arc<AtomicU64>,
    schedule_tx: Sender<Detail>,
}

impl Timer {
    /// Creates a new timer, passing a channel sender used to send timeouted tokens.
    pub fn new(expire_tx: UnboundedSender<u64>) -> Self {
        let (schedule_tx, schedule_rx) = mpsc::channel(1);

        let _ = tokio::spawn(async move { Self::run(expire_tx, schedule_rx).await });

        Self {
            next_token: Arc::new(AtomicU64::new(0)),
            schedule_tx,
        }
    }

    /// Schedules a timeout event after `duration`. Returns a token that can be used to identify
    /// the timeout event.
    pub async fn schedule(&mut self, duration: Duration) -> u64 {
        let token = self.next_token.fetch_add(1, Ordering::Relaxed);

        let detail = Detail {
            expiry: Instant::now() + duration,
            token,
        };

        if self.schedule_tx.send(detail).await.is_ok() {
            token
        } else {
            error!("Timer could not be scheduled");
            0
        }
    }

    // #[cfg(not(feature = "mock"))]
    async fn run(mut expire_tx: UnboundedSender<u64>, mut schedule_rx: Receiver<Detail>) {
        let mut deadlines: BTreeMap<Instant, Vec<u64>> = Default::default();

        loop {
            let r = if let Some(t) = deadlines.keys().next() {
                let now = Instant::now();
                if *t > now {
                    let duration = *t - now;
                    match time::timeout(duration, schedule_rx.recv()).await {
                        Ok(Some(detail)) => Some(detail),
                        Ok(None) => break,
                        Err(_) => None,
                    }
                } else {
                    None
                }
            } else {
                match schedule_rx.recv().await {
                    Some(detail) => Some(detail),
                    None => break,
                }
            };

            if let Some(Detail { expiry, token }) = r {
                deadlines.entry(expiry).or_insert_with(Vec::new).push(token);
            }

            process_deadlines(&mut deadlines, &mut expire_tx);
        }
    }
}

fn process_deadlines(deadlines: &mut BTreeMap<Instant, Vec<u64>>, tx: &mut UnboundedSender<u64>) {
    let now = Instant::now();
    let expired_list: Vec<_> = deadlines
        .keys()
        .take_while(|&&deadline| deadline < now)
        .copied()
        .collect();
    for expired in expired_list {
        for token in deadlines.remove(&expired).into_iter().flatten() {
            let _ = tx.send(token);
        }
    }
}

#[cfg(all(test, not(feature = "mock")))]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn schedule() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let interval = Duration::from_millis(500);
        let instant_when_added;

        {
            let mut timer = Timer::new(tx);

            // Add deadlines, the first to time out after 2.5s, the second after 2.0s, and so on
            // down to 500ms.
            let count = 5;
            for i in 0..count {
                let timeout = interval * (count - i);
                let token = timer.schedule(timeout).await;
                assert_eq!(token, u64::from(i));
            }

            // Ensure timeout notifications are received correctly.
            time::delay_for(Duration::from_millis(100)).await;
            for i in 0..count {
                assert!(rx.try_recv().is_err());
                time::delay_for(interval).await;

                let token = rx.try_recv().expect("Should have received a timer token.");
                assert_eq!(token, u64::from(count - i - 1));
            }

            // Add deadline and check that dropping `timer` doesn't fire a timeout notification,
            // and that dropping doesn't block until the deadline has expired.
            instant_when_added = Instant::now();
            let _ = timer.schedule(interval);
        }

        assert!(instant_when_added.elapsed() < interval);

        time::delay_for(interval + Duration::from_millis(100)).await;
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn heavy_duty_time_out() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut timer = Timer::new(tx);
        let num_scheduled: usize = 1000;

        for _ in 0..num_scheduled {
            let _ = timer.schedule(Duration::from_millis(100)).await;
        }

        let run = async {
            let mut num_expired = 0;
            while let Some(_) = rx.recv().await {
                num_expired += 1;

                if num_expired >= num_scheduled {
                    break;
                }
            }

            num_expired
        };

        match time::timeout(Duration::from_millis(500), run).await {
            Ok(num_expired) => {
                assert_eq!(num_expired, num_scheduled);
                assert!(rx.try_recv().is_err());
            }
            Err(_) => panic!("timeout"),
        }
    }
}
