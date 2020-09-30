// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Cancellable futures
//!
//! A simple mechanism for creating futures that can be cancelled remotely (e.g., from another task).
//!
//! To make a future cancellable, first create a (`CancellableHandle`, `CancellableToken`) pair,
//! then pass the future to the `cancellable` function, together with the token. To cancel the
//! future, simply drop the handle. The token is cloneable, so multiple futures can be cancelled
//! using a single handle. The token implements `Send`, so this mechanism can be used to cancel a
//! future running in a different task/thread.
//!
//! Example:
//!
//! ```ignore
//! let (handle, token) = CancellationHandle::new();
//! let future = cancellable(token, async { true });
//! drop(handle);
//! assert_eq!(future.await, Err(Cancelled));
//! ```

use std::{
    fmt::{self, Display, Formatter},
    future::Future,
    sync::Arc,
};
use tokio::sync::{Mutex, OwnedMutexGuard};

/// Handle that can be used to cancel a running future. The cancellation is triggered by dropping
/// this handle.
pub struct CancellationHandle(OwnedMutexGuard<()>);

impl CancellationHandle {
    /// Creates a (`CancellationHandle`, `CancellationToken`) pair that can be used to cancel a
    /// running future.
    pub fn new() -> (Self, CancellationToken) {
        let mutex = Arc::new(Mutex::new(()));
        let guard = mutex
            .clone()
            .try_lock_owned()
            .expect("the mutex shouldn't be locked yet");

        (Self(guard), CancellationToken(mutex))
    }
}

/// A token to create `cancellable` future. Can be cheaply cloned, so one `CancellationHandle` can
/// be used to cancel multiple futures.
#[derive(Clone)]
pub struct CancellationToken(Arc<Mutex<()>>);

/// Create a future that can be cancelled remotely (from another task) using a `CancellationHandle`
/// that corresponds to the given `CancellationToken`.
pub async fn cancellable<F: Future>(
    token: CancellationToken,
    future: F,
) -> Result<F::Output, Cancelled> {
    tokio::select! {
        value = future => Ok(value),
        _ = token.0.lock() => Err(Cancelled),
    }
}

/// Indicator that the `cancellable` future was cancelled.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Cancelled;

impl Display for Cancelled {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "future has been cancelled")
    }
}

impl std::error::Error for Cancelled {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancel() {
        let (handle, token) = CancellationHandle::new();
        let future = cancellable(token, tokio::task::yield_now());
        drop(handle);
        assert_eq!(future.await, Err(Cancelled));
    }

    #[tokio::test]
    async fn dont_cancel() {
        let (_handle, token) = CancellationHandle::new();
        let future = cancellable(token, tokio::task::yield_now());
        assert_eq!(future.await, Ok(()));
    }
}
