// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Log identifier - a short string that is prefixed in front of every log message.

use std::{future::Future, sync::Arc};

tokio::task_local! {
    static LOG_IDENT: Arc<String>;
}

/// Set the log identifier for the current task.
pub async fn set<F>(ident: String, f: F) -> F::Output
where
    F: Future,
{
    LOG_IDENT.scope(Arc::new(ident), f).await
}

/// Get the current log identifier.
pub fn get() -> Arc<String> {
    LOG_IDENT
        .try_with(|ident| ident.clone())
        .unwrap_or_default()
}
