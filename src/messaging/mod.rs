// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// Length of the GUID (unique ID) of a message (16 bytes).
pub const GUID_SIZE: usize = 16;
/// Maximum allowed inbox size for an account (128 MiB).
pub const MAX_INBOX_SIZE: usize = 1 << 27;
/// Maximum allowed outbox size for an account (128 MiB).
pub const MAX_OUTBOX_SIZE: usize = 1 << 27;

mod error;
mod mpid_header;
mod mpid_message;
mod mpid_message_wrapper;

pub use self::error::Error;
pub use self::mpid_header::{MpidHeader, MAX_HEADER_METADATA_SIZE};
pub use self::mpid_message::{MpidMessage, MAX_BODY_SIZE};
pub use self::mpid_message_wrapper::MpidMessageWrapper;

#[cfg(test)]
fn generate_random_bytes(size: usize) -> Vec<u8> {
    use rand::Rng;
    rand::thread_rng().gen_iter().take(size).collect()
}
