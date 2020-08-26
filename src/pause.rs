// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    consensus::VoteAccumulator,
    id::FullId,
    message_filter::MessageFilter,
    messages::{MessageAccumulator, QueuedMessage},
    network_params::NetworkParams,
    section::{SectionKeysProvider, SectionUpdateBarrier, SharedState},
    transport::Transport,
    TransportEvent,
};
use bytes::Bytes;
use crossbeam_channel as mpmc;
use std::collections::VecDeque;

/// A type that wraps the internal state of a node while it is paused in order to be upgraded and/or
/// restarted. A value of this type is obtained by pausing a node and can be then used to resume
/// it.
// TODO: this is just a placeholder for now which allows us to have the pause/resume API in place
// and have tests passing. To make it actually work for all its intended purposes, we need to make
// sure this type is serialisable/deserialisable in a forward compatible way - that is, we must be
// able to create a value of this type in routing version X and use it to resume the node in any
// version >= X.
pub struct PausedState {
    pub(super) network_params: NetworkParams,
    pub(super) shared_state: SharedState,
    pub(super) section_keys_provider: SectionKeysProvider,
    pub(super) full_id: FullId,
    pub(super) msg_filter: MessageFilter,
    pub(super) msg_queue: VecDeque<QueuedMessage>,
    // TODO: instead of storing both transport and network_rx, store only the network config.
    pub(super) transport: Transport,
    pub(super) transport_rx: Option<mpmc::Receiver<TransportEvent>>,
    pub(super) msg_accumulator: MessageAccumulator,
    pub(super) vote_accumulator: VoteAccumulator,
    pub(super) section_update_barrier: SectionUpdateBarrier,
    pub(super) relocate_promise: Option<Bytes>,
}
