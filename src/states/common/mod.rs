// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod base;

pub use self::base::Base;
use crate::{
    id::FullId, message_filter::MessageFilter, network_service::NetworkService, rng::MainRng,
    time::Duration, timer::Timer,
};

/// Delay after which a bounced message is resent.
pub const BOUNCE_RESEND_DELAY: Duration = Duration::from_secs(1);

/// Struct that contains data common to all states.
pub struct Core {
    pub full_id: FullId,
    pub network_service: NetworkService,
    pub msg_filter: MessageFilter,
    pub timer: Timer,
    pub rng: MainRng,
}
