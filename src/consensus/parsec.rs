// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    consensus::{AccumulatingEvent, NetworkEvent},
    id::{FullId, PublicId},
    messages::Variant,
    rng::{self, MainRng},
    section::EldersInfo,
    time::Duration,
};
#[cfg(feature = "mock")]
use crate::{crypto, mock::parsec as inner};
#[cfg(not(feature = "mock"))]
use parsec as inner;
#[cfg(all(test, feature = "mock"))]
use std::collections::BTreeSet;
use std::{
    collections::{btree_map::Entry, BTreeMap},
    env,
    fmt::{self, Display},
    str::FromStr,
};

#[cfg(feature = "mock")]
pub use crate::mock::parsec::{
    init_mock, ConsensusMode, Error, NetworkEvent as ParsecNetworkEvent, Observation, Proof,
    SecretId,
};
#[cfg(not(feature = "mock"))]
pub use parsec::{
    ConsensusMode, Error, NetworkEvent as ParsecNetworkEvent, Observation, Proof, SecretId,
};

pub type Block = inner::Block<NetworkEvent, PublicId>;
pub type Parsec = inner::Parsec<NetworkEvent, FullId>;
pub type Request = inner::Request<NetworkEvent, PublicId>;
pub type Response = inner::Response<NetworkEvent, PublicId>;

// The maximum number of parsec instances to store.
const MAX_PARSECS: usize = 10;

// Limit in production
#[cfg(not(feature = "mock_base"))]
const PARSEC_SIZE_LIMIT: u64 = 1_000_000_000;
// Limit in integration tests
#[cfg(all(feature = "mock_base", not(feature = "mock")))]
const PARSEC_SIZE_LIMIT: u64 = 20_000_000;
// Limit for integration tests with mock-parsec
#[cfg(feature = "mock")]
const PARSEC_SIZE_LIMIT: u64 = 500;

/// Period within which the number of sent gossip messages is limited. When the period ends, the
/// limit resets at a new period starts.
pub const GOSSIP_PERIOD: Duration = Duration::from_secs(1);

// Maximum number of gossip messages a node can send within one gossip period.
const GOSSIP_LIMIT: usize = 5;

// Keep track of size in case we need to prune.
#[derive(Default, Debug, PartialEq, Eq)]
struct ParsecSizeCounter {
    size_counter: u64,
    pruning_voted_for: bool,
}

impl ParsecSizeCounter {
    fn increase_size(&mut self, size: u64) {
        self.size_counter += size;
    }

    fn needs_pruning(&self) -> bool {
        self.size_counter > PARSEC_SIZE_LIMIT && !self.pruning_voted_for
    }

    fn set_pruning_voted_for(&mut self) {
        self.pruning_voted_for = true;
    }
}

impl Display for ParsecSizeCounter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.size_counter)
    }
}

pub struct ParsecMap {
    map: BTreeMap<u64, Parsec>,
    size_counter: ParsecSizeCounter,
    send_gossip: bool,
    // Number of gossip messages we sent within this gossip period.
    gossip_count: usize,

    gossip_limit: usize,
    gossip_period: Duration,
}

impl Default for ParsecMap {
    fn default() -> Self {
        let gossip_limit = parse_env_var("ROUTING_GOSSIP_LIMIT").unwrap_or(GOSSIP_LIMIT);
        let gossip_period = parse_env_var("ROUTING_GOSSIP_PERIOD")
            .map(Duration::from_millis)
            .unwrap_or(GOSSIP_PERIOD);

        Self {
            map: Default::default(),
            size_counter: Default::default(),
            send_gossip: false,
            gossip_count: 0,
            gossip_limit,
            gossip_period,
        }
    }
}

impl ParsecMap {
    pub fn init(
        &mut self,
        rng: &mut MainRng,
        full_id: FullId,
        elders_info: &EldersInfo,
        serialised_state: Vec<u8>,
        parsec_version: u64,
    ) {
        self.add_new(rng, full_id, elders_info, serialised_state, parsec_version);
        self.remove_old();
    }

    pub fn handle_request(
        &mut self,
        msg_version: u64,
        request: Request,
        pub_id: PublicId,
    ) -> Option<Variant> {
        // Increase the size before fetching the parsec to satisfy the borrow checker
        let ser_size = if let Ok(size) = bincode::serialized_size(&request) {
            size
        } else {
            return None;
        };
        self.count_size(ser_size, msg_version);

        let parsec = self.map.get_mut(&msg_version)?;

        match parsec.handle_request(&pub_id, request) {
            Ok(response) => {
                // Check gossip termination condition - if there are no more unpolled observations
                // in our parsec instance we can stop gossiping.
                if msg_version == self.last_version() && self.has_unpolled_observations() {
                    self.send_gossip = true;
                }

                Some(Variant::ParsecResponse(msg_version, response))
            }
            Err(err) => {
                debug!("Error handling parsec request: {:?}", err);
                None
            }
        }
    }

    pub fn handle_response(&mut self, msg_version: u64, response: Response, pub_id: PublicId) {
        // Increase the size before fetching the parsec to satisfy the borrow checker
        let ser_size = if let Ok(size) = bincode::serialized_size(&response) {
            size
        } else {
            return;
        };
        self.count_size(ser_size, msg_version);

        let parsec = if let Some(parsec) = self.map.get_mut(&msg_version) {
            parsec
        } else {
            return;
        };

        if let Err(err) = parsec.handle_response(&pub_id, response) {
            debug!("Error handling parsec response: {:?}", err);
        }
    }

    pub fn create_gossip(
        &mut self,
        version: u64,
        target: &PublicId,
    ) -> Result<Variant, CreateGossipError> {
        let request = self
            .map
            .get_mut(&version)
            .ok_or(CreateGossipError::MissingVersion)?
            .create_gossip(target)?;

        if version == self.last_version() {
            self.gossip_count += 1;
        }

        Ok(Variant::ParsecRequest(version, request))
    }

    pub fn vote_for(&mut self, event: NetworkEvent) {
        trace!("Vote for Event {:?}", event);

        let prune = matches!(&event.payload, AccumulatingEvent::ParsecPrune);

        if let Some(parsec) = self.map.values_mut().last() {
            let obs = event.into_obs();

            match parsec.vote_for(obs) {
                Ok(()) => {
                    self.send_gossip = true;
                    if prune {
                        self.size_counter.set_pruning_voted_for();
                    }
                }
                Err(err) => trace!("Parsec vote error: {:?}", err),
            }
        }
    }

    // Enable test to simulate other members voting
    #[cfg(all(test, feature = "mock"))]
    pub fn vote_for_as(&mut self, obs: Observation<NetworkEvent, PublicId>, vote_id: &FullId) {
        if let Some(ref mut parsec) = self.map.values_mut().last() {
            parsec.vote_for_as(obs, vote_id)
        }
    }

    // Enable test to simulate other members signing and getting the right pk_set
    // TODO: remove this function as we no longer use parsec for DKG
    #[cfg(all(test, feature = "mock"))]
    pub fn get_dkg_result_as(
        &mut self,
        participants: BTreeSet<PublicId>,
        vote_id: &FullId,
    ) -> Option<parsec::DkgResult> {
        if let Some(ref mut parsec) = self.map.values_mut().last() {
            return Some(parsec.get_dkg_result_as(participants, vote_id));
        }
        None
    }

    pub fn last_version(&self) -> u64 {
        if let Some(version) = self.map.keys().last() {
            *version
        } else {
            log_or_panic!(log::Level::Error, "ParsecMap is empty.");
            0
        }
    }

    pub fn add_force_gossip_peer(&mut self, peer_id: &PublicId) {
        if let Some(ref mut parsec) = self.map.values_mut().last() {
            parsec.add_force_gossip_peer(peer_id)
        }
    }

    pub fn gossip_recipients(&self) -> Vec<&PublicId> {
        self.map
            .values()
            .last()
            .map(|parsec| parsec.gossip_recipients().collect())
            .unwrap_or_else(Vec::new)
    }

    pub fn poll(&mut self) -> Option<Block> {
        self.map.values_mut().last().and_then(Parsec::poll)
    }

    pub fn our_unpolled_observations(
        &self,
    ) -> impl Iterator<Item = &Observation<NetworkEvent, PublicId>> {
        self.map
            .values()
            .last()
            .map(Parsec::our_unpolled_observations)
            .into_iter()
            .flatten()
    }

    pub fn has_unpolled_observations(&self) -> bool {
        let parsec = if let Some(parsec) = self.map.values().last() {
            parsec
        } else {
            return false;
        };

        parsec.has_unpolled_observations()
    }

    pub fn needs_pruning(&self) -> bool {
        self.size_counter.needs_pruning()
    }

    // Returns whether we should send parsec gossip now.
    pub fn should_send_gossip(&mut self) -> bool {
        let send_gossip = self.send_gossip;
        self.send_gossip = false;

        if !send_gossip {
            return false;
        }

        if self.gossip_count >= self.gossip_limit {
            trace!("not sending parsec request: limit reached");
            return false;
        }

        true
    }

    pub fn gossip_period(&self) -> Duration {
        self.gossip_period
    }

    pub fn reset_gossip_period(&mut self) {
        self.gossip_count = 0;

        if self.has_unpolled_observations() {
            self.send_gossip = true;
        }
    }

    fn count_size(&mut self, size: u64, msg_version: u64) {
        if self.last_version() == msg_version && self.map.contains_key(&msg_version) {
            self.size_counter.increase_size(size);
            trace!(
                "Parsec size is now estimated to: {} / {}.",
                self.size_counter,
                PARSEC_SIZE_LIMIT,
            );
        }
    }

    fn add_new(
        &mut self,
        rng: &mut MainRng,
        full_id: FullId,
        elders_info: &EldersInfo,
        serialised_state: Vec<u8>,
        parsec_version: u64,
    ) {
        if let Entry::Vacant(entry) = self.map.entry(parsec_version) {
            let _ = entry.insert(create(
                rng,
                full_id,
                elders_info,
                serialised_state,
                parsec_version,
            ));
            self.size_counter = ParsecSizeCounter::default();
            info!("Init new Parsec v{}", parsec_version);
        }
    }

    fn remove_old(&mut self) {
        let parsec_map = std::mem::take(&mut self.map);
        self.map = parsec_map
            .into_iter()
            .rev()
            .take(MAX_PARSECS)
            .rev()
            .collect();
    }
}

/// Create Parsec instance.
fn create(
    rng: &mut MainRng,
    full_id: FullId,
    elders_info: &EldersInfo,
    serialised_state: Vec<u8>,
    #[cfg_attr(not(feature = "mock"), allow(unused))] parsec_version: u64,
) -> Parsec {
    #[cfg(feature = "mock")]
    let hash = {
        let fields = (elders_info.prefix, parsec_version);
        crypto::sha3_256(&bincode::serialize(&fields).unwrap())
    };

    if elders_info.elders.contains_key(full_id.public_id().name()) {
        Parsec::from_genesis(
            #[cfg(feature = "mock")]
            hash,
            full_id,
            &elders_info.elder_ids().copied().collect(),
            serialised_state,
            ConsensusMode::Single,
            Box::new(rng::new_from(rng)),
        )
    } else {
        let members = elders_info.elder_ids().copied().collect();

        Parsec::from_existing(
            #[cfg(feature = "mock")]
            hash,
            full_id,
            &members,
            &members,
            ConsensusMode::Single,
            Box::new(rng::new_from(rng)),
        )
    }
}

#[derive(Debug)]
pub enum CreateGossipError {
    MissingVersion,
    Other(Error),
}

impl From<Error> for CreateGossipError {
    fn from(src: Error) -> Self {
        Self::Other(src)
    }
}

fn parse_env_var<T>(name: &str) -> Option<T>
where
    T: FromStr,
    T::Err: Display,
{
    env::var(name).ok().map(|value| match value.parse() {
        Ok(value) => value,
        Err(error) => panic!("Failed to parse '{}': {}", name, error),
    })
}

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::*;
    use crate::{id::P2pNode, rng::MainRng, section::EldersInfo};

    use serde::Serialize;
    use std::net::SocketAddr;
    use xor_name::Prefix;

    const DEFAULT_MIN_SECTION_SIZE: usize = 4;

    #[test]
    fn parsec_size_counter() {
        let mut counter = ParsecSizeCounter::default();
        assert!(!counter.needs_pruning());
        counter.increase_size(PARSEC_SIZE_LIMIT);
        assert!(!counter.needs_pruning());
        counter.increase_size(1);
        assert!(counter.needs_pruning());
    }

    fn create_full_ids(rng: &mut MainRng) -> Vec<FullId> {
        (0..DEFAULT_MIN_SECTION_SIZE)
            .map(|_| FullId::gen(rng))
            .collect()
    }

    fn init_parsec_map(
        parsec_map: &mut ParsecMap,
        rng: &mut MainRng,
        full_ids: Vec<FullId>,
        version: u64,
    ) {
        let socket_addr: SocketAddr = ([127, 0, 0, 1], 9999).into();
        let members = full_ids
            .iter()
            .map(|id| {
                (
                    *id.public_id().name(),
                    P2pNode::new(*id.public_id(), socket_addr),
                )
            })
            .collect();
        let elders_info = EldersInfo::new(members, Prefix::default());
        parsec_map.init(rng, full_ids[0].clone(), &elders_info, vec![], version);
    }

    fn create_parsec_map(rng: &mut MainRng, size: u64) -> ParsecMap {
        let full_ids = create_full_ids(rng);

        let mut parsec_map = ParsecMap::default();
        for parsec_no in 0..=size {
            init_parsec_map(&mut parsec_map, rng, full_ids.clone(), parsec_no);
        }

        parsec_map
    }

    fn add_to_parsec_map(rng: &mut MainRng, parsec_map: &mut ParsecMap, version: u64) {
        let full_ids = create_full_ids(rng);
        init_parsec_map(parsec_map, rng, full_ids, version);
    }

    trait HandleRequestResponse {
        fn handle(&self, parsec_map: &mut ParsecMap, msg_version: u64, pub_id: &PublicId);
    }

    impl HandleRequestResponse for Request {
        fn handle(&self, parsec_map: &mut ParsecMap, msg_version: u64, pub_id: &PublicId) {
            let _ = parsec_map.handle_request(msg_version, self.clone(), *pub_id);
        }
    }

    impl HandleRequestResponse for Response {
        fn handle(&self, parsec_map: &mut ParsecMap, msg_version: u64, pub_id: &PublicId) {
            parsec_map.handle_response(msg_version, self.clone(), *pub_id);
        }
    }

    fn handle_msgs_just_below_prune_limit<T: HandleRequestResponse + Serialize>(
        parsec_map: &mut ParsecMap,
        msg_version: u64,
        msg: &T,
        pub_id: &PublicId,
    ) {
        let msg_size = bincode::serialized_size(&msg).unwrap();
        let msg_size_limit = PARSEC_SIZE_LIMIT / msg_size;

        // Handle msg_size_limit msgs which should trigger pruning needed on the next
        // msg if it's against the latest parsec.
        for _ in 0..msg_size_limit {
            msg.handle(parsec_map, msg_version, pub_id);
        }

        // Make sure we don't cross the prune limit
        assert_eq!(parsec_map.size_counter.needs_pruning(), false);
    }

    fn check_prune_needed_after_msg<T: HandleRequestResponse + Serialize>(
        rng: &mut MainRng,
        msg: T,
        parsec_age: u64,
        prune_needed: bool,
    ) -> ParsecMap {
        let full_id = FullId::gen(rng);
        let pub_id = full_id.public_id();
        let number_of_parsecs = 2;

        let mut parsec_map = create_parsec_map(rng, number_of_parsecs);

        // Sometimes send to an old parsec
        let msg_version = number_of_parsecs - parsec_age;

        handle_msgs_just_below_prune_limit(&mut parsec_map, msg_version, &msg, pub_id);

        msg.handle(&mut parsec_map, msg_version, pub_id);
        assert_eq!(parsec_map.size_counter.needs_pruning(), prune_needed);

        parsec_map
    }

    #[test]
    fn prune_not_required_for_resp_to_old_parsec() {
        let parsec_age = 1;
        let _ = check_prune_needed_after_msg(&mut rng::new(), Response::new(), parsec_age, false);
    }

    #[test]
    fn prune_required_for_resp_to_latest_parsec() {
        let parsec_age = 0;
        let _ = check_prune_needed_after_msg(&mut rng::new(), Response::new(), parsec_age, true);
    }

    #[test]
    fn prune_not_required_for_req_to_old_parsec() {
        let parsec_age = 1;
        let _ = check_prune_needed_after_msg(&mut rng::new(), Request::new(), parsec_age, false);
    }

    #[test]
    fn prune_required_for_req_to_latest_parsec() {
        let parsec_age = 0;
        let _ = check_prune_needed_after_msg(&mut rng::new(), Request::new(), parsec_age, true);
    }

    #[test]
    fn prune_required_is_reset_on_adding_parsec() {
        let mut rng = rng::new();
        let parsec_age = 0;
        let mut parsec_map =
            check_prune_needed_after_msg(&mut rng, Response::new(), parsec_age, true);

        assert_eq!(parsec_map.size_counter.needs_pruning(), true);
        let number_of_parsecs = 2;
        add_to_parsec_map(&mut rng, &mut parsec_map, number_of_parsecs + 1);
        assert_eq!(parsec_map.size_counter.needs_pruning(), false);
    }

    #[test]
    fn prune_required_is_reset_on_voting() {
        let parsec_age = 0;
        let mut parsec_map =
            check_prune_needed_after_msg(&mut rng::new(), Response::new(), parsec_age, true);

        assert_eq!(parsec_map.size_counter.needs_pruning(), true);
        parsec_map.size_counter.set_pruning_voted_for();
        assert_eq!(parsec_map.size_counter.needs_pruning(), false);
    }
}
