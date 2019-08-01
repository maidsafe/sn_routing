// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(feature = "mock_parsec")]
use crate::mock::parsec as inner;
use crate::{
    chain::{self, GenesisPfxInfo},
    id::{self, FullId},
    messages::DirectMessage,
    utils::LogIdent,
};
use log::LogLevel;
#[cfg(not(feature = "mock_parsec"))]
use parsec as inner;
use std::collections::{btree_map::Entry, BTreeMap};

#[cfg(feature = "mock_parsec")]
pub use crate::mock::parsec::{
    init_mock, ConsensusMode, NetworkEvent, Observation, Proof, PublicId, SecretId,
};
#[cfg(not(feature = "mock_parsec"))]
pub use parsec::{ConsensusMode, NetworkEvent, Observation, Proof, PublicId, SecretId};

pub type Block = inner::Block<chain::NetworkEvent, id::PublicId>;
pub type Parsec = inner::Parsec<chain::NetworkEvent, FullId>;
pub type Request = inner::Request<chain::NetworkEvent, id::PublicId>;
pub type Response = inner::Response<chain::NetworkEvent, id::PublicId>;

pub struct ParsecMap {
    map: BTreeMap<u64, Parsec>,
}

impl ParsecMap {
    pub fn new(full_id: FullId, gen_pfx_info: &GenesisPfxInfo) -> Self {
        let mut map = BTreeMap::new();
        let _ = map.insert(
            *gen_pfx_info.first_info.version(),
            create(full_id, gen_pfx_info),
        );

        Self { map }
    }

    pub fn init(&mut self, full_id: FullId, gen_pfx_info: &GenesisPfxInfo, log_ident: &LogIdent) {
        if let Entry::Vacant(entry) = self.map.entry(*gen_pfx_info.first_info.version()) {
            let _ = entry.insert(create(full_id, gen_pfx_info));
            info!(
                "{}: Init new Parsec, genesis = {:?}",
                log_ident, gen_pfx_info
            );
        }
    }

    pub fn handle_request(
        &mut self,
        msg_version: u64,
        request: Request,
        pub_id: id::PublicId,
        log_ident: &LogIdent,
    ) -> (Option<DirectMessage>, bool) {
        let parsec = if let Some(parsec) = self.map.get_mut(&msg_version) {
            parsec
        } else {
            return (None, false);
        };

        let response = parsec
            .handle_request(&pub_id, request)
            .map(|response| DirectMessage::ParsecResponse(msg_version, response))
            .map_err(|err| {
                debug!("{} - Error handling parsec request: {:?}", log_ident, err);
                err
            })
            .ok();
        let poll = self.last_version() == msg_version;

        (response, poll)
    }

    pub fn handle_response(
        &mut self,
        msg_version: u64,
        response: Response,
        pub_id: id::PublicId,
        log_ident: &LogIdent,
    ) -> bool {
        let parsec = if let Some(parsec) = self.map.get_mut(&msg_version) {
            parsec
        } else {
            return false;
        };

        if let Err(err) = parsec.handle_response(&pub_id, response) {
            debug!("{} - Error handling parsec response: {:?}", log_ident, err);
        }

        self.last_version() == msg_version
    }

    pub fn create_gossip(&mut self, version: u64, target: &id::PublicId) -> Option<DirectMessage> {
        let request = self.map.get_mut(&version)?.create_gossip(target).ok()?;
        Some(DirectMessage::ParsecRequest(version, request))
    }

    pub fn vote_for(&mut self, event: chain::NetworkEvent, log_ident: &LogIdent) {
        if let Some(ref mut parsec) = self.map.values_mut().last() {
            let obs = match event.into_obs() {
                Err(_) => {
                    warn!(
                        "{} - Failed to convert NetworkEvent to Parsec Observation.",
                        log_ident
                    );
                    return;
                }
                Ok(obs) => obs,
            };

            if let Err(err) = parsec.vote_for(obs) {
                trace!("{} - Parsec vote error: {:?}", log_ident, err);
            }
        }
    }

    pub fn last_version(&self) -> u64 {
        if let Some(version) = self.map.keys().last() {
            *version
        } else {
            log_or_panic!(LogLevel::Error, "ParsecMap is empty.");
            0
        }
    }

    pub fn gossip_recipients(&self) -> Vec<&id::PublicId> {
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
    ) -> impl Iterator<Item = &Observation<chain::NetworkEvent, id::PublicId>> {
        self.map
            .values()
            .last()
            .map(Parsec::our_unpolled_observations)
            .into_iter()
            .flatten()
    }

    #[cfg(feature = "mock_base")]
    pub fn has_unpolled_observations(&self) -> bool {
        let parsec = if let Some(parsec) = self.map.values().last() {
            parsec
        } else {
            return false;
        };

        parsec.has_unpolled_observations()
    }
}

/// Create Parsec instance.
fn create(full_id: FullId, gen_pfx_info: &GenesisPfxInfo) -> Parsec {
    if gen_pfx_info
        .first_info
        .members()
        .contains(full_id.public_id())
    {
        Parsec::from_genesis(
            #[cfg(feature = "mock_parsec")]
            *gen_pfx_info.first_info.hash(),
            full_id,
            &gen_pfx_info.first_info.members(),
            gen_pfx_info.first_state_serialized.clone(),
            ConsensusMode::Single,
            Box::new(rand::os::OsRng::new().unwrap()),
        )
    } else {
        Parsec::from_existing(
            #[cfg(feature = "mock_parsec")]
            *gen_pfx_info.first_info.hash(),
            full_id,
            &gen_pfx_info.first_info.members(),
            &gen_pfx_info.latest_info.members(),
            ConsensusMode::Single,
            Box::new(rand::os::OsRng::new().unwrap()),
        )
    }
}
