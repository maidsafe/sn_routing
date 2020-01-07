// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    chain_accumulator::{AccumulatingProof, ChainAccumulator, InsertError},
    shared_state::{SectionKeyInfo, SectionProofBlock, SharedState, SplitCache},
    AccumulatedEvent, AccumulatingEvent, AgeCounter, EldersChange, EldersInfo, GenesisPfxInfo,
    MemberInfo, MemberPersona, MemberState, NetworkEvent, NetworkParams, Proof, ProofSet,
    SectionProofChain,
};
use crate::{
    error::RoutingError,
    id::{P2pNode, PublicId},
    parsec::{DkgResult, DkgResultWrapper},
    relocation::{self, RelocateDetails},
    utils::LogIdent,
    Authority, BlsPublicKeySet, BlsSecretKeyShare, BlsSignature, ConnectionInfo, Prefix, XorName,
    Xorable,
};
use itertools::Itertools;
use log::LogLevel;
use maidsafe_utilities::serialisation::serialise;
use serde::Serialize;
use std::cmp::Ordering;
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    fmt::{self, Debug, Display, Formatter},
    iter, mem,
    net::SocketAddr,
};

#[cfg(feature = "mock_base")]
use crate::crypto::Digest256;

/// Returns the delivery group size based on the section size `n`
pub fn delivery_group_size(n: usize) -> usize {
    // this is an integer that is ≥ n/3
    (n + 2) / 3
}

/// Data chain.
pub struct Chain {
    /// Network parameters
    network_cfg: NetworkParams,
    /// This node's public ID.
    our_id: PublicId,
    /// Our current Section BLS keys.
    our_section_bls_keys: SectionKeys,
    /// The shared state of the section.
    state: SharedState,
    /// If we're an elder of the section yet. This will be toggled once we get a `EldersInfo`
    /// block accumulated which bears `our_id` as one of the members
    is_elder: bool,
    /// Accumulate NetworkEvent that do not have yet enough vote/proofs.
    chain_accumulator: ChainAccumulator,
    /// Pending events whose handling has been deferred due to an ongoing split or merge.
    event_cache: BTreeSet<NetworkEvent>,
    /// Marker indicating we are processing churn event
    churn_in_progress: bool,
    /// Marker indicating we are processing a relocation.
    relocation_in_progress: bool,
    /// Marker indicating that elders may need to change,
    members_changed: bool,
    /// The new dkg key to use when SectionInfo completes. For lookup, use the XorName of the
    /// first member in DKG participants and new ElderInfo. We only store 2 items during split, and
    /// then members are disjoint. We are working around not having access to the prefix for the
    /// DkgResult but only the list of participants.
    new_section_bls_keys: BTreeMap<XorName, DkgResult>,
}

#[allow(clippy::len_without_is_empty)]
impl Chain {
    /// Returns the number of elders per section
    pub fn elder_size(&self) -> usize {
        self.network_cfg.elder_size
    }

    /// Returns the safe section size.
    pub fn safe_section_size(&self) -> usize {
        self.network_cfg.safe_section_size
    }

    /// Returns the full NetworkParams structure (if present)
    pub fn network_cfg(&self) -> NetworkParams {
        self.network_cfg
    }

    pub fn our_section_bls_keys(&self) -> &BlsPublicKeySet {
        &self.our_section_bls_keys.public_key_set
    }

    pub fn our_section_bls_secret_key_share(&self) -> Result<&SectionKeyShare, RoutingError> {
        self.our_section_bls_keys
            .secret_key_share
            .as_ref()
            .ok_or(RoutingError::InvalidElderDkgResult)
    }

    /// Collects prefixes of all sections known by the routing table into a `BTreeSet`.
    pub fn prefixes(&self) -> BTreeSet<Prefix<XorName>> {
        self.other_prefixes()
            .iter()
            .chain(iter::once(self.state.our_info().prefix()))
            .cloned()
            .collect()
    }

    /// Create a new chain given genesis information
    pub fn new(
        network_cfg: NetworkParams,
        our_id: PublicId,
        gen_info: GenesisPfxInfo,
        secret_key_share: Option<BlsSecretKeyShare>,
    ) -> Self {
        // TODO validate `gen_info` to contain adequate proofs
        let is_elder = gen_info.first_info.is_member(&our_id);
        let secret_key_share = secret_key_share
            .and_then(|key| SectionKeyShare::new(key, &our_id, &gen_info.first_info));
        Self {
            network_cfg,
            our_id,
            our_section_bls_keys: SectionKeys {
                public_key_set: gen_info.first_bls_keys.clone(),
                secret_key_share,
            },
            state: SharedState::new(
                gen_info.first_info,
                gen_info.first_bls_keys,
                gen_info.first_ages,
            ),
            is_elder,
            chain_accumulator: Default::default(),
            event_cache: Default::default(),
            churn_in_progress: false,
            relocation_in_progress: false,
            members_changed: false,
            new_section_bls_keys: Default::default(),
        }
    }

    /// Handles an accumulated parsec Observation for genesis.
    ///
    /// The related_info is the serialized shared state that will be the starting
    /// point when processing parsec data.
    pub fn handle_genesis_event(
        &mut self,
        _group: &BTreeSet<PublicId>,
        related_info: &[u8],
    ) -> Result<(), RoutingError> {
        // On split membership may need to be checked again.
        self.members_changed = true;
        self.state
            .update_with_genesis_related_info(related_info, &LogIdent::new(self))
    }

    /// Handles a completed parsec DKG Observation.
    pub fn handle_dkg_result_event(
        &mut self,
        participants: &BTreeSet<PublicId>,
        dkg_result: &DkgResultWrapper,
    ) -> Result<(), RoutingError> {
        if let Some(first) = participants.iter().next() {
            if self
                .new_section_bls_keys
                .insert(*first.name(), dkg_result.0.clone())
                .is_some()
            {
                log_or_panic!(LogLevel::Error, "{} - Ejected previous DKG result", self);
            }
        }

        Ok(())
    }

    /// Get the serialized shared state that will be the starting point when processing
    /// parsec data
    pub fn get_genesis_related_info(&self) -> Result<Vec<u8>, RoutingError> {
        self.state.get_genesis_related_info()
    }

    fn get_age_counters(&self) -> BTreeMap<PublicId, AgeCounter> {
        self.state
            .our_members
            .values()
            .map(|member_info| (*member_info.p2p_node.public_id(), member_info.age_counter))
            .collect()
    }

    /// Handles an opaque parsec Observation as a NetworkEvent.
    pub fn handle_opaque_event(
        &mut self,
        event: &NetworkEvent,
        proof: Proof,
    ) -> Result<(), RoutingError> {
        if self.should_skip_accumulator(event) {
            return Ok(());
        }

        if !self.can_handle_vote(event) {
            self.cache_event(event, proof.pub_id())?;
            return Ok(());
        }

        let (acc_event, signature) = AccumulatingEvent::from_network_event(event.clone());
        match self
            .chain_accumulator
            .add_proof(acc_event, proof, signature)
        {
            Err(InsertError::AlreadyComplete) => {
                // Ignore further votes for completed events.
            }
            Err(InsertError::ReplacedAlreadyInserted) => {
                // TODO: If detecting duplicate vote from peer, penalise.
                log_or_panic!(
                    LogLevel::Warn,
                    "{} Duplicate proof for {:?} in chain accumulator. {:?}",
                    self,
                    event,
                    self.chain_accumulator.incomplete_events().collect_vec()
                );
            }
            Ok(()) => {
                // Proof added.
            }
        }
        Ok(())
    }

    /// Returns the next accumulated event.
    ///
    /// If the event is a `SectionInfo` or `NeighbourInfo`, it also updates the corresponding
    /// containers.
    pub fn poll_accumulated(&mut self) -> Result<Option<PollAccumulated>, RoutingError> {
        if let Some(event) = self.poll_churn_event_backlog() {
            return Ok(Some(PollAccumulated::AccumulatedEvent(event)));
        }

        // Note: it's important that `promote_and_demote_elders` happens before `poll_relocation`,
        // otherwise we might relocate a node that we still need.
        if let Some(new_infos) = self.promote_and_demote_elders()? {
            return Ok(Some(PollAccumulated::PromoteDemoteElders(new_infos)));
        }

        if let Some(details) = self.poll_relocation() {
            return Ok(Some(PollAccumulated::RelocateDetails(details)));
        }

        let (event, proofs) = match self.poll_chain_accumulator() {
            None => return Ok(None),
            Some((event, proofs)) => (event, proofs),
        };

        let event = match self.process_accumulating(event, proofs)? {
            None => return Ok(None),
            Some(event) => event,
        };

        if let Some(event) = self.check_ready_or_backlog_churn_event(event)? {
            return Ok(Some(PollAccumulated::AccumulatedEvent(event)));
        }

        Ok(None)
    }

    fn poll_chain_accumulator(&mut self) -> Option<(AccumulatingEvent, AccumulatingProof)> {
        let opt_event = self
            .chain_accumulator
            .incomplete_events()
            .find(|(event, proofs)| self.is_valid_transition(event, proofs.parsec_proof_set()))
            .map(|(event, _)| event.clone());

        opt_event.and_then(|event| {
            self.chain_accumulator
                .poll_event(event, self.our_info().member_ids().cloned().collect())
        })
    }

    fn process_accumulating(
        &mut self,
        event: AccumulatingEvent,
        proofs: AccumulatingProof,
    ) -> Result<Option<AccumulatedEvent>, RoutingError> {
        match event {
            AccumulatingEvent::SectionInfo(ref info, ref key_info) => {
                let change = EldersChangeBuilder::new(self);
                if self.add_elders_info(info.clone(), key_info.clone(), proofs)? {
                    let change = change.build(self);
                    return Ok(Some(
                        AccumulatedEvent::new(event).with_elders_change(change),
                    ));
                } else {
                    return Ok(None);
                }
            }
            AccumulatingEvent::NeighbourInfo(ref info) => {
                let change = EldersChangeBuilder::new(self);
                self.add_neighbour_elders_info(info.clone())?;
                let change = change.build(self);

                return Ok(Some(
                    AccumulatedEvent::new(event).with_elders_change(change),
                ));
            }
            AccumulatingEvent::TheirKeyInfo(ref key_info) => {
                self.update_their_keys(key_info);
            }
            AccumulatingEvent::AckMessage(ref ack_payload) => {
                self.update_their_knowledge(ack_payload.src_prefix, ack_payload.ack_version);
            }
            AccumulatingEvent::Relocate(ref relocate_details) => {
                self.relocation_in_progress = false;
                let signature = Some(
                    self.check_and_combine_signatures(relocate_details, proofs)
                        .ok_or(RoutingError::InvalidRelocation)?,
                );
                return Ok(Some(AccumulatedEvent::new(event).with_signature(signature)));
            }
            AccumulatingEvent::Online(_)
            | AccumulatingEvent::Offline(_)
            | AccumulatingEvent::StartDkg(_)
            | AccumulatingEvent::User(_)
            | AccumulatingEvent::ParsecPrune
            | AccumulatingEvent::RelocatePrepare(_, _)
            | AccumulatingEvent::SendAckMessage(_) => (),
        }

        Ok(Some(AccumulatedEvent::new(event)))
    }

    pub fn poll_churn_event_backlog(&mut self) -> Option<AccumulatedEvent> {
        if self.can_poll_churn() {
            if let Some(event) = self.state.churn_event_backlog.pop_back() {
                trace!(
                    "{} churn backlog poll {:?}, Others: {:?}",
                    self,
                    event,
                    self.state.churn_event_backlog
                );
                return Some(event);
            }
        }

        None
    }

    pub fn check_ready_or_backlog_churn_event(
        &mut self,
        event: AccumulatedEvent,
    ) -> Result<Option<AccumulatedEvent>, RoutingError> {
        let start_churn_event = match &event.content {
            AccumulatingEvent::Online(_) | AccumulatingEvent::Offline(_) => true,
            _ => false,
        };

        if start_churn_event && !self.can_poll_churn() {
            trace!(
                "{} churn backlog {:?}, Other: {:?}",
                self,
                event,
                self.state.churn_event_backlog
            );
            self.state.churn_event_backlog.push_front(event);
            return Ok(None);
        }

        Ok(Some(event))
    }

    // Increment the age counters of the members.
    pub fn increment_age_counters(&mut self, trigger_node: &PublicId) {
        let our_section_size = self.state.our_joined_members().count();
        let safe_section_size = self.safe_section_size();

        if our_section_size >= safe_section_size
            && self
                .state
                .get_persona(trigger_node)
                .map(|persona| persona == MemberPersona::Infant)
                .unwrap_or(true)
        {
            // FIXME: skipping infants churn for ageing breaks tests for node ageing, as once a
            // section reaches a safe size, nodes stop ageing at all, because all churn in tests
            // is Infant churn.
            // Temporarily ignore until we either find a better way of preventing churn spam,
            // or we change the tests to provide some Adult churn at all times.
            trace!(
                "{} FIXME: should do nothing for infants and unknown nodes {:?}",
                self,
                trigger_node
            );
        }

        let our_prefix = *self.state.our_prefix();
        let relocating_state = self.state.create_relocating_state();
        let mut details_to_add = Vec::new();

        for (name, member_info) in self.state.our_joined_members_mut() {
            if member_info.p2p_node.public_id() == trigger_node {
                continue;
            }

            if !member_info.increment_age_counter() {
                continue;
            }

            let destination =
                relocation::compute_destination(&our_prefix, name, trigger_node.name());
            if our_prefix.matches(&destination) {
                // Relocation destination inside the current section - ignoring.
                trace!(
                    "increment_age_counters: Ignoring relocation for {:?}",
                    member_info.p2p_node.public_id()
                );
                continue;
            }

            member_info.state = relocating_state;
            details_to_add.push(RelocateDetails {
                pub_id: *member_info.p2p_node.public_id(),
                destination,
                age: member_info.age() + 1,
            })
        }

        trace!("increment_age_counters: {:?}", self.state.our_members);

        for details in details_to_add {
            trace!("{} - Change state to Relocating {}", self, details.pub_id);
            self.state.relocate_queue.push_front(details)
        }
    }

    /// Returns the details of the next scheduled relocation to be voted for, if any.
    fn poll_relocation(&mut self) -> Option<RelocateDetails> {
        // Delay relocation until all backlogged churn events have been handled and no
        // additional churn is in progress. Only allow one relocation at a time.
        if !self.can_poll_churn() || !self.state.churn_event_backlog.is_empty() {
            return None;
        }

        let details = loop {
            if let Some(details) = self.state.relocate_queue.pop_back() {
                if self.is_peer_our_member(&details.pub_id) {
                    break details;
                } else {
                    trace!(
                        "{} - Not relocating {} - not a member",
                        self,
                        details.pub_id
                    );
                }
            } else {
                return None;
            }
        };

        if self.is_peer_our_elder(&details.pub_id) {
            warn!(
                "{} - Not relocating {} - The peer is still our elder.",
                self, details.pub_id,
            );

            // Keep the details in the queue so when the node is demoted we can relocate it.
            self.state.relocate_queue.push_back(details);
            return None;
        }

        trace!("{} - relocating member {}", self, details.pub_id);
        self.relocation_in_progress = true;

        Some(details)
    }

    fn can_poll_churn(&self) -> bool {
        self.state.handled_genesis_event
            && !self.churn_in_progress
            && !self.relocation_in_progress
            && !self.state.split_in_progress
    }

    /// Validate if can call add_member on this node.
    pub fn can_add_member(&self, pub_id: &PublicId) -> bool {
        self.our_prefix().matches(pub_id.name()) && !self.is_peer_our_member(pub_id)
    }

    /// Validate if can call remove_member on this node.
    pub fn can_remove_member(&self, pub_id: &PublicId) -> bool {
        self.is_peer_our_member(pub_id)
    }

    /// Adds a member to our section.
    pub fn add_member(&mut self, p2p_node: P2pNode, age: u8) {
        self.assert_no_prefix_change("add member");
        self.members_changed = true;

        match self.state.our_members.entry(*p2p_node.name()) {
            Entry::Occupied(mut entry) => {
                if entry.get().state == MemberState::Left {
                    // Node rejoining
                    // TODO: To properly support rejoining, either keep the previous age or set the
                    // new age to max(old_age, new_age)
                    entry.get_mut().state = MemberState::Joined;
                    entry.get_mut().set_age(age);
                } else {
                    // Node already joined - this should not happen.
                    log_or_panic!(
                        LogLevel::Error,
                        "{} - Adding member that already exists: {}",
                        self,
                        p2p_node,
                    );
                }
            }
            Entry::Vacant(entry) => {
                // Node joining for the first time.
                let _ = entry.insert(MemberInfo::new(age, p2p_node.clone()));
            }
        }
    }

    /// Remove a member from our section. Returns the state of the member before the removal.
    pub fn remove_member(&mut self, pub_id: &PublicId) -> MemberState {
        self.assert_no_prefix_change("remove member");
        self.members_changed = true;

        if let Some(info) = self
            .state
            .our_members
            .get_mut(pub_id.name())
            // TODO: Probably should actually remove them
            .filter(|info| info.state != MemberState::Left)
        {
            let member_state = info.state;
            info.state = MemberState::Left;
            self.state
                .relocate_queue
                .retain(|details| &details.pub_id != pub_id);
            member_state
        } else {
            log_or_panic!(
                LogLevel::Error,
                "{} - Removing member that doesn't exist: {}",
                self,
                pub_id
            );

            MemberState::Left
        }
    }

    /// Generate a new section info based on the current set of members.
    /// Returns a set of EldersInfos to vote for.
    fn promote_and_demote_elders(&mut self) -> Result<Option<Vec<EldersInfo>>, RoutingError> {
        if !self.members_changed || !self.can_poll_churn() {
            // Nothing changed that could impact elder set, or we cannot process it yet.
            return Ok(None);
        }

        if self.should_split()? {
            let (our_info, other_info) = self.split_self()?;
            self.state.split_in_progress = true;
            self.members_changed = false;
            self.churn_in_progress = true;
            return Ok(Some(vec![our_info, other_info]));
        }

        let expected_elders_map = self.our_expected_elders();
        let expected_elders: BTreeSet<_> = expected_elders_map.values().cloned().collect();
        let current_elders: BTreeSet<_> = self.state.our_info().member_nodes().cloned().collect();

        if expected_elders != current_elders {
            let old_size = self.state.our_info().len();

            let new_info = EldersInfo::new(
                expected_elders_map,
                *self.state.our_info().prefix(),
                Some(self.state.our_info()),
            )?;

            if self.state.our_info().len() < self.elder_size() && old_size >= self.elder_size() {
                panic!(
                    "Merging situation encountered! Not supported: {:?}: {:?}",
                    self.our_id(),
                    self.state.our_info()
                );
            }

            self.members_changed = false;
            self.churn_in_progress = true;
            Ok(Some(vec![new_info]))
        } else {
            self.members_changed = false;
            Ok(None)
        }
    }

    /// Gets the data needed to initialise a new Parsec instance
    pub fn prepare_parsec_reset(
        &mut self,
        parsec_version: u64,
    ) -> Result<ParsecResetData, RoutingError> {
        let remaining = self.chain_accumulator.reset_accumulator(&self.our_id);
        let event_cache = mem::replace(&mut self.event_cache, Default::default());

        self.state.handled_genesis_event = false;

        Ok(ParsecResetData {
            gen_pfx_info: GenesisPfxInfo {
                first_info: self.our_info().clone(),
                first_bls_keys: self.our_section_bls_keys().clone(),
                first_state_serialized: self.get_genesis_related_info()?,
                first_ages: self.get_age_counters(),
                latest_info: self.our_info().clone(),
                parsec_version,
            },
            cached_events: remaining
                .cached_events
                .into_iter()
                .chain(event_cache)
                .collect(),
            completed_events: remaining.completed_events,
        })
    }

    /// Finalises a split or merge - creates a `GenesisPfxInfo` for the new graph and returns the
    /// cached and currently accumulated events.
    pub fn finalise_prefix_change(
        &mut self,
        parsec_version: u64,
    ) -> Result<ParsecResetData, RoutingError> {
        // TODO: Bring back using their_knowledge to clean_older section in our_infos
        self.check_and_clean_neighbour_infos(None);
        self.state.split_in_progress = false;

        info!("{} - finalise_prefix_change: {:?}", self, self.our_prefix());
        trace!("{} - finalise_prefix_change state: {:?}", self, self.state);

        self.prepare_parsec_reset(parsec_version)
    }

    /// Returns our public ID
    pub fn our_id(&self) -> &PublicId {
        &self.our_id
    }

    /// Returns our own current section info.
    pub fn our_info(&self) -> &EldersInfo {
        self.state.our_info()
    }

    /// Returns our own current section's prefix.
    pub fn our_prefix(&self) -> &Prefix<XorName> {
        self.state.our_prefix()
    }

    /// Returns whether our section is in the process of splitting.
    pub fn split_in_progress(&self) -> bool {
        self.state.split_in_progress
    }

    /// Returns whether a membership change is in progress (a node leaving, joining or being
    /// relocated).
    pub fn membership_change_in_progress(&self) -> bool {
        self.churn_in_progress || self.relocation_in_progress
    }

    /// Neighbour infos signed by our section
    pub fn neighbour_infos(&self) -> impl Iterator<Item = &EldersInfo> {
        self.state.neighbour_infos.values()
    }

    /// Return prefixes of all our neighbours
    pub fn other_prefixes(&self) -> BTreeSet<Prefix<XorName>> {
        self.state.neighbour_infos.keys().cloned().collect()
    }

    /// Neighbour infos signed by our section
    pub fn get_neighbour_info(&self, prefix: &Prefix<XorName>) -> Option<&EldersInfo> {
        self.state.neighbour_infos.get(prefix)
    }

    /// Check if the given `PublicId` is a member of our section.
    pub fn is_peer_our_member(&self, pub_id: &PublicId) -> bool {
        self.state
            .our_members
            .get(pub_id.name())
            .map(|info| info.state != MemberState::Left)
            .unwrap_or(false)
    }

    /// Returns the `ConnectioInfo` for a member of our section.
    pub fn get_member_connection_info(&self, pub_id: &PublicId) -> Option<&ConnectionInfo> {
        self.state
            .our_members
            .get(pub_id.name())
            .map(|member_info| member_info.p2p_node.connection_info())
    }

    /// Returns a section member `P2pNode`
    pub fn get_member_p2p_node(&self, name: &XorName) -> Option<&P2pNode> {
        self.state
            .our_members
            .get(name)
            .map(|member_info| &member_info.p2p_node)
    }

    /// Returns an old section member `P2pNode`
    fn get_post_split_sibling_member_p2p_node(&self, name: &XorName) -> Option<&P2pNode> {
        self.state
            .post_split_sibling_members
            .get(name)
            .map(|member_info| &member_info.p2p_node)
    }

    /// Returns the connection infos for all non-Elders in the section
    pub fn adults_and_infants_conn_infos(&self) -> Vec<ConnectionInfo> {
        self.state
            .our_joined_members()
            .filter(|(_, info)| !self.state.our_info().is_member(info.p2p_node.public_id()))
            .map(|(_, info)| info.p2p_node.connection_info().clone())
            .collect()
    }

    pub fn get_our_info_p2p_node(&self, name: &XorName) -> Option<&P2pNode> {
        self.state.our_info().member_map().get(name)
    }

    /// Returns a neighbour `P2pNode`
    pub fn get_neighbour_p2p_node(&self, name: &XorName) -> Option<&P2pNode> {
        self.state
            .neighbour_infos
            .iter()
            .find(|(pfx, _)| pfx.matches(name))
            .and_then(|(_, elders_info)| elders_info.member_map().get(name))
    }

    pub fn get_p2p_node(&self, name: &XorName) -> Option<&P2pNode> {
        self.get_member_p2p_node(name)
            .or_else(|| self.get_our_info_p2p_node(name))
            .or_else(|| self.get_neighbour_p2p_node(name))
            .or_else(|| self.get_post_split_sibling_member_p2p_node(name))
    }

    /// Returns a set of elders we should be connected to.
    pub fn elders(&self) -> impl Iterator<Item = &P2pNode> {
        self.neighbour_infos()
            .chain(iter::once(self.state.our_info()))
            .flat_map(EldersInfo::member_nodes)
    }

    pub fn find_p2p_node_from_addr(&self, socket_addr: &SocketAddr) -> Option<&P2pNode> {
        self.known_nodes()
            .find(|p2p_node| p2p_node.peer_addr() == socket_addr)
    }

    /// Checks if given `PublicId` is an elder in our section or one of our neighbour sections.
    pub fn is_peer_elder(&self, pub_id: &PublicId) -> bool {
        self.is_peer_our_elder(pub_id) || self.is_peer_neighbour_elder(pub_id)
    }

    /// Returns whether we are elder in our section.
    pub fn is_self_elder(&self) -> bool {
        self.is_elder
    }

    /// Returns whether the given peer is elder in our section.
    pub fn is_peer_our_elder(&self, pub_id: &PublicId) -> bool {
        self.state.our_info().is_member(pub_id)
    }

    /// Returns whether the given peer is elder in one of our neighbour sections.
    pub fn is_peer_neighbour_elder(&self, pub_id: &PublicId) -> bool {
        self.neighbour_infos().any(|info| info.is_member(pub_id))
    }

    /// Returns elders from our own section according to the latest accumulated `SectionInfo`.
    pub fn our_elders(&self) -> impl Iterator<Item = &P2pNode> + ExactSizeIterator {
        self.state.our_info().member_nodes()
    }

    pub fn our_joined_members(&self) -> impl Iterator<Item = &P2pNode> {
        self.state
            .our_joined_members()
            .map(|(_, info)| &info.p2p_node)
    }

    fn elders_and_adults(&self) -> impl Iterator<Item = &PublicId> {
        self.state
            .our_joined_members()
            // FIXME: we temporarily treat all section
            // members as Adults
            //.filter(|(_, info)| info.is_mature())
            .map(|(_, info)| info.p2p_node.public_id())
    }

    fn our_expected_elders(&self) -> BTreeMap<XorName, P2pNode> {
        let mut elders: BTreeMap<_, _> = self
            .state
            .our_joined_members()
            .sorted_by(|&(_, info1), &(_, info2)| Ord::cmp(&info2.age_counter, &info1.age_counter))
            .into_iter()
            .map(|(name, info)| (*name, info.p2p_node.clone()))
            .take(self.elder_size())
            .collect();

        // Ensure that we can still handle one node lost when relocating.
        // Ensure that the node we eject are the one we want to relocate first.
        let min_elders = self.elder_size();
        let num_elders = elders.len();
        elders.extend(
            self.state
                .relocate_queue
                .iter()
                .map(|details| details.pub_id.name())
                .filter_map(|name| self.state.our_members.get(name))
                .filter(|info| info.state != MemberState::Left)
                .take(min_elders.saturating_sub(num_elders))
                .map(|info| (*info.p2p_node.name(), info.p2p_node.clone())),
        );

        elders
    }

    fn eldest_members_matching_prefix(
        &self,
        prefix: &Prefix<XorName>,
    ) -> BTreeMap<XorName, P2pNode> {
        self.state
            .our_joined_members()
            .filter(|(name, _)| prefix.matches(name))
            .sorted_by(|&(_, info1), &(_, info2)| Ord::cmp(&info2.age_counter, &info1.age_counter))
            .into_iter()
            .map(|(name, info)| (*name, info.p2p_node.clone()))
            .take(self.elder_size())
            .collect()
    }

    /// Returns all neighbour elders.
    pub fn neighbour_elder_nodes(&self) -> impl Iterator<Item = &P2pNode> {
        self.neighbour_infos().flat_map(EldersInfo::member_nodes)
    }

    /// Returns an iterator over the members that have not state == `Left`.
    pub fn our_active_members(&self) -> impl Iterator<Item = &P2pNode> {
        self.state
            .our_active_members()
            .map(|(_, info)| &info.p2p_node)
    }

    /// Returns the members in our section and elders we know.
    pub fn known_nodes(&self) -> impl Iterator<Item = &P2pNode> {
        self.our_active_members()
            .chain(self.neighbour_elder_nodes())
    }

    /// Return the keys we know
    pub fn get_their_keys_info(&self) -> impl Iterator<Item = (&Prefix<XorName>, &SectionKeyInfo)> {
        self.state.get_their_keys_info()
    }

    /// Returns `true` if the `proof_chain` contains a key we have in `their_keys` and that key is
    /// for a prefix compatible with proof_chain prefix.
    pub fn check_trust(&self, proof_chain: &SectionProofChain) -> bool {
        let last_prefix = proof_chain.last_public_key_info().prefix();
        let filtered_keys: BTreeSet<_> = self
            .state
            .get_their_keys_info()
            .filter(|&(pfx, _)| last_prefix.is_compatible(pfx))
            .map(|(_, info)| info)
            .collect();
        proof_chain
            .all_key_infos()
            .any(|key_info| filtered_keys.contains(key_info))
    }

    /// Returns `true` if the `EldersInfo` isn't known to us yet.
    /// Ignore votes we may have produced as Parsec will filter for us.
    pub fn is_new(&self, elders_info: &EldersInfo) -> bool {
        let is_newer = |si: &EldersInfo| {
            si.version() >= elders_info.version() && si.prefix().is_compatible(elders_info.prefix())
        };

        if elders_info.prefix().matches(self.our_id.name()) {
            !self.state.our_infos().any(is_newer)
        } else {
            !self.neighbour_infos().any(is_newer)
        }
    }

    /// Returns `true` if the `EldersInfo` isn't known to us yet and is a neighbouring section.
    pub fn is_new_neighbour(&self, elders_info: &EldersInfo) -> bool {
        let our_prefix = self.our_prefix();
        let other_prefix = elders_info.prefix();

        (our_prefix.is_neighbour(other_prefix) || other_prefix.is_extension_of(our_prefix))
            && self.is_new(elders_info)
    }

    /// Provide a SectionProofChain that proves the given signature to the given destination
    /// authority.
    /// If `node_knowledge_override` is `Some`, it is used when calculating proof for
    /// `Authority::Node` instead of the stored knowledge. Has no effect for other authority types.
    pub fn prove(
        &self,
        target: &Authority<XorName>,
        node_knowledge_override: Option<u64>,
    ) -> SectionProofChain {
        let first_index = match (target, node_knowledge_override) {
            (Authority::Node(_), Some(knowledge)) => knowledge,
            _ => self.state.proving_index(target),
        };

        self.state.our_history.slice_from(first_index as usize)
    }

    /// Check which nodes are unresponsive.
    pub fn check_vote_status(&mut self) -> BTreeSet<PublicId> {
        let members = self.our_info().member_ids();
        self.chain_accumulator.check_vote_status(members)
    }

    /// Returns `true` if the given `NetworkEvent` is already accumulated and can be skipped.
    fn should_skip_accumulator(&self, event: &NetworkEvent) -> bool {
        // FIXME: may also need to handle non SI votes to not get handled multiple times
        let si = match event.payload {
            AccumulatingEvent::SectionInfo(ref si, _)
            | AccumulatingEvent::NeighbourInfo(ref si) => si,
            _ => return false,
        };

        // we can ignore self SI additional votes we do not require.
        if si.prefix().matches(self.our_id.name()) && self.our_info().version() >= si.version() {
            return true;
        }

        // we can skip neighbour infos we've already accumulated
        if self
            .state
            .neighbour_infos
            .iter()
            .any(|(pfx, elders_info)| pfx == si.prefix() && elders_info.version() >= si.version())
        {
            return true;
        }

        false
    }

    /// If given `NetworkEvent` is a `EldersInfo`, returns `true` if we have the previous
    /// `EldersInfo` in our_infos/neighbour_infos OR if its a valid neighbour pfx
    /// we do not currently have in our chain.
    /// Returns `true` for other types of `NetworkEvent`.
    fn is_valid_transition(&self, network_event: &AccumulatingEvent, proofs: &ProofSet) -> bool {
        match *network_event {
            AccumulatingEvent::SectionInfo(ref info, _) => {
                if !self.our_info().is_quorum(proofs) {
                    return false;
                }

                if !info.is_successor_of(self.our_info()) {
                    log_or_panic!(
                        LogLevel::Error,
                        "We shouldn't have a SectionInfo that is not a direct descendant. our: {:?}, new: {:?}",
                        self.our_info(), info
                    );
                }

                true
            }
            AccumulatingEvent::NeighbourInfo(ref info) => {
                if !self.our_info().is_quorum(proofs) {
                    return false;
                }

                // Do not process yet any version that is not the immediate follower of the one we have.
                let not_follow = |i: &EldersInfo| {
                    info.prefix().is_compatible(i.prefix()) && info.version() != (i.version() + 1)
                };
                if self
                    .compatible_neighbour_info(info)
                    .into_iter()
                    .any(not_follow)
                {
                    return false;
                }

                true
            }

            AccumulatingEvent::Online(_)
            | AccumulatingEvent::Offline(_)
            | AccumulatingEvent::TheirKeyInfo(_)
            | AccumulatingEvent::ParsecPrune
            | AccumulatingEvent::AckMessage(_)
            | AccumulatingEvent::User(_)
            | AccumulatingEvent::Relocate(_)
            | AccumulatingEvent::RelocatePrepare(_, _) => {
                !self.state.split_in_progress && self.our_info().is_quorum(proofs)
            }
            AccumulatingEvent::StartDkg(_) => {
                log_or_panic!(
                    LogLevel::Error,
                    "StartDkg present in the chain accumulator - should never happen!"
                );
                false
            }
            AccumulatingEvent::SendAckMessage(_) => {
                // We may not reach consensus if malicious peer, but when we do we know all our
                // nodes have updated `their_keys`.
                !self.state.split_in_progress && self.our_info().is_total_consensus(proofs)
            }
        }
    }

    fn compatible_neighbour_info<'a>(&'a self, si: &'a EldersInfo) -> Option<&'a EldersInfo> {
        self.state
            .neighbour_infos
            .iter()
            .find(move |&(pfx, _)| pfx.is_compatible(si.prefix()))
            .map(|(_, info)| info)
    }

    /// Check if we can handle a given event immediately.
    /// Returns `true` if we are not in the process of waiting for a pfx change
    /// or if incoming event is a vote for the ongoing pfx change.
    fn can_handle_vote(&self, event: &NetworkEvent) -> bool {
        if !self.state.split_in_progress {
            return true;
        }

        match &event.payload {
            AccumulatingEvent::SectionInfo(elders_info, _)
            | AccumulatingEvent::NeighbourInfo(elders_info) => {
                if elders_info.prefix().is_compatible(self.our_prefix())
                    && elders_info.version() > self.state.our_info().version() + 1
                {
                    log_or_panic!(
                        LogLevel::Error,
                        "We shouldn't have progressed past the split/merged version."
                    );
                    return false;
                }
                true
            }
            _ => false,
        }
    }

    /// Store given event if created by us for use later on.
    fn cache_event(
        &mut self,
        net_event: &NetworkEvent,
        sender_id: &PublicId,
    ) -> Result<(), RoutingError> {
        if !self.state.split_in_progress {
            log_or_panic!(
                LogLevel::Error,
                "Shouldn't be caching events while not splitting."
            );
        }
        if self.our_id == *sender_id {
            let _ = self.event_cache.insert(net_event.clone());
        }
        Ok(())
    }

    /// Handles our own section info, or the section info of our sibling directly after a split.
    /// Returns whether the event should be handled by the caller.
    pub fn add_elders_info(
        &mut self,
        elders_info: EldersInfo,
        key_info: SectionKeyInfo,
        proofs: AccumulatingProof,
    ) -> Result<bool, RoutingError> {
        // Split handling alone. wouldn't cater to merge
        if elders_info.prefix().is_extension_of(self.our_prefix()) {
            match self.state.split_cache.take() {
                None => {
                    self.state.split_cache = Some(SplitCache {
                        elders_info,
                        key_info,
                        proofs,
                    });
                    Ok(false)
                }
                Some(cache) => {
                    let cache_pfx = *cache.elders_info.prefix();

                    // Add our_info first so when we add sibling info, its a valid neighbour prefix
                    // which does not get immediately purged.
                    if cache_pfx.matches(self.our_id.name()) {
                        self.do_add_elders_info(cache.elders_info, cache.key_info, cache.proofs)?;
                        self.add_neighbour_elders_info(elders_info)?;
                    } else {
                        self.do_add_elders_info(elders_info, key_info, proofs)?;
                        self.add_neighbour_elders_info(cache.elders_info)?;
                    }
                    Ok(true)
                }
            }
        } else {
            self.do_add_elders_info(elders_info, key_info, proofs)?;
            Ok(true)
        }
    }

    fn do_add_elders_info(
        &mut self,
        elders_info: EldersInfo,
        key_info: SectionKeyInfo,
        proofs: AccumulatingProof,
    ) -> Result<(), RoutingError> {
        let is_new_elder = !self.is_elder && elders_info.is_member(&self.our_id);
        let proof_block = self.combine_signatures_for_section_proof_block(key_info, proofs)?;
        let our_new_key = key_matching_first_elder_name(
            &elders_info,
            mem::replace(&mut self.new_section_bls_keys, Default::default()),
        )?;

        self.state.push_our_new_info(elders_info, proof_block);
        self.our_section_bls_keys = SectionKeys::new(our_new_key, self.our_id(), self.our_info());

        if is_new_elder {
            self.is_elder = true;
        }
        self.churn_in_progress = false;
        self.check_and_clean_neighbour_infos(None);
        self.state.remove_our_members_not_matching_our_prefix();
        Ok(())
    }

    fn add_neighbour_elders_info(&mut self, elders_info: EldersInfo) -> Result<(), RoutingError> {
        let pfx = *elders_info.prefix();
        let ppfx = elders_info.prefix().popped();
        let spfx = elders_info.prefix().sibling();
        let new_elders_info_version = elders_info.version();

        if let Some(old_elders_info) = self.state.neighbour_infos.insert(pfx, elders_info) {
            if old_elders_info.version() > new_elders_info_version {
                log_or_panic!(
                    LogLevel::Error,
                    "{} Ejected newer neighbour info {:?}",
                    self,
                    old_elders_info
                );
            }
        }

        // If we just split an existing neighbour and we also need its sibling,
        // add the sibling prefix with the parent prefix sigs.
        if let Some(sinfo) = self
            .state
            .neighbour_infos
            .get(&ppfx)
            .filter(|pinfo| {
                pinfo.version() < new_elders_info_version
                    && self.our_prefix().is_neighbour(&spfx)
                    && !self.state.neighbour_infos.contains_key(&spfx)
            })
            .cloned()
        {
            let _ = self.state.neighbour_infos.insert(spfx, sinfo);
        }

        self.check_and_clean_neighbour_infos(Some(&pfx));
        Ok(())
    }

    pub fn combine_signatures_for_section_proof_block(
        &self,
        key_info: SectionKeyInfo,
        proofs: AccumulatingProof,
    ) -> Result<SectionProofBlock, RoutingError> {
        let signature = self
            .check_and_combine_signatures(&key_info, proofs)
            .ok_or(RoutingError::InvalidNewSectionInfo)?;
        Ok(SectionProofBlock::new(key_info, signature))
    }

    pub fn check_and_combine_signatures<S: Serialize + Debug>(
        &self,
        signed_payload: &S,
        proofs: AccumulatingProof,
    ) -> Option<BlsSignature> {
        let signed_bytes = serialise(signed_payload)
            .map_err(|err| {
                log_or_panic!(
                    LogLevel::Error,
                    "{} Failed to serialise accumulated event: {:?} for {:?}",
                    self,
                    err,
                    signed_payload
                );
                err
            })
            .ok()?;

        proofs
            .check_and_combine_signatures(
                self.our_info(),
                self.our_section_bls_keys(),
                &signed_bytes,
            )
            .or_else(|| {
                log_or_panic!(
                    LogLevel::Error,
                    "{} Failed to combine signatures for accumulated event: {:?}",
                    self,
                    signed_payload
                );
                None
            })
    }

    /// Inserts the `version` of our own section into `their_knowledge` for `pfx`.
    pub fn update_their_knowledge(&mut self, prefix: Prefix<XorName>, version: u64) {
        trace!(
            "{:?} attempts to update their_knowledge of our elders_info with version {:?} for \
             prefix {:?} ",
            self.our_id(),
            version,
            prefix
        );
        self.state.update_their_knowledge(prefix, version);
    }

    /// Updates `their_keys` in the shared state
    pub fn update_their_keys(&mut self, key_info: &SectionKeyInfo) {
        trace!(
            "{:?} attempts to update their_keys for {:?} ",
            self.our_id(),
            key_info,
        );
        self.state.update_their_keys(key_info);
    }

    /// Returns whether we should split into two sections.
    fn should_split(&self) -> Result<bool, RoutingError> {
        if self.state.split_in_progress {
            return Ok(false);
        }

        let our_name = self.our_id.name();
        let our_prefix_bit_count = self.our_prefix().bit_count();
        let (our_new_size, sibling_new_size) = self
            .elders_and_adults()
            .map(|id| our_name.common_prefix(id.name()) > our_prefix_bit_count)
            .fold((0, 0), |(ours, siblings), is_our_prefix| {
                if is_our_prefix {
                    (ours + 1, siblings)
                } else {
                    (ours, siblings + 1)
                }
            });

        // If either of the two new sections will not contain enough entries, return `false`.
        let safe_section_size = self.safe_section_size();
        Ok(our_new_size >= safe_section_size && sibling_new_size >= safe_section_size)
    }

    /// Splits our section and generates new elders infos for the child sections.
    fn split_self(&mut self) -> Result<(EldersInfo, EldersInfo), RoutingError> {
        let next_bit = self.our_id.name().bit(self.our_prefix().bit_count());

        let our_prefix = self.our_prefix().pushed(next_bit);
        let other_prefix = self.our_prefix().pushed(!next_bit);

        let our_new_section = self.eldest_members_matching_prefix(&our_prefix);
        let other_section = self.eldest_members_matching_prefix(&other_prefix);

        let our_new_info =
            EldersInfo::new(our_new_section, our_prefix, Some(self.state.our_info()))?;
        let other_info = EldersInfo::new(other_section, other_prefix, Some(self.state.our_info()))?;

        Ok((our_new_info, other_info))
    }

    /// Update our version which has signed the neighbour infos to whichever latest version
    /// possible.
    ///
    /// If we want to do for a particular `NeighbourInfo` then supply that else we will go over the
    /// entire list.
    fn check_and_clean_neighbour_infos(&mut self, _for_pfx: Option<&Prefix<XorName>>) {
        // Remove invalid neighbour pfx, older version of compatible pfx.
        let to_remove: Vec<Prefix<XorName>> = self
            .state
            .neighbour_infos
            .iter()
            .filter_map(|(pfx, elders_info)| {
                if !self.our_prefix().is_neighbour(pfx) {
                    // we just split making old neighbour no longer needed
                    return Some(*pfx);
                }

                // Remove older compatible neighbour prefixes.
                // DO NOT SUPPORT MERGE: Not consider newer if the older one was extension (split).
                let is_newer = |(other_pfx, other_elders_info): (&Prefix<XorName>, &EldersInfo)| {
                    other_pfx.is_compatible(pfx)
                        && other_elders_info.version() > elders_info.version()
                        && !pfx.is_extension_of(other_pfx)
                };

                if self.state.neighbour_infos.iter().any(is_newer) {
                    return Some(*pfx);
                }

                None
            })
            .collect();
        for pfx in to_remove {
            let _ = self.state.neighbour_infos.remove(&pfx);
        }
    }

    // Set of methods ported over from routing_table mostly as-is. The idea is to refactor and
    // restructure them after they've all been ported over.

    /// Returns an iterator over all neighbouring sections and our own, together with their prefix
    /// in the map.
    pub fn all_sections(&self) -> impl Iterator<Item = (&Prefix<XorName>, &EldersInfo)> {
        self.state.neighbour_infos.iter().chain(iter::once((
            self.state.our_info().prefix(),
            self.state.our_info(),
        )))
    }

    /// Finds the `count` names closest to `name` in the whole routing table.
    fn closest_known_names(
        &self,
        name: &XorName,
        count: usize,
        connected_peers: &[&XorName],
    ) -> Vec<XorName> {
        self.all_sections()
            .sorted_by(|&(pfx0, _), &(pfx1, _)| pfx0.cmp_distance(&pfx1, name))
            .into_iter()
            .flat_map(|(_, si)| {
                si.member_names()
                    .sorted_by(|name0, name1| name.cmp_distance(name0, name1))
            })
            .filter(|name| connected_peers.contains(&name))
            .take(count)
            .copied()
            .collect_vec()
    }

    /// Returns the `count` closest entries to `name` in the routing table, including our own name,
    /// sorted by ascending distance to `name`. If we are not close, returns `None`.
    pub fn closest_names(
        &self,
        name: &XorName,
        count: usize,
        connected_peers: &[&XorName],
    ) -> Option<Vec<XorName>> {
        let result = self.closest_known_names(name, count, connected_peers);
        if result.contains(&&self.our_id().name()) {
            Some(result)
        } else {
            None
        }
    }

    /// Returns the prefix of the closest non-empty section to `name`, regardless of whether `name`
    /// belongs in that section or not, and the section itself.
    pub(crate) fn closest_section_info(&self, name: XorName) -> (&Prefix<XorName>, &EldersInfo) {
        let mut best_pfx = self.our_prefix();
        let mut best_info = self.our_info();
        for (ref pfx, ref info) in &self.state.neighbour_infos {
            // TODO: Remove the first check after verifying that section infos are never empty.
            if !info.is_empty() && best_pfx.cmp_distance(pfx, &name) == Ordering::Greater {
                best_pfx = pfx;
                best_info = info;
            }
        }
        (best_pfx, best_info)
    }

    /// Returns the known sections sorted by the distance from a given XorName.
    fn closest_sections_info(&self, name: XorName) -> Vec<(&Prefix<XorName>, &EldersInfo)> {
        let mut result: Vec<_> = iter::once((self.our_prefix(), self.our_info()))
            .chain(self.state.neighbour_infos.iter())
            .collect();
        result.sort_by(|lhs, rhs| lhs.0.cmp_distance(rhs.0, &name));
        result
    }

    /// Returns a set of nodes to which a message for the given `Authority` could be sent
    /// onwards, sorted by priority, along with the number of targets the message should be sent to.
    /// If the total number of targets returned is larger than this number, the spare targets can
    /// be used if the message can't be delivered to some of the initial ones.
    ///
    /// * If the destination is an `Authority::Section`:
    ///     - if our section is the closest on the network (i.e. our section's prefix is a prefix of
    ///       the destination), returns all other members of our section; otherwise
    ///     - returns the `N/3` closest members of the RT to the target
    ///
    /// * If the destination is an `Authority::PrefixSection`:
    ///     - if the prefix is compatible with our prefix and is fully-covered by prefixes in our
    ///       RT, returns all members in these prefixes except ourself; otherwise
    ///     - if the prefix is compatible with our prefix and is *not* fully-covered by prefixes in
    ///       our RT, returns `Err(Error::CannotRoute)`; otherwise
    ///     - returns the `N/3` closest members of the RT to the lower bound of the target
    ///       prefix
    ///
    /// * If the destination is a group (`ClientManager`, `NaeManager` or `NodeManager`):
    ///     - if our section is the closest on the network (i.e. our section's prefix is a prefix of
    ///       the destination), returns all other members of our section; otherwise
    ///     - returns the `N/3` closest members of the RT to the target
    ///
    /// * If the destination is an individual node (`ManagedNode` or `Client`):
    ///     - if our name *is* the destination, returns an empty set; otherwise
    ///     - if the destination name is an entry in the routing table, returns it; otherwise
    ///     - returns the `N/3` closest members of the RT to the target
    pub fn targets(
        &self,
        dst: &Authority<XorName>,
    ) -> Result<(Vec<&P2pNode>, usize), RoutingError> {
        let candidates = |target_name: &XorName| {
            let filtered_sections =
                self.closest_sections_info(*target_name)
                    .into_iter()
                    .map(|(prefix, members)| {
                        (
                            prefix,
                            members.len(),
                            members.member_nodes().collect::<Vec<_>>(),
                        )
                    });

            let mut dg_size = 0;
            let mut nodes_to_send = Vec::new();
            for (idx, (prefix, len, connected)) in filtered_sections.enumerate() {
                nodes_to_send.extend(connected.into_iter());
                dg_size = delivery_group_size(len);

                if prefix == self.our_prefix() {
                    // Send to all connected targets so they can forward the message
                    let our_name = self.our_id().name();
                    nodes_to_send.retain(|&node| node.name() != our_name);
                    dg_size = nodes_to_send.len();
                    break;
                }
                if idx == 0 && nodes_to_send.len() >= dg_size {
                    // can deliver to enough of the closest section
                    break;
                }
            }
            nodes_to_send.sort_by(|lhs, rhs| target_name.cmp_distance(lhs.name(), rhs.name()));

            if dg_size > 0 && nodes_to_send.len() >= dg_size {
                Ok((dg_size, nodes_to_send))
            } else {
                Err(RoutingError::CannotRoute)
            }
        };

        let (dg_size, best_section) = match *dst {
            Authority::Node(ref target_name) => {
                if target_name == self.our_id().name() {
                    return Ok((Vec::new(), 0));
                }
                if let Some(node) = self.get_p2p_node(target_name) {
                    return Ok((vec![node], 1));
                }
                candidates(target_name)?
            }
            Authority::Section(ref target_name) => {
                let (prefix, section) = self.closest_section_info(*target_name);
                if prefix == self.our_prefix() || prefix.is_neighbour(self.our_prefix()) {
                    // Exclude our name since we don't need to send to ourself
                    let our_name = self.our_id().name();

                    // FIXME: only doing this for now to match RT.
                    // should confirm if needed esp after msg_relay changes.
                    let section: Vec<_> = section
                        .member_nodes()
                        .filter(|node| node.name() != our_name)
                        .collect();
                    let dg_size = section.len();
                    return Ok((section, dg_size));
                }
                candidates(target_name)?
            }
            Authority::PrefixSection(ref prefix) => {
                if prefix.is_compatible(self.our_prefix()) || prefix.is_neighbour(self.our_prefix())
                {
                    // only route the message when we have all the targets in our routing table -
                    // this is to prevent spamming the network by sending messages with
                    // intentionally short prefixes
                    if prefix.is_compatible(self.our_prefix())
                        && !prefix.is_covered_by(self.prefixes().iter())
                    {
                        return Err(RoutingError::CannotRoute);
                    }

                    let is_compatible = |(pfx, section)| {
                        if prefix.is_compatible(pfx) {
                            Some(section)
                        } else {
                            None
                        }
                    };

                    // Exclude our name since we don't need to send to ourself
                    let our_name = self.our_id().name();

                    let targets = self
                        .all_sections()
                        .filter_map(is_compatible)
                        .flat_map(EldersInfo::member_nodes)
                        .filter(|node| node.name() != our_name)
                        .collect::<Vec<_>>();
                    let dg_size = targets.len();
                    return Ok((targets, dg_size));
                }
                candidates(&prefix.lower_bound())?
            }
        };

        Ok((best_section, dg_size))
    }

    /// Returns whether we are a part of the given authority.
    pub fn in_authority(&self, auth: &Authority<XorName>) -> bool {
        match *auth {
            Authority::Node(ref name) => self.our_id().name() == name,
            Authority::Section(ref name) => self.our_prefix().matches(name),
            Authority::PrefixSection(ref prefix) => self.our_prefix().is_compatible(prefix),
        }
    }

    /// Compute an estimate of the size of the network from the size of our routing table.
    ///
    /// Return (estimate, exact), with exact = true iff we have the whole network in our
    /// routing table.
    pub fn network_size_estimate(&self) -> (u64, bool) {
        let known_prefixes = self.prefixes();
        let is_exact = Prefix::default().is_covered_by(known_prefixes.iter());

        // Estimated fraction of the network that we have in our RT.
        // Computed as the sum of 1 / 2^(prefix.bit_count) for all known section prefixes.
        let network_fraction: f64 = known_prefixes
            .iter()
            .map(|p| 1.0 / (p.bit_count() as f64).exp2())
            .sum();

        // Total size estimate = known_nodes / network_fraction
        let network_size = self.elders().count() as f64 / network_fraction;

        (network_size.ceil() as u64, is_exact)
    }

    fn assert_no_prefix_change(&self, label: &str) {
        if self.state.split_in_progress {
            log_or_panic!(
                LogLevel::Warn,
                "{} - attempt to {} during prefix change.",
                self,
                label,
            );
        }
    }

    /// Check if we know this node but have not yet processed it.
    pub fn is_in_online_backlog(&self, pub_id: &PublicId) -> bool {
        self.state.churn_event_backlog.iter().any(|evt| {
            if let AccumulatingEvent::Online(payload) = &evt.content {
                payload.p2p_node.public_id() == pub_id
            } else {
                false
            }
        })
    }
}

impl Debug for Chain {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        writeln!(formatter, "Chain {{")?;
        writeln!(formatter, "\tour_id: {},", self.our_id)?;
        writeln!(formatter, "\tour_version: {}", self.state.our_version())?;
        writeln!(formatter, "\tis_elder: {},", self.is_elder)?;
        writeln!(
            formatter,
            "\tsplit_in_progress: {}",
            self.state.split_in_progress
        )?;

        writeln!(formatter, "\tour_infos: len {}", self.state.our_infos.len())?;
        for info in self.state.our_infos() {
            writeln!(formatter, "\t{}", info)?;
        }

        writeln!(formatter, "\tneighbour_infos:")?;
        for (pfx, info) in &self.state.neighbour_infos {
            writeln!(formatter, "\t {:?}\t {}", pfx, info)?;
        }

        writeln!(formatter, "}}")
    }
}

impl Display for Chain {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Node({}({:b}))", self.our_id(), self.state.our_prefix())
    }
}

#[cfg(any(test, feature = "mock_base"))]
impl Chain {
    /// Returns the members of the section with the given prefix (if it exists)
    pub fn get_section(&self, pfx: &Prefix<XorName>) -> Option<&EldersInfo> {
        if self.our_prefix() == pfx {
            Some(self.our_info())
        } else {
            self.state.neighbour_infos.get(pfx)
        }
    }
}

#[cfg(feature = "mock_base")]
impl Chain {
    /// Returns the total number of entries in the routing table, excluding our own name.
    pub fn len(&self) -> usize {
        self.state
            .neighbour_infos
            .values()
            .map(|info| info.len())
            .sum::<usize>()
            + self.state.our_info().len()
            - 1
    }

    /// Returns our section info with the given hash, if it exists.
    pub fn our_info_by_hash(&self, hash: &Digest256) -> Option<&EldersInfo> {
        self.state.our_info_by_hash(hash)
    }

    /// If our section is the closest one to `name`, returns all names in our section *including
    /// ours*, otherwise returns `None`.
    pub fn close_names(&self, name: &XorName) -> Option<Vec<XorName>> {
        if self.our_prefix().matches(name) {
            Some(self.our_info().member_names().copied().collect())
        } else {
            None
        }
    }

    /// If our section is the closest one to `name`, returns all names in our section *excluding
    /// ours*, otherwise returns `None`.
    pub fn other_close_names(&self, name: &XorName) -> Option<BTreeSet<XorName>> {
        if self.our_prefix().matches(name) {
            let mut section: BTreeSet<_> = self.our_info().member_names().copied().collect();
            let _ = section.remove(&self.our_id().name());
            Some(section)
        } else {
            None
        }
    }

    /// Returns their_knowledge
    pub fn get_their_knowledge(&self) -> &BTreeMap<Prefix<XorName>, u64> {
        &self.state.get_their_knowledge()
    }

    /// Return a minimum length prefix, favouring our prefix if it is one of the shortest.
    pub fn min_len_prefix(&self) -> Prefix<XorName> {
        *iter::once(self.our_prefix())
            .chain(self.state.neighbour_infos.keys())
            .min_by_key(|prefix| prefix.bit_count())
            .unwrap_or(&self.our_prefix())
    }

    /// Returns the age counter of the given member or `None` if not a member.
    pub fn member_age_counter(&self, name: &XorName) -> Option<u32> {
        self.state
            .our_members
            .get(name)
            .map(|member| member.age_counter_value())
    }
}

#[cfg(test)]
impl Chain {
    pub fn validate_our_history(&self) -> bool {
        self.state.our_history.validate()
    }
}

fn key_matching_first_elder_name(
    elders_info: &EldersInfo,
    mut name_to_key: BTreeMap<XorName, DkgResult>,
) -> Result<DkgResult, RoutingError> {
    let first_name = elders_info
        .member_names()
        .next()
        .ok_or(RoutingError::InvalidElderDkgResult)?;
    name_to_key
        .remove(first_name)
        .ok_or(RoutingError::InvalidElderDkgResult)
}

/// The outcome of successful accumulated poll
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum PollAccumulated {
    AccumulatedEvent(AccumulatedEvent),
    RelocateDetails(RelocateDetails),
    PromoteDemoteElders(Vec<EldersInfo>),
}

/// The outcome of a prefix change.
pub struct ParsecResetData {
    /// The new genesis prefix info.
    pub gen_pfx_info: GenesisPfxInfo,
    /// The cached events that should be revoted.
    pub cached_events: BTreeSet<NetworkEvent>,
    /// The completed events.
    pub completed_events: BTreeSet<AccumulatingEvent>,
}

/// The secret share of the section key.
#[derive(Clone)]
pub struct SectionKeyShare {
    /// Index used to combine signature share and get PublicKeyShare from PublicKeySet.
    pub index: usize,
    /// Secret Key share
    pub key: BlsSecretKeyShare,
}

impl SectionKeyShare {
    /// Create a new share with associated share index.
    #[cfg(any(test, feature = "mock_base"))]
    pub fn new_with_position(index: usize, key: BlsSecretKeyShare) -> Self {
        Self { index, key }
    }

    /// create a new share finding the position wihtin the elders.
    pub fn new(
        key: BlsSecretKeyShare,
        our_id: &PublicId,
        new_elders_info: &EldersInfo,
    ) -> Option<Self> {
        Some(Self {
            index: new_elders_info.member_ids().position(|id| id == our_id)?,
            key,
        })
    }
}

/// All the key material needed to sign or combine signature for our section key.
#[derive(Clone)]
pub struct SectionKeys {
    /// Public key set to verify threshold signatures and combine shares.
    pub public_key_set: BlsPublicKeySet,
    /// Secret Key share and index. None if the node was not participating in the DKG.
    pub secret_key_share: Option<SectionKeyShare>,
}

impl SectionKeys {
    pub fn new(dkg_result: DkgResult, our_id: &PublicId, new_elders_info: &EldersInfo) -> Self {
        Self {
            public_key_set: dkg_result.public_key_set,
            secret_key_share: dkg_result
                .secret_key_share
                .and_then(|key| SectionKeyShare::new(key, our_id, new_elders_info)),
        }
    }
}

struct EldersChangeBuilder {
    old_own: BTreeSet<P2pNode>,
    old_neighbour: BTreeSet<P2pNode>,
}

impl EldersChangeBuilder {
    fn new(chain: &Chain) -> Self {
        Self {
            old_own: chain.our_info().member_nodes().cloned().collect(),
            old_neighbour: chain.neighbour_elder_nodes().cloned().collect(),
        }
    }

    fn build(self, chain: &Chain) -> EldersChange {
        let new_neighbour: BTreeSet<_> = chain.neighbour_elder_nodes().cloned().collect();
        let new_own: BTreeSet<_> = chain.our_info().member_nodes().cloned().collect();
        EldersChange {
            neighbour_added: new_neighbour
                .difference(&self.old_neighbour)
                .cloned()
                .collect(),
            neighbour_removed: self
                .old_neighbour
                .difference(&new_neighbour)
                .cloned()
                .collect(),
            own_added: new_own.difference(&self.old_own).cloned().collect(),
            own_removed: self.old_own.difference(&new_own).cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{EldersInfo, EventSigPayload, GenesisPfxInfo, MIN_AGE_COUNTER};
    use super::*;
    use crate::{
        id::{FullId, P2pNode, PublicId},
        parsec::generate_bls_threshold_secret_key,
        quorum_count, rng,
        rng::MainRng,
        unwrap,
        xor_space::{Prefix, XorName},
        BlsSecretKeySet, ConnectionInfo,
    };
    use rand::{seq::SliceRandom, Rng};
    use std::{
        collections::{BTreeMap, HashMap},
        str::FromStr,
    };

    enum SecInfoGen<'a> {
        New(Prefix<XorName>, usize),
        Add(&'a EldersInfo),
        Remove(&'a EldersInfo),
    }

    fn gen_section_info(
        rng: &mut MainRng,
        gen: SecInfoGen,
    ) -> (EldersInfo, HashMap<PublicId, FullId>) {
        match gen {
            SecInfoGen::New(pfx, n) => {
                let mut full_ids = HashMap::new();
                let mut members = BTreeMap::new();
                for _ in 0..n {
                    let some_id = FullId::within_range(rng, &pfx.range_inclusive());
                    let connection_info = ConnectionInfo {
                        peer_addr: ([127, 0, 0, 1], 9999).into(),
                        peer_cert_der: vec![],
                    };
                    let pub_id = *some_id.public_id();
                    let _ = members.insert(*pub_id.name(), P2pNode::new(pub_id, connection_info));
                    let _ = full_ids.insert(*some_id.public_id(), some_id);
                }
                (EldersInfo::new(members, pfx, None).unwrap(), full_ids)
            }
            SecInfoGen::Add(info) => {
                let mut members = info.member_map().clone();
                let some_id = FullId::within_range(rng, &info.prefix().range_inclusive());
                let connection_info = ConnectionInfo {
                    peer_addr: ([127, 0, 0, 1], 9999).into(),
                    peer_cert_der: vec![],
                };
                let pub_id = *some_id.public_id();
                let _ = members.insert(*pub_id.name(), P2pNode::new(pub_id, connection_info));
                let mut full_ids = HashMap::new();
                let _ = full_ids.insert(pub_id, some_id);
                (
                    EldersInfo::new(members, *info.prefix(), Some(info)).unwrap(),
                    full_ids,
                )
            }
            SecInfoGen::Remove(info) => {
                let members = info.member_map().clone();
                (
                    EldersInfo::new(members, *info.prefix(), Some(info)).unwrap(),
                    Default::default(),
                )
            }
        }
    }

    fn add_neighbour_elders_info(
        chain: &mut Chain,
        neighbour_info: EldersInfo,
    ) -> Result<(), RoutingError> {
        assert!(
            !neighbour_info.prefix().matches(chain.our_id.name()),
            "Only add neighbours."
        );
        chain.add_neighbour_elders_info(neighbour_info)
    }

    fn gen_chain<T>(
        rng: &mut MainRng,
        sections: T,
    ) -> (Chain, HashMap<PublicId, FullId>, BlsSecretKeySet)
    where
        T: IntoIterator<Item = (Prefix<XorName>, usize)>,
    {
        let mut full_ids = HashMap::new();
        let mut our_id = None;
        let mut section_members = vec![];
        for (pfx, size) in sections {
            let (info, ids) = gen_section_info(rng, SecInfoGen::New(pfx, size));
            if our_id.is_none() {
                our_id = Some(unwrap!(ids.values().next()).clone());
            }
            full_ids.extend(ids);
            section_members.push(info);
        }

        let our_id = unwrap!(our_id);
        let mut sections_iter = section_members.into_iter();

        let first_info = sections_iter.next().expect("section members");
        let first_ages = first_info
            .member_ids()
            .map(|pub_id| (*pub_id, MIN_AGE_COUNTER))
            .collect();

        let participants = first_info.len();
        let our_id_index = 0;
        let secret_key_set = generate_bls_threshold_secret_key(rng, participants);
        let secret_key_share = secret_key_set.secret_key_share(our_id_index);
        let public_key_set = secret_key_set.public_keys();

        let genesis_info = GenesisPfxInfo {
            first_info,
            first_bls_keys: public_key_set,
            first_state_serialized: Vec::new(),
            first_ages,
            latest_info: Default::default(),
            parsec_version: 0,
        };

        let mut chain = Chain::new(
            Default::default(),
            *our_id.public_id(),
            genesis_info,
            Some(secret_key_share),
        );

        for neighbour_info in sections_iter {
            unwrap!(add_neighbour_elders_info(&mut chain, neighbour_info));
        }

        (chain, full_ids, secret_key_set)
    }

    fn gen_00_chain(rng: &mut MainRng) -> (Chain, HashMap<PublicId, FullId>, BlsSecretKeySet) {
        let elder_size: usize = 7;
        gen_chain(
            rng,
            vec![
                (Prefix::from_str("00").unwrap(), elder_size),
                (Prefix::from_str("01").unwrap(), elder_size),
                (Prefix::from_str("10").unwrap(), elder_size),
            ],
        )
    }

    fn check_infos_for_duplication(chain: &Chain) {
        let mut prefixes: Vec<Prefix<XorName>> = vec![];
        for info in chain.neighbour_infos() {
            if let Some(pfx) = prefixes.iter().find(|x| x.is_compatible(info.prefix())) {
                panic!(
                    "Found compatible prefixes! {:?} and {:?}",
                    pfx,
                    info.prefix()
                );
            }
            prefixes.push(*info.prefix());
        }
    }

    #[test]
    fn generate_chain() {
        let mut rng = rng::new();

        let (chain, _, _) = gen_00_chain(&mut rng);
        let chain_id = *chain.our_id();

        assert_eq!(
            chain
                .get_section(&Prefix::from_str("00").unwrap())
                .map(|info| info.is_member(&chain_id)),
            Some(true)
        );
        assert_eq!(chain.get_section(&Prefix::from_str("").unwrap()), None);
        assert!(chain.validate_our_history());
        check_infos_for_duplication(&chain);
    }

    #[test]
    fn neighbour_info_cleaning() {
        let mut rng = rng::new();
        let (mut chain, _, _) = gen_00_chain(&mut rng);
        for _ in 0..100 {
            let (new_info, _new_ids) = {
                let old_info: Vec<_> = chain.neighbour_infos().collect();
                let info = old_info.choose(&mut rng).expect("neighbour infos");
                if rng.gen_bool(0.5) {
                    gen_section_info(&mut rng, SecInfoGen::Add(info))
                } else {
                    gen_section_info(&mut rng, SecInfoGen::Remove(info))
                }
            };

            unwrap!(add_neighbour_elders_info(&mut chain, new_info));
            assert!(chain.validate_our_history());
            check_infos_for_duplication(&chain);
        }
    }

    #[test]
    fn filter_invalid_relocation_signatures_succeed() {
        let elder_size: usize = 7;
        let acceptable_malicious_bls_count = (elder_size - 1) / 3;
        filter_invalid_relocation_signatures(acceptable_malicious_bls_count);
    }

    #[test]
    #[should_panic]
    fn filter_invalid_relocation_signatures_fail() {
        let elder_size: usize = 7;
        let acceptable_malicious_bls_count = (elder_size - 1) / 3;
        filter_invalid_relocation_signatures(acceptable_malicious_bls_count + 1);
    }

    fn filter_invalid_relocation_signatures(malicious_bls_count: usize) {
        //
        // Arrange
        //
        let mut rng = rng::new();
        let (mut chain, full_ids, bls_secrets) = gen_00_chain(&mut rng);
        let relocate_details = RelocateDetails {
            pub_id: *chain.our_id(),
            destination: *chain.our_id().name(),
            age: 0,
        };
        let elder_size = chain.our_info().len();
        let quorum_count = quorum_count(elder_size);
        let fake_signed_bytes: Vec<u8> = Vec::new();
        let opaque_infos = chain
            .our_info()
            .member_ids()
            .take(quorum_count)
            .map(|id| unwrap!(full_ids.get(id)))
            .map(|full_id| unwrap!(Proof::new(full_id, &fake_signed_bytes)))
            .enumerate()
            .map(|(idx, proof)| {
                let key_idx = if idx < malicious_bls_count {
                    // Use last key that won't match the given index to create
                    // invalid BLS signatures for malicious nodes.
                    elder_size - 1
                } else {
                    idx
                };
                let secret_key = bls_secrets.secret_key_share(key_idx);
                let signature = unwrap!(EventSigPayload::new(&secret_key, &relocate_details));
                (signature, proof)
            })
            .collect_vec();

        //
        // Act
        //
        for (signature, proof) in opaque_infos {
            let acc_event = AccumulatingEvent::Relocate(relocate_details.clone());
            let event = acc_event.into_network_event_with(Some(signature));
            unwrap!(chain.handle_opaque_event(&event, proof));
        }
        let chain_accumulated = chain.poll_accumulated();

        //
        // Assert
        //
        let accumulated_event = match chain_accumulated {
            Ok(Some(PollAccumulated::AccumulatedEvent(event))) => event,
            evt => panic!("unexpected {:?}", evt),
        };
        let public_key = bls_secrets.public_keys().public_key();
        let signed_bytes = unwrap!(serialise(&relocate_details));
        assert_eq!(
            accumulated_event
                .signature
                .as_ref()
                .map(|sig| public_key.verify(sig, &signed_bytes)),
            Some(true)
        );
    }
}
