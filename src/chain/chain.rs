// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    chain_accumulator::{AccumulatingProof, ChainAccumulator, InsertError},
    shared_state::{PrefixChange, SectionKeyInfo, SharedState},
    AccumulatedEvent, AccumulatingEvent, AgeCounter, DevParams, EldersChange, EldersInfo,
    GenesisPfxInfo, MemberInfo, MemberPersona, MemberState, NetworkEvent, NetworkParams, Proof,
    ProofSet, SectionProofChain,
};
use crate::{
    error::RoutingError,
    id::{P2pNode, PublicId},
    relocation::{self, RelocateDetails},
    routing_table::{Authority, Error},
    utils::LogIdent,
    BlsPublicKeySet, ConnectionInfo, Prefix, XorName, Xorable,
};
use itertools::Itertools;
use log::LogLevel;
use std::cmp::Ordering;
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    fmt::{self, Debug, Display, Formatter},
    iter, mem,
};

#[cfg(feature = "mock_base")]
use crate::crypto::Digest256;

/// Amount added to `min_section_size` when deciding whether a bucket split can happen. This helps
/// protect against rapid splitting and merging in the face of moderate churn.
const SPLIT_BUFFER: usize = 1;

/// Returns the delivery group size based on the section size `n`
pub fn delivery_group_size(n: usize) -> usize {
    // this is an integer that is ≥ n/3
    (n + 2) / 3
}

/// Data chain.
pub struct Chain {
    /// Network parameters
    network_cfg: NetworkParams,
    /// Development/testing configuration.
    dev_params: DevParams,
    /// This node's public ID.
    our_id: PublicId,
    /// The shared state of the section.
    state: SharedState,
    /// If we're an elder of the section yet. This will be toggled once we get a `EldersInfo`
    /// block accumulated which bears `our_id` as one of the members
    is_elder: bool,
    /// Accumulate NetworkEvent that do not have yet enough vote/proofs.
    chain_accumulator: ChainAccumulator,
    /// Pending events whose handling has been deferred due to an ongoing split or merge.
    event_cache: BTreeSet<NetworkEvent>,
    /// Temporary. Counting the accumulated prune events. Only used in tests until tests that
    /// actually tests pruning is in place.
    parsec_prune_accumulated: usize,
    /// Marker indicating we are processing churn event
    churn_in_progress: bool,
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

    /// Returns the number of nodes which need to exist in each subsection of a given section to
    /// allow it to be split.
    pub fn min_split_size(&self) -> usize {
        self.safe_section_size() + SPLIT_BUFFER
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
        dev_params: DevParams,
        our_id: PublicId,
        gen_info: GenesisPfxInfo,
    ) -> Self {
        // TODO validate `gen_info` to contain adequate proofs
        let is_elder = gen_info.first_info.members().contains(&our_id);
        Self {
            network_cfg,
            dev_params,
            our_id,
            state: SharedState::new(gen_info.first_info, gen_info.first_ages),
            is_elder,
            chain_accumulator: Default::default(),
            event_cache: Default::default(),
            parsec_prune_accumulated: 0,
            churn_in_progress: false,
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
        self.state
            .update_with_genesis_related_info(related_info, &LogIdent::new(self))
    }

    /// Get the serialized shared state that will be the starting point when processing
    /// parsec data
    pub fn get_genesis_related_info(&self) -> Result<Vec<u8>, RoutingError> {
        self.state.get_genesis_related_info()
    }

    fn get_age_counters(&self) -> BTreeMap<PublicId, AgeCounter> {
        self.state
            .our_members
            .iter()
            .map(|(pub_id, member_info)| (*pub_id, member_info.age_counter))
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
    /// If the event is a `EldersInfo` or `NeighbourInfo`, it also updates the corresponding
    /// containers.
    pub fn poll(&mut self) -> Result<Option<AccumulatedEvent>, RoutingError> {
        if self.state.handled_genesis_event
            && !self.churn_in_progress
            && self.state.change == PrefixChange::None
        {
            if let Some(event) = self.state.churn_event_backlog.pop_back() {
                trace!(
                    "{} churn backlog poll {:?}, Others: {:?}",
                    self,
                    event,
                    self.state.churn_event_backlog
                );
                return Ok(Some(AccumulatedEvent::new(event)));
            }
        }

        let (event, proofs) = {
            let opt_event = self
                .chain_accumulator
                .incomplete_events()
                .find(|(event, proofs)| self.is_valid_transition(event, proofs.parsec_proof_set()))
                .map(|(event, _)| event.clone());

            let opt_event_proofs = opt_event.and_then(|event| {
                self.chain_accumulator
                    .poll_event(event, self.our_info().members().clone())
            });

            match opt_event_proofs {
                None => return Ok(None),
                Some((event, proofs)) => (event, proofs),
            }
        };

        match event {
            AccumulatingEvent::SectionInfo(ref info)
            | AccumulatingEvent::NeighbourInfo(ref info) => {
                let old_neighbours: BTreeSet<_> = self.neighbour_elders_p2p().cloned().collect();
                self.add_elders_info(info.clone(), proofs)?;
                let new_neighbours: BTreeSet<_> = self.neighbour_elders_p2p().cloned().collect();

                if let Some((ref cached_info, _)) = self.state.split_cache {
                    if cached_info == info {
                        return Ok(None);
                    }
                }

                let neighbour_change = EldersChange {
                    added: new_neighbours
                        .difference(&old_neighbours)
                        .cloned()
                        .collect(),
                    removed: old_neighbours
                        .difference(&new_neighbours)
                        .cloned()
                        .collect(),
                };

                return Ok(Some(
                    AccumulatedEvent::new(event).with_neighbour_change(neighbour_change),
                ));
            }
            AccumulatingEvent::TheirKeyInfo(ref key_info) => {
                self.update_their_keys(key_info);
            }
            AccumulatingEvent::AckMessage(ref ack_payload) => {
                self.update_their_knowledge(ack_payload.src_prefix, ack_payload.ack_version);
            }
            AccumulatingEvent::OurMerge => {
                // use new_info here as our_info might still be accumulating signatures
                // and we'd want to perform the merge eventually with our current latest state.
                let our_hash = *self.state.new_info.hash();
                let _ = self.state.merging.insert(our_hash);
                self.state.change = PrefixChange::Merging;
                panic!(
                    "Merge not supported: AccumulatingEvent::OurMerge {:?}: {:?}",
                    self.our_id(),
                    self.state.new_info
                );
            }
            AccumulatingEvent::NeighbourMerge(digest) => {
                // TODO: Check that the section is known and not already merged.
                let _ = self.state.merging.insert(digest);
            }
            AccumulatingEvent::ParsecPrune => {
                info!(
                    "{} Handling accumulated {:?} not yet implemented, ignoring.",
                    self, event
                );
                // TODO: remove once we have real integration tests of `ParsecPrune` accumulating.
                self.parsec_prune_accumulated += 1;
            }
            AccumulatingEvent::Relocate(_) => {
                self.churn_in_progress = false;
                let signature = proofs.combine_signatures(&self.public_key_set());
                return Ok(Some(AccumulatedEvent::new(event).with_signature(signature)));
            }
            AccumulatingEvent::Online(_)
            | AccumulatingEvent::Offline(_)
            | AccumulatingEvent::StartDkg(_)
            | AccumulatingEvent::User(_)
            | AccumulatingEvent::SendAckMessage(_) => (),
        }

        let start_churn_event = match event {
            AccumulatingEvent::Online(_) | AccumulatingEvent::Offline(_) => true,
            _ => false,
        };

        if start_churn_event && self.churn_in_progress {
            trace!(
                "{} churn backlog {:?}, Other: {:?}",
                self,
                event,
                self.state.churn_event_backlog
            );
            self.state.churn_event_backlog.push_front(event);
            return Ok(None);
        }

        Ok(Some(AccumulatedEvent::new(event)))
    }

    // Increment the age counters of the members.
    pub fn increment_age_counters(&mut self, trigger_node: &PublicId) {
        if self.state.our_joined_members().count() >= self.safe_section_size()
            && self
                .state
                .get_persona(trigger_node)
                .map(|persona| persona == MemberPersona::Infant)
                .unwrap_or(true)
        {
            // Do nothing for infants and unknown nodes
            return;
        }

        let our_prefix = *self.state.our_prefix();
        let mut details_to_add = Vec::new();

        for (pub_id, member_info) in self.state.our_joined_members_mut() {
            if pub_id == trigger_node {
                continue;
            }

            if !member_info.increment_age_counter() {
                continue;
            }

            let destination = compute_relocation_destination(
                pub_id.name(),
                trigger_node.name(),
                &mut self.dev_params,
            );
            if our_prefix.matches(&destination) {
                // Relocation destination inside the current section - ignoring.
                continue;
            }

            details_to_add.push(RelocateDetails {
                pub_id: *pub_id,
                destination,
                age: member_info.age() + 1,
            })
        }

        for details in details_to_add {
            self.state.relocate_queue.push_front(details)
        }
    }

    /// Returns the details of the next scheduled relocation to be voted for, if any.
    pub fn poll_relocation(&mut self) -> Option<RelocateDetails> {
        // Delay relocation until all backlogged churn events have been handled and no
        // additional churn is in progress.
        if self.churn_in_progress || !self.state.churn_event_backlog.is_empty() {
            return None;
        }

        let details = self.state.relocate_queue.pop_back()?;

        if self.is_peer_our_elder(&details.pub_id) {
            let num_elders = self.our_elders().len();
            if num_elders <= self.elder_size() {
                warn!(
                    "{} - Not relocating {} - not enough elders in the section ({}/{}).",
                    self,
                    details.pub_id,
                    num_elders,
                    self.elder_size() + 1,
                );

                // Keep the details in the queue so when we gain more elders we can try to relocate
                // the node again.
                self.state.relocate_queue.push_back(details);

                return None;
            }
        }

        self.churn_in_progress = true;

        Some(details)
    }

    /// Validate if can call add_member on this node.
    pub fn can_add_member(&mut self, pub_id: &PublicId) -> bool {
        self.our_prefix().matches(pub_id.name()) && !self.is_peer_our_member(pub_id)
    }

    /// Validate if can call remove_member on this node.
    pub fn can_remove_member(&mut self, pub_id: &PublicId) -> bool {
        self.is_peer_our_member(pub_id)
    }

    /// Adds a member to our section.
    pub fn add_member(&mut self, p2p_node: P2pNode, age: u8) {
        self.assert_no_prefix_change("add member");

        let pub_id = *p2p_node.public_id();

        match self.state.our_members.entry(pub_id) {
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
                        pub_id
                    );
                    return;
                }
            }
            Entry::Vacant(entry) => {
                // Node joining for the first time.
                let _ = entry.insert(MemberInfo::new(age, p2p_node.connection_info().clone()));
            }
        }

        // TODO: switch this to true only when the new member is going to be immediately promoted
        // to elder.
        self.churn_in_progress = true;
    }

    /// Remove a member from our section.
    pub fn remove_member(&mut self, pub_id: &PublicId) {
        self.assert_no_prefix_change("remove member");

        if let Some(info) = self
            .state
            .our_members
            .get_mut(&pub_id)
            .filter(|info| info.state == MemberState::Joined)
        {
            info.state = MemberState::Left;

            // TODO: switch this to true only if the member is elder.
            self.churn_in_progress = true;
        } else {
            log_or_panic!(
                LogLevel::Error,
                "{} - Removing member that doesn't exists: {}",
                self,
                pub_id
            );
        }
    }

    /// Adds an elder to our section, creating a new `EldersInfo` in the process.
    /// If we need to split also returns an additional sibling `EldersInfo`.
    /// Should not be called while a pfx change is in progress.
    pub fn add_elder(&mut self, pub_id: PublicId) -> Result<Vec<EldersInfo>, RoutingError> {
        self.assert_no_prefix_change("add elder");

        if !self.our_prefix().matches(&pub_id.name()) {
            log_or_panic!(
                LogLevel::Error,
                "{} - Adding elder {} whose name does not match our prefix {:?}.",
                self,
                pub_id,
                self.our_prefix()
            );
        }

        // We already have the connection info from when it was added online.
        let connection_info = self
            .get_member_connection_info(&pub_id)
            .ok_or(RoutingError::PeerNotFound(pub_id))?;

        let mut elders_p2p = self.state.new_info.p2p_members().clone();
        let _ = elders_p2p.insert(P2pNode::new(pub_id, connection_info.clone()));

        // TODO: the split decision should be based on the number of all members, not just elders.
        if self.should_split(&elders_p2p)? {
            let (our_info, other_info) = self.split_self(elders_p2p.clone())?;
            self.state.change = PrefixChange::Splitting;
            return Ok(vec![our_info, other_info]);
        }

        self.state.new_info = EldersInfo::new(
            elders_p2p,
            *self.state.new_info.prefix(),
            Some(&self.state.new_info),
        )?;

        Ok(vec![self.state.new_info.clone()])
    }

    /// Removes an elder from our section, creating a new `our_info` in the process.
    /// Should not be called while a pfx change is in progress.
    pub fn remove_elder(&mut self, pub_id: PublicId) -> Result<EldersInfo, RoutingError> {
        self.assert_no_prefix_change("remove elder");

        let mut elders = self.state.new_info.p2p_members().clone();
        let connection_info = self
            .get_member_connection_info(&pub_id)
            .ok_or(RoutingError::PeerNotFound(pub_id))?;
        let p2p_node = P2pNode::new(pub_id, connection_info.clone());
        let _ = elders.remove(&p2p_node);

        if self.our_id() == &pub_id {
            self.is_elder = false;
        }

        self.state.new_info = EldersInfo::new(
            elders,
            *self.state.new_info.prefix(),
            Some(&self.state.new_info),
        )?;

        if self.state.new_info.members().len() < self.elder_size() {
            // set to merge state to prevent extending chain any further.
            // We'd still not Vote for OurMerge until we've updated our_infos
            self.state.change = PrefixChange::Merging;
            panic!(
                "Merge not supported: remove_member < min_sec_size {:?}: {:?}",
                self.our_id(),
                self.state.new_info
            );
        }

        Ok(self.state.new_info.clone())
    }

    /// Returns the next section info if both we and our sibling have signalled for merging.
    pub fn try_merge(&mut self) -> Result<Option<EldersInfo>, RoutingError> {
        self.state.try_merge()
    }

    /// Returns `true` if we have accumulated self `AccumulatingEvent::OurMerge`.
    pub fn is_self_merge_ready(&self) -> bool {
        self.state.is_self_merge_ready()
    }

    /// Returns `true` if we should merge.
    pub fn should_vote_for_merge(&self) -> bool {
        self.state
            .should_vote_for_merge(self.elder_size(), self.neighbour_infos())
    }

    /// Gets the data needed to initialise a new Parsec instance
    pub fn prepare_parsec_reset(&mut self) -> Result<ParsecResetData, RoutingError> {
        let remaining = self.chain_accumulator.reset_accumulator(&self.our_id);
        let event_cache = mem::replace(&mut self.event_cache, Default::default());
        let merges = mem::replace(&mut self.state.merging, Default::default())
            .into_iter()
            .map(|digest| AccumulatingEvent::NeighbourMerge(digest).into_network_event());

        self.state.handled_genesis_event = false;

        Ok(ParsecResetData {
            gen_pfx_info: GenesisPfxInfo {
                first_info: self.our_info().clone(),
                first_state_serialized: self.get_genesis_related_info()?,
                first_ages: self.get_age_counters(),
                latest_info: Default::default(),
            },
            cached_events: remaining
                .cached_events
                .into_iter()
                .chain(event_cache)
                .chain(merges)
                .collect(),
            completed_events: remaining.completed_events,
        })
    }

    /// Finalises a split or merge - creates a `GenesisPfxInfo` for the new graph and returns the
    /// cached and currently accumulated events.
    pub fn finalise_prefix_change(&mut self) -> Result<ParsecResetData, RoutingError> {
        // Clear any relocation overrides
        #[cfg(feature = "mock_base")]
        {
            self.dev_params.next_relocation_dst = None;
            self.dev_params.next_relocation_interval = None;
        }

        // TODO: Bring back using their_knowledge to clean_older section in our_infos
        self.check_and_clean_neighbour_infos(None);
        self.state.change = PrefixChange::None;

        info!("{} - finalise_prefix_change: {:?}", self, self.our_prefix());
        trace!("{} - finalise_prefix_change state: {:?}", self, self.state);

        self.prepare_parsec_reset()
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

    /// Returns whether our section is in the process of changing (splitting or merging).
    pub fn prefix_change(&self) -> PrefixChange {
        self.state.change
    }

    /// Neighbour infos signed by our section
    pub fn neighbour_infos(&self) -> impl Iterator<Item = &EldersInfo> {
        self.state.neighbour_infos.values()
    }

    /// Return prefixes of all our neighbours
    pub fn other_prefixes(&self) -> BTreeSet<Prefix<XorName>> {
        self.state.neighbour_infos.keys().cloned().collect()
    }

    /// Check if the given `PublicId` is a member of our section.
    pub fn is_peer_our_member(&self, pub_id: &PublicId) -> bool {
        self.state
            .our_members
            .get(pub_id)
            .map(|info| info.state == MemberState::Joined)
            .unwrap_or(false)
    }

    /// Returns the `ConnectioInfo` for a member of our section.
    pub fn get_member_connection_info(&self, pub_id: &PublicId) -> Option<&ConnectionInfo> {
        self.state
            .our_members
            .get(&pub_id)
            .map(|member_info| &member_info.connection_info)
    }

    /// Returns a set of elders we should be connected to.
    pub fn elders_p2p(&self) -> impl Iterator<Item = &P2pNode> {
        self.neighbour_infos()
            .chain(iter::once(self.state.our_info()))
            .flat_map(EldersInfo::p2p_members)
            .chain(self.state.new_info.p2p_members())
    }

    /// Returns a set of elders we should be connected to.
    // WIP: consider removing me
    pub fn elders(&self) -> impl Iterator<Item = &PublicId> {
        self.elders_p2p().map(P2pNode::public_id)
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
        self.state.our_info().members().contains(pub_id)
            || self.state.new_info.members().contains(pub_id)
    }

    /// Returns whether the given peer is elder in one of our neighbour sections.
    pub fn is_peer_neighbour_elder(&self, pub_id: &PublicId) -> bool {
        self.neighbour_infos()
            .any(|info| info.members().contains(pub_id))
    }

    /// Returns elders from our own section according to the latest accumulated `SectionInfo`.
    pub fn our_elders(&self) -> impl Iterator<Item = &P2pNode> + ExactSizeIterator {
        self.state.our_info().p2p_members().iter()
    }

    /// Returns all neighbour elders.
    pub fn neighbour_elders_p2p(&self) -> impl Iterator<Item = &P2pNode> {
        self.neighbour_infos().flat_map(EldersInfo::p2p_members)
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

    /// Returns the index of the public key in our_history that will be trusted by the target
    /// Authority
    fn proving_index(&self, target: &Authority<XorName>) -> u64 {
        self.state
            .their_knowledge
            .iter()
            .filter(|(prefix, _)| target.is_compatible(prefix))
            .map(|(_, index)| *index)
            .min()
            .unwrap_or(0)
    }

    /// Provide a SectionProofChain that proves the given signature to the section with a given
    /// prefix
    pub fn prove(&self, target: &Authority<XorName>) -> SectionProofChain {
        let first_index = self.proving_index(target);
        self.state.our_history.slice_from(first_index as usize)
    }

    /// Check which nodes are unresponsive.
    pub fn check_vote_status(&mut self) -> BTreeSet<PublicId> {
        let members = self.our_info().members().clone();
        self.chain_accumulator.check_vote_status(&members)
    }

    /// Returns `true` if the given `NetworkEvent` is already accumulated and can be skipped.
    fn should_skip_accumulator(&self, event: &NetworkEvent) -> bool {
        // FIXME: may also need to handle non SI votes to not get handled multiple times
        let si = match event.payload {
            AccumulatingEvent::SectionInfo(ref si) | AccumulatingEvent::NeighbourInfo(ref si) => si,
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
            AccumulatingEvent::SectionInfo(ref info) => {
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
                    info.prefix().is_compatible(i.prefix()) && *info.version() != (i.version() + 1)
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
            | AccumulatingEvent::Relocate(_) => {
                self.state.change == PrefixChange::None && self.our_info().is_quorum(proofs)
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
                self.state.change == PrefixChange::None
                    && self.our_info().is_total_consensus(proofs)
            }
            AccumulatingEvent::OurMerge | AccumulatingEvent::NeighbourMerge(_) => {
                self.our_info().is_quorum(proofs)
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
        // TODO: is the merge state check even needed in the following match?
        // we only seem to set self.state = Merging after accumulation of OurMerge
        match (self.state.change, &event.payload) {
            (PrefixChange::None, _)
            | (PrefixChange::Merging, AccumulatingEvent::OurMerge)
            | (PrefixChange::Merging, AccumulatingEvent::NeighbourMerge(_)) => true,
            (_, AccumulatingEvent::SectionInfo(elders_info))
            | (_, AccumulatingEvent::NeighbourInfo(elders_info)) => {
                if elders_info.prefix().is_compatible(self.our_prefix())
                    && elders_info.version() > self.state.new_info.version()
                {
                    log_or_panic!(
                        LogLevel::Error,
                        "We shouldn't have progressed past the split/merged version."
                    );
                    return false;
                }
                true
            }
            (_, _) => false, // Don't want to handle any events other than `EldersInfo`.
        }
    }

    /// Store given event if created by us for use later on.
    fn cache_event(
        &mut self,
        net_event: &NetworkEvent,
        sender_id: &PublicId,
    ) -> Result<(), RoutingError> {
        if self.state.change == PrefixChange::None {
            log_or_panic!(
                LogLevel::Error,
                "Shouldn't be caching events while not splitting or merging."
            );
        }
        if self.our_id == *sender_id {
            let _ = self.event_cache.insert(net_event.clone());
        }
        Ok(())
    }

    /// Handles our own section info, or the section info of our sibling directly after a split.
    fn add_elders_info(
        &mut self,
        info: EldersInfo,
        proofs: AccumulatingProof,
    ) -> Result<(), RoutingError> {
        // Split handling alone. wouldn't cater to merge
        if info.prefix().is_extension_of(self.our_prefix()) {
            match self.state.split_cache.take() {
                None => {
                    self.state.split_cache = Some((info, proofs));
                    return Ok(());
                }
                Some((cache_info, cache_proofs)) => {
                    let cache_pfx = *cache_info.prefix();

                    // Add our_info first so when we add sibling info, its a valid neighbour prefix
                    // which does not get immediately purged.
                    if cache_pfx.matches(self.our_id.name()) {
                        self.do_add_elders_info(cache_info, cache_proofs)?;
                        self.do_add_elders_info(info, proofs)?;
                    } else {
                        self.do_add_elders_info(info, proofs)?;
                        self.do_add_elders_info(cache_info, cache_proofs)?;
                    }
                    return Ok(());
                }
            }
        }

        self.do_add_elders_info(info, proofs)
    }

    fn do_add_elders_info(
        &mut self,
        elders_info: EldersInfo,
        proofs: AccumulatingProof,
    ) -> Result<(), RoutingError> {
        let pfx = *elders_info.prefix();
        if pfx.matches(self.our_id.name()) {
            let is_new_elder = !self.is_elder && elders_info.members().contains(&self.our_id);
            let pk_set = self.public_key_set();
            self.state.push_our_new_info(elders_info, proofs, &pk_set)?;

            if is_new_elder {
                self.is_elder = true;
            }
            self.churn_in_progress = false;
            self.check_and_clean_neighbour_infos(None);
        } else {
            let ppfx = elders_info.prefix().popped();
            let spfx = elders_info.prefix().sibling();
            let new_elders_info_version = *elders_info.version();

            if let Some(old_elders_info) = self.state.neighbour_infos.insert(pfx, elders_info) {
                if *old_elders_info.version() > new_elders_info_version {
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
                    *pinfo.version() < new_elders_info_version
                        && self.our_prefix().is_neighbour(&spfx)
                        && !self.state.neighbour_infos.contains_key(&spfx)
                })
                .cloned()
            {
                let _ = self.state.neighbour_infos.insert(spfx, sinfo);
            }

            self.check_and_clean_neighbour_infos(Some(&pfx));
        }
        Ok(())
    }

    pub(crate) fn public_key_set(&self) -> BlsPublicKeySet {
        BlsPublicKeySet::from_elders_info(self.our_info().clone())
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
    fn should_split(&self, members: &BTreeSet<P2pNode>) -> Result<bool, RoutingError> {
        if self.state.change != PrefixChange::None || self.should_vote_for_merge() {
            return Ok(false);
        }

        let new_size = members
            .iter()
            .filter(|p2p_node| {
                self.our_id
                    .name()
                    .common_prefix(p2p_node.public_id().name())
                    > self.our_prefix().bit_count()
            })
            .count();
        let min_split_size = self.min_split_size();
        // If either of the two new sections will not contain enough entries, return `false`.
        Ok(new_size >= min_split_size && members.len() >= min_split_size + new_size)
    }

    /// Splits our section and generates new section infos for the child sections.
    fn split_self(
        &mut self,
        members: BTreeSet<P2pNode>,
    ) -> Result<(EldersInfo, EldersInfo), RoutingError> {
        let next_bit = self.our_id.name().bit(self.our_prefix().bit_count());

        let our_prefix = self.our_prefix().pushed(next_bit);
        let other_prefix = self.our_prefix().pushed(!next_bit);

        let (our_new_section, other_section) = members
            .into_iter()
            .partition(|p2p_node| our_prefix.matches(p2p_node.name()));

        let our_new_info =
            EldersInfo::new(our_new_section, our_prefix, Some(&self.state.new_info))?;
        let other_info = EldersInfo::new(other_section, other_prefix, Some(&self.state.new_info))?;

        self.state.new_info = our_new_info.clone();
        self.state
            .remove_our_members_not_matching_prefix(&our_prefix);

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
                    .into_iter()
                    .sorted_by(|name0, name1| name.cmp_distance(name0, name1))
            })
            .filter(|name| connected_peers.contains(&name))
            .take(count)
            .collect_vec()
    }

    /// Returns whether the table contains the given `name`.
    fn has(&self, name: &XorName) -> bool {
        self.get_section_legacy(name)
            .map_or(false, |section| section.contains(name))
    }

    /// Returns the section matching the given `name`, if present.
    /// Includes our own name in the case that our prefix matches `name`.
    fn get_section_legacy(&self, name: &XorName) -> Option<BTreeSet<XorName>> {
        if self.our_prefix().matches(name) {
            return Some(self.our_info().member_names());
        }
        self.state
            .neighbour_infos
            .iter()
            .find(|&(ref pfx, _)| pfx.matches(name))
            .map(|(_, ref info)| info.member_names())
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
    pub(crate) fn closest_section(&self, name: &XorName) -> (Prefix<XorName>, BTreeSet<XorName>) {
        let mut best_pfx = *self.our_prefix();
        let mut best_info = self.our_info();
        for (pfx, info) in &self.state.neighbour_infos {
            // TODO: Remove the first check after verifying that section infos are never empty.
            if !info.members().is_empty() && best_pfx.cmp_distance(&pfx, name) == Ordering::Greater
            {
                best_pfx = *pfx;
                best_info = info;
            }
        }
        (best_pfx, best_info.member_names())
    }

    /// Returns the known sections sorted by the distance from a given XorName.
    fn closest_sections(&self, name: &XorName) -> Vec<(Prefix<XorName>, BTreeSet<XorName>)> {
        let mut result = vec![(*self.our_prefix(), self.our_info().member_names())];
        for (pfx, info) in &self.state.neighbour_infos {
            result.push((*pfx, info.member_names()));
        }
        result.sort_by(|lhs, rhs| lhs.0.cmp_distance(&rhs.0, name));
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
        connected_peers: &[&XorName],
    ) -> Result<(Vec<XorName>, usize), Error> {
        // FIXME: only filtering for now to match RT.
        // should confirm if needed esp after msg_relay changes.
        let is_connected = |target_name: &XorName| connected_peers.contains(&target_name);

        let candidates = |target_name: &XorName| {
            let filtered_sections =
                self.closest_sections(target_name)
                    .into_iter()
                    .map(|(prefix, members)| {
                        (
                            prefix,
                            members.len(),
                            members.into_iter().filter(is_connected).collect::<Vec<_>>(),
                        )
                    });

            let mut dg_size = 0;
            let mut nodes_to_send = Vec::new();
            for (idx, (prefix, len, connected)) in filtered_sections.enumerate() {
                nodes_to_send.extend(connected.into_iter());
                dg_size = delivery_group_size(len);

                if &prefix == self.our_prefix() {
                    // Send to all connected targets so they can forward the message
                    nodes_to_send.retain(|&x| x != *self.our_id().name());
                    dg_size = nodes_to_send.len();
                    break;
                }
                if idx == 0 && nodes_to_send.len() >= dg_size {
                    // can deliver to enough of the closest section
                    break;
                }
            }
            nodes_to_send.sort_by(|lhs, rhs| target_name.cmp_distance(lhs, rhs));

            if dg_size > 0 && nodes_to_send.len() >= dg_size {
                Ok((dg_size, nodes_to_send))
            } else {
                Err(Error::CannotRoute)
            }
        };

        let (dg_size, best_section) = match *dst {
            Authority::Node(ref target_name) => {
                if target_name == self.our_id().name() {
                    return Ok((Vec::new(), 0));
                }
                if self.has(target_name) && is_connected(&target_name) {
                    return Ok((vec![*target_name], 1));
                }
                candidates(target_name)?
            }
            Authority::Section(ref target_name) => {
                let (prefix, section) = self.closest_section(target_name);
                if &prefix == self.our_prefix() {
                    // Exclude our name since we don't need to send to ourself
                    let mut section = section.clone();
                    let _ = section.remove(&self.our_id().name());

                    // FIXME: only doing this for now to match RT.
                    // should confirm if needed esp after msg_relay changes.
                    let section: Vec<_> = section.into_iter().filter(is_connected).collect();
                    let dg_size = section.len();
                    return Ok((section, dg_size));
                }
                candidates(target_name)?
            }
            Authority::PrefixSection(ref prefix) => {
                if prefix.is_compatible(&self.our_prefix()) {
                    // only route the message when we have all the targets in our routing table -
                    // this is to prevent spamming the network by sending messages with
                    // intentionally short prefixes
                    if !prefix.is_covered_by(self.prefixes().iter()) {
                        return Err(Error::CannotRoute);
                    }

                    let is_compatible = |(pfx, section)| {
                        if prefix.is_compatible(pfx) {
                            Some(section)
                        } else {
                            None
                        }
                    };

                    let targets = Iterator::flatten(
                        self.all_sections()
                            .filter_map(is_compatible)
                            .map(EldersInfo::member_names),
                    )
                    .filter(is_connected)
                    .filter(|name| name != self.our_id().name())
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

    /// Returns the total number of entries in the routing table, excluding our own name.
    pub fn len(&self) -> usize {
        self.state
            .neighbour_infos
            .values()
            .map(|info| info.members().len())
            .sum::<usize>()
            + self.state.our_info().members().len()
            - 1
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
        if self.state.change != PrefixChange::None {
            log_or_panic!(
                LogLevel::Warn,
                "{} - attempt to {} during prefix change.",
                self,
                label,
            );
        }
    }

    pub fn dev_params(&self) -> &DevParams {
        &self.dev_params
    }

    pub fn dev_params_mut(&mut self) -> &mut DevParams {
        &mut self.dev_params
    }
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

impl Debug for Chain {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        writeln!(formatter, "Chain {{")?;
        writeln!(formatter, "\tchange: {:?},", self.state.change)?;
        writeln!(formatter, "\tour_id: {},", self.our_id)?;
        writeln!(formatter, "\tour_version: {}", self.state.our_version())?;
        writeln!(formatter, "\tis_elder: {},", self.is_elder)?;
        writeln!(formatter, "\tnew_info: {}", self.state.new_info)?;
        writeln!(formatter, "\tmerging: {:?}", self.state.merging)?;

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
    /// Returns our section info with the given hash, if it exists.
    pub fn our_info_by_hash(&self, hash: &Digest256) -> Option<&EldersInfo> {
        self.state.our_info_by_hash(hash)
    }

    /// Returns all neighbour elders.
    // WIP: consider remove
    pub fn neighbour_elders(&self) -> impl Iterator<Item = &PublicId> {
        self.neighbour_elders_p2p().map(P2pNode::public_id)
    }

    /// If our section is the closest one to `name`, returns all names in our section *including
    /// ours*, otherwise returns `None`.
    pub fn close_names(&self, name: &XorName) -> Option<Vec<XorName>> {
        if self.our_prefix().matches(name) {
            Some(
                self.our_info()
                    .members()
                    .iter()
                    .map(|id| *id.name())
                    .collect(),
            )
        } else {
            None
        }
    }

    /// If our section is the closest one to `name`, returns all names in our section *excluding
    /// ours*, otherwise returns `None`.
    pub fn other_close_names(&self, name: &XorName) -> Option<BTreeSet<XorName>> {
        if self.our_prefix().matches(name) {
            let mut section = self.our_info().member_names();
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

    /// Get the number of accumulated `ParsecPrune` events. This is only used until we have
    /// implemented acting on the accumulated events.
    pub fn parsec_prune_accumulated(&self) -> usize {
        self.parsec_prune_accumulated
    }

    /// Return a minimum length prefix, favouring our prefix if it is one of the shortest.
    pub fn min_len_prefix(&self) -> Prefix<XorName> {
        *iter::once(self.our_prefix())
            .chain(self.state.neighbour_infos.keys())
            .min_by_key(|prefix| prefix.bit_count())
            .unwrap_or(&self.our_prefix())
    }
}

#[cfg(test)]
impl Chain {
    pub fn validate_our_history(&self) -> bool {
        self.state.our_history.validate()
    }
}

#[cfg(not(feature = "mock_base"))]
fn compute_relocation_destination(
    relocated_name: &XorName,
    trigger_name: &XorName,
    _dev_params: &mut DevParams,
) -> XorName {
    relocation::compute_destination(relocated_name, trigger_name)
}

#[cfg(feature = "mock_base")]
fn compute_relocation_destination(
    relocated_name: &XorName,
    trigger_name: &XorName,
    dev_params: &mut DevParams,
) -> XorName {
    dev_params
        .next_relocation_dst
        .take()
        .unwrap_or_else(|| relocation::compute_destination(relocated_name, trigger_name))
}

#[cfg(test)]
mod tests {
    use super::super::{
        AccumulatingProof, EldersInfo, GenesisPfxInfo, Proof, ProofSet, MIN_AGE_COUNTER,
    };
    use super::Chain;
    use crate::{
        id::{FullId, P2pNode, PublicId},
        ConnectionInfo, {Prefix, XorName},
    };
    use rand::{thread_rng, Rng};
    use serde::Serialize;
    use std::{
        collections::{BTreeSet, HashMap},
        net::SocketAddr,
        str::FromStr,
    };
    use unwrap::unwrap;

    enum SecInfoGen<'a> {
        New(Prefix<XorName>, usize),
        Add(&'a EldersInfo),
        Remove(&'a EldersInfo),
    }

    fn gen_section_info(gen: SecInfoGen) -> (EldersInfo, HashMap<PublicId, FullId>) {
        match gen {
            SecInfoGen::New(pfx, n) => {
                let mut full_ids = HashMap::new();
                let mut members = BTreeSet::new();
                for _ in 0..n {
                    let some_id = FullId::within_range(&pfx.range_inclusive());
                    let socket_addr: SocketAddr = unwrap!("127.0.0.1:9999".parse());
                    let connection_info = ConnectionInfo {
                        peer_addr: socket_addr,
                        peer_cert_der: vec![],
                    };
                    let _ = members.insert(P2pNode::new(*some_id.public_id(), connection_info));
                    let _ = full_ids.insert(*some_id.public_id(), some_id);
                }
                (EldersInfo::new(members, pfx, None).unwrap(), full_ids)
            }
            SecInfoGen::Add(info) => {
                let mut members = info.p2p_members().clone();
                let some_id = FullId::within_range(&info.prefix().range_inclusive());
                let socket_addr: SocketAddr = unwrap!("127.0.0.1:9999".parse());
                let connection_info = ConnectionInfo {
                    peer_addr: socket_addr,
                    peer_cert_der: vec![],
                };
                let _ = members.insert(P2pNode::new(*some_id.public_id(), connection_info));
                let mut full_ids = HashMap::new();
                let _ = full_ids.insert(*some_id.public_id(), some_id);
                (
                    EldersInfo::new(members, *info.prefix(), Some(info)).unwrap(),
                    full_ids,
                )
            }
            SecInfoGen::Remove(info) => {
                let members = info.p2p_members().clone();
                (
                    EldersInfo::new(members, *info.prefix(), Some(info)).unwrap(),
                    Default::default(),
                )
            }
        }
    }

    fn gen_proofs<'a, S, I>(
        full_ids: &HashMap<PublicId, FullId>,
        members: I,
        payload: &S,
    ) -> AccumulatingProof
    where
        S: Serialize,
        I: IntoIterator<Item = &'a PublicId>,
    {
        let mut proofs = ProofSet::new();
        for member in members {
            let _ = full_ids.get(member).map(|full_id| {
                let proof = unwrap!(Proof::new(full_id, payload,));
                let _ = proofs.add_proof(proof);
            });
        }
        AccumulatingProof::from_proof_set(proofs)
    }

    fn gen_chain<T>(sections: T) -> (Chain, HashMap<PublicId, FullId>)
    where
        T: IntoIterator<Item = (Prefix<XorName>, usize)>,
    {
        let mut full_ids = HashMap::new();
        let mut our_id = None;
        let mut section_members = vec![];
        for (pfx, size) in sections {
            let (info, ids) = gen_section_info(SecInfoGen::New(pfx, size));
            if our_id.is_none() {
                our_id = Some(unwrap!(ids.values().next()).clone());
            }
            full_ids.extend(ids);
            section_members.push(info);
        }

        let our_id = unwrap!(our_id);
        let mut sections_iter = section_members.into_iter();

        let first_info = sections_iter.next().expect("section members");
        let our_members = first_info.members().clone();
        let first_ages = first_info
            .members()
            .iter()
            .map(|pub_id| (*pub_id, MIN_AGE_COUNTER))
            .collect();
        let genesis_info = GenesisPfxInfo {
            first_info,
            first_state_serialized: Vec::new(),
            first_ages,
            latest_info: Default::default(),
        };

        let mut chain = Chain::new(
            Default::default(),
            Default::default(),
            *our_id.public_id(),
            genesis_info,
        );

        for neighbour_info in sections_iter {
            let proofs = gen_proofs(&full_ids, &our_members, &neighbour_info);
            unwrap!(chain.add_elders_info(neighbour_info, proofs));
        }

        (chain, full_ids)
    }

    #[test]
    fn generate_chain() {
        let (chain, _ids) = gen_chain(vec![
            (Prefix::from_str("00").unwrap(), 8),
            (Prefix::from_str("01").unwrap(), 8),
            (Prefix::from_str("10").unwrap(), 8),
        ]);
        assert!(!chain
            .get_section(&Prefix::from_str("00").unwrap())
            .expect("No section 00 found!")
            .members()
            .is_empty());
        assert!(chain.get_section(&Prefix::from_str("").unwrap()).is_none());
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
    fn neighbour_info_cleaning() {
        let mut rng = thread_rng();
        let p_00 = Prefix::from_str("00").unwrap();
        let p_01 = Prefix::from_str("01").unwrap();
        let p_10 = Prefix::from_str("10").unwrap();
        let (mut chain, mut full_ids) = gen_chain(vec![(p_00, 8), (p_01, 8), (p_10, 8)]);
        for _ in 0..1000 {
            let (new_info, new_ids) = {
                let old_info: Vec<_> = chain.neighbour_infos().collect();
                let info = rng.choose(&old_info).expect("neighbour infos");
                if rng.gen_weighted_bool(2) {
                    gen_section_info(SecInfoGen::Add(info))
                } else {
                    gen_section_info(SecInfoGen::Remove(info))
                }
            };
            full_ids.extend(new_ids);
            let proofs = gen_proofs(&full_ids, &chain.our_info().members(), &new_info);
            unwrap!(chain.add_elders_info(new_info, proofs));
            assert!(chain.validate_our_history());
            check_infos_for_duplication(&chain);
        }
    }
}
