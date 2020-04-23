// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    consensus::{
        AccumulatedEvent, AccumulatingEvent, AccumulatingProof, ConsensusEngine, DkgResult,
        DkgResultWrapper, EldersChange, GenesisPfxInfo, NetworkEvent,
    },
    error::{Result, RoutingError},
    id::{FullId, P2pNode, PublicId},
    location::DstLocation,
    messages::{AccumulatingMessage, PlainMessage, Variant},
    network_params::NetworkParams,
    relocation::RelocateDetails,
    rng::MainRng,
    section::{EldersInfo, MemberState, SectionKeyInfo, SectionProofBlock, SharedState},
    XorName,
};
use bincode::serialize;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    mem,
    net::SocketAddr,
};

/// Data chain.
pub struct Chain {
    /// The consensus engine.
    pub consensus_engine: ConsensusEngine,
    /// Network parameters
    network_params: NetworkParams,
    /// This node's public ID.
    our_id: PublicId,
    /// Our current Section BLS keys.
    our_section_bls_keys: SectionKeys,
    /// The shared state of the section.
    state: SharedState,
    /// Marker indicating we are processing churn event
    churn_in_progress: bool,
    /// Marker indicating that elders may need to change,
    members_changed: bool,
    /// The new dkg key to use when SectionInfo completes. For lookup, use the XorName of the
    /// first member in DKG participants and new ElderInfo. We only store 2 items during split, and
    /// then members are disjoint. We are working around not having access to the prefix for the
    /// DkgResult but only the list of participants.
    new_section_bls_keys: BTreeMap<XorName, DkgResult>,
    // The accumulated info during a split pfx change.
    split_cache: Option<SplitCache>,
}

#[allow(clippy::len_without_is_empty)]
impl Chain {
    /// Returns the safe section size.
    pub fn safe_section_size(&self) -> usize {
        self.network_params.safe_section_size
    }

    /// Returns the full `NetworkParams` structure (if present)
    pub fn network_params(&self) -> NetworkParams {
        self.network_params
    }

    /// Returns the shared section state.
    pub fn state(&self) -> &SharedState {
        &self.state
    }

    pub fn our_section_bls_keys(&self) -> &bls::PublicKeySet {
        &self.our_section_bls_keys.public_key_set
    }

    pub fn our_section_bls_secret_key_share(&self) -> Result<&SectionKeyShare, RoutingError> {
        self.our_section_bls_keys
            .secret_key_share
            .as_ref()
            .ok_or(RoutingError::InvalidElderDkgResult)
    }

    /// Create a new chain given genesis information
    pub fn new(
        rng: &mut MainRng,
        network_params: NetworkParams,
        our_full_id: FullId,
        gen_info: GenesisPfxInfo,
        secret_key_share: Option<bls::SecretKeyShare>,
    ) -> Self {
        // TODO validate `gen_info` to contain adequate proofs
        let our_id = *our_full_id.public_id();
        let secret_key_share = secret_key_share
            .and_then(|key| SectionKeyShare::new(key, &our_id, &gen_info.elders_info));
        let consensus_engine = ConsensusEngine::new(rng, our_full_id, &gen_info);

        Self {
            network_params,
            our_id,
            our_section_bls_keys: SectionKeys {
                public_key_set: gen_info.public_keys.clone(),
                secret_key_share,
            },
            state: SharedState::new(gen_info.elders_info, gen_info.public_keys, gen_info.ages),
            consensus_engine,
            churn_in_progress: false,
            members_changed: false,
            new_section_bls_keys: Default::default(),
            split_cache: None,
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
        // `related_info` is empty only if this is the `first` node.
        let new_state = if !related_info.is_empty() {
            Some(bincode::deserialize(related_info)?)
        } else {
            None
        };

        // On split membership may need to be checked again.
        self.members_changed = true;
        self.state.update(new_state);

        Ok(())
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
                log_or_panic!(log::Level::Error, "Ejected previous DKG result");
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

        let (event, proofs) = match self.poll_consensus() {
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

    fn poll_consensus(&mut self) -> Option<(AccumulatingEvent, AccumulatingProof)> {
        self.consensus_engine.poll(self.state.sections.our())
    }

    fn process_accumulating(
        &mut self,
        event: AccumulatingEvent,
        proofs: AccumulatingProof,
    ) -> Result<Option<AccumulatedEvent>, RoutingError> {
        match event {
            AccumulatingEvent::Genesis {
                ref group,
                ref related_info,
            } => self.handle_genesis_event(group, related_info)?,
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
                self.state.sections.add_neighbour(info.clone());
                let change = change.build(self);

                return Ok(Some(
                    AccumulatedEvent::new(event).with_elders_change(change),
                ));
            }
            AccumulatingEvent::TheirKeyInfo(ref key_info) => {
                self.state.sections.update_keys(key_info);
            }
            AccumulatingEvent::AckMessage(ref ack_payload) => {
                self.state
                    .sections
                    .update_knowledge(ack_payload.src_prefix, ack_payload.ack_version);
            }
            AccumulatingEvent::ParsecPrune => {
                if self.churn_in_progress {
                    return Ok(None);
                }
            }
            AccumulatingEvent::DkgResult {
                ref participants,
                ref dkg_result,
            } => {
                self.handle_dkg_result_event(participants, dkg_result)?;
            }
            AccumulatingEvent::Online(_)
            | AccumulatingEvent::Offline(_)
            | AccumulatingEvent::StartDkg(_)
            | AccumulatingEvent::User(_)
            | AccumulatingEvent::Relocate(_)
            | AccumulatingEvent::RelocatePrepare(_, _)
            | AccumulatingEvent::SendAckMessage(_) => (),
        }

        Ok(Some(AccumulatedEvent::new(event)))
    }

    pub fn poll_churn_event_backlog(&mut self) -> Option<AccumulatedEvent> {
        if self.can_poll_churn() {
            if let Some(event) = self.state.churn_event_backlog.pop_back() {
                trace!(
                    "churn backlog poll {:?}, Others: {:?}",
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
            AccumulatingEvent::Online(_)
            | AccumulatingEvent::Offline(_)
            | AccumulatingEvent::Relocate(_) => true,
            _ => false,
        };

        if start_churn_event && !self.can_poll_churn() {
            trace!(
                "churn backlog {:?}, Other: {:?}",
                event,
                self.state.churn_event_backlog
            );
            self.state.churn_event_backlog.push_front(event);
            return Ok(None);
        }

        Ok(Some(event))
    }

    /// Returns the details of the next scheduled relocation to be voted for, if any.
    fn poll_relocation(&mut self) -> Option<RelocateDetails> {
        // Delay relocation until no additional churn is in progress.
        if !self.can_poll_churn() {
            return None;
        }

        self.state.poll_relocation()
    }

    fn can_poll_churn(&self) -> bool {
        self.state.handled_genesis_event && !self.churn_in_progress
    }

    /// Adds a member to our section.
    ///
    /// # Panics
    ///
    /// Panics if churn is in progress
    pub fn add_member(&mut self, p2p_node: P2pNode, age: u8) -> bool {
        assert!(!self.churn_in_progress);

        let added = self
            .state
            .add_member(p2p_node, age, self.safe_section_size());

        if added {
            self.members_changed = true;
        }

        added
    }

    /// Remove a member from our section. Returns the SocketAddr and the state of the member before
    /// the removal.
    ///
    /// # Panics
    ///
    /// Panics if churn is in progress
    pub fn remove_member(&mut self, pub_id: &PublicId) -> (Option<SocketAddr>, MemberState) {
        assert!(!self.churn_in_progress);

        let (addr, state) = self.state.remove_member(pub_id, self.safe_section_size());

        if addr.is_some() {
            self.members_changed = true;
        }

        (addr, state)
    }

    /// Generate a new section info based on the current set of members.
    /// Returns a set of EldersInfos to vote for.
    fn promote_and_demote_elders(&mut self) -> Result<Option<Vec<EldersInfo>>, RoutingError> {
        if !self.members_changed || !self.can_poll_churn() {
            // Nothing changed that could impact elder set, or we cannot process it yet.
            return Ok(None);
        }

        let new_infos = self
            .state
            .promote_and_demote_elders(self.our_id.name(), &self.network_params)?;
        self.churn_in_progress = new_infos.is_some();
        self.members_changed = false;

        Ok(new_infos)
    }

    /// Gets the data needed to initialise a new Parsec instance
    pub fn prepare_parsec_reset(&mut self) -> Result<ParsecResetData, RoutingError> {
        self.state.handled_genesis_event = false;
        self.state.sections.prune_neighbours();
        let cached_events = self.consensus_engine.prepare_reset(&self.our_id);

        Ok(ParsecResetData {
            gen_pfx_info: GenesisPfxInfo {
                elders_info: self.state.our_info().clone(),
                public_keys: self.our_section_bls_keys().clone(),
                state_serialized: serialize(&self.state)?,
                ages: self.state.our_members.get_age_counters(),
                parsec_version: self.consensus_engine.parsec_version() + 1,
            },
            cached_events,
        })
    }

    /// Returns whether we are elder in our section.
    pub fn is_self_elder(&self) -> bool {
        self.state.is_peer_our_elder(&self.our_id)
    }

    // Signs and proves the given message and wraps it in `AccumulatingMessage`.
    pub fn to_accumulating_message(
        &self,
        dst: DstLocation,
        variant: Variant,
        node_knowledge_override: Option<u64>,
    ) -> Result<AccumulatingMessage> {
        let proof = self.state.prove(&dst, node_knowledge_override);
        let pk_set = self.our_section_bls_keys().clone();
        let secret_key = self.our_section_bls_secret_key_share()?;

        let content = PlainMessage {
            src: *self.state.our_prefix(),
            dst,
            variant,
        };

        AccumulatingMessage::new(content, secret_key, pk_set, proof)
    }

    /// Check which nodes are unresponsive.
    pub fn check_vote_status(&mut self) -> BTreeSet<PublicId> {
        let members = self.state.our_info().member_ids();
        self.consensus_engine.check_vote_status(members)
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
        if elders_info
            .prefix()
            .is_extension_of(self.state.our_prefix())
        {
            match self.split_cache.take() {
                None => {
                    self.split_cache = Some(SplitCache {
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
                        self.state.sections.add_neighbour(elders_info);
                    } else {
                        self.do_add_elders_info(elders_info, key_info, proofs)?;
                        self.state.sections.add_neighbour(cache.elders_info);
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
        let proof_block = self.combine_signatures_for_section_proof_block(key_info, proofs)?;
        let our_new_key =
            key_matching_first_elder_name(&elders_info, mem::take(&mut self.new_section_bls_keys))?;

        self.state.push_our_new_info(elders_info, proof_block);
        self.our_section_bls_keys =
            SectionKeys::new(our_new_key, &self.our_id, self.state.our_info());
        self.churn_in_progress = false;
        self.state.sections.prune_neighbours();
        self.state.remove_our_members_not_matching_our_prefix();
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
    ) -> Option<bls::Signature> {
        let signed_bytes = serialize(signed_payload)
            .map_err(|err| {
                log_or_panic!(
                    log::Level::Error,
                    "Failed to serialise accumulated event: {:?} for {:?}",
                    err,
                    signed_payload
                );
                err
            })
            .ok()?;

        proofs
            .check_and_combine_signatures(
                self.state.our_info(),
                self.our_section_bls_keys(),
                &signed_bytes,
            )
            .or_else(|| {
                log_or_panic!(
                    log::Level::Error,
                    "Failed to combine signatures for accumulated event: {:?}",
                    signed_payload
                );
                None
            })
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
    pub cached_events: Vec<NetworkEvent>,
}

/// The secret share of the section key.
#[derive(Clone)]
pub struct SectionKeyShare {
    /// Index used to combine signature share and get PublicKeyShare from PublicKeySet.
    pub index: usize,
    /// Secret Key share
    pub key: bls::SecretKeyShare,
}

impl SectionKeyShare {
    /// Create a new share with associated share index.
    #[cfg(any(test, feature = "mock_base"))]
    pub const fn new_with_position(index: usize, key: bls::SecretKeyShare) -> Self {
        Self { index, key }
    }

    /// create a new share finding the position wihtin the elders.
    pub fn new(
        key: bls::SecretKeyShare,
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
    pub public_key_set: bls::PublicKeySet,
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
    old_neighbour: BTreeSet<P2pNode>,
}

impl EldersChangeBuilder {
    fn new(chain: &Chain) -> Self {
        Self {
            old_neighbour: chain.state.sections.other_elders().cloned().collect(),
        }
    }

    fn build(self, chain: &Chain) -> EldersChange {
        let new_neighbour: BTreeSet<_> = chain.state.sections.other_elders().cloned().collect();

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
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SplitCache {
    elders_info: EldersInfo,
    key_info: SectionKeyInfo,
    proofs: AccumulatingProof,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{generate_bls_threshold_secret_key, GenesisPfxInfo},
        id::{FullId, P2pNode, PublicId},
        rng::{self, MainRng},
        section::{EldersInfo, MIN_AGE_COUNTER},
        unwrap,
        xor_space::{Prefix, XorName},
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
                    let peer_addr = ([127, 0, 0, 1], 9999).into();
                    let pub_id = *some_id.public_id();
                    let _ = members.insert(*pub_id.name(), P2pNode::new(pub_id, peer_addr));
                    let _ = full_ids.insert(*some_id.public_id(), some_id);
                }
                (EldersInfo::new(members, pfx, None).unwrap(), full_ids)
            }
            SecInfoGen::Add(info) => {
                let mut members = info.member_map().clone();
                let some_id = FullId::within_range(rng, &info.prefix().range_inclusive());
                let peer_addr = ([127, 0, 0, 1], 9999).into();
                let pub_id = *some_id.public_id();
                let _ = members.insert(*pub_id.name(), P2pNode::new(pub_id, peer_addr));
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

    fn add_neighbour_elders_info(chain: &mut Chain, neighbour_info: EldersInfo) {
        assert!(
            !neighbour_info.prefix().matches(chain.our_id.name()),
            "Only add neighbours."
        );
        chain.state.sections.add_neighbour(neighbour_info)
    }

    fn gen_chain<T>(
        rng: &mut MainRng,
        sections: T,
    ) -> (Chain, HashMap<PublicId, FullId>, bls::SecretKeySet)
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

        let elders_info = sections_iter.next().expect("section members");
        let ages = elders_info
            .member_ids()
            .map(|pub_id| (*pub_id, MIN_AGE_COUNTER))
            .collect();

        let participants = elders_info.len();
        let our_id_index = 0;
        let secret_key_set = generate_bls_threshold_secret_key(rng, participants);
        let secret_key_share = secret_key_set.secret_key_share(our_id_index);
        let public_key_set = secret_key_set.public_keys();

        let genesis_info = GenesisPfxInfo {
            elders_info,
            public_keys: public_key_set,
            state_serialized: Vec::new(),
            ages,
            parsec_version: 0,
        };

        let mut chain = Chain::new(
            rng,
            Default::default(),
            our_id,
            genesis_info,
            Some(secret_key_share),
        );

        for neighbour_info in sections_iter {
            add_neighbour_elders_info(&mut chain, neighbour_info);
        }

        (chain, full_ids, secret_key_set)
    }

    fn gen_00_chain(rng: &mut MainRng) -> (Chain, HashMap<PublicId, FullId>, bls::SecretKeySet) {
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
        for (_, info) in chain.state.sections.all() {
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
        let chain_id = chain.our_id;

        assert_eq!(
            chain
                .state
                .sections
                .get(&Prefix::from_str("00").unwrap())
                .map(|info| info.is_member(&chain_id)),
            Some(true)
        );
        assert_eq!(
            chain.state.sections.get(&Prefix::from_str("").unwrap()),
            None
        );
        assert!(chain.state.our_history.validate());
        check_infos_for_duplication(&chain);
    }

    #[test]
    fn neighbour_info_cleaning() {
        let mut rng = rng::new();
        let (mut chain, _, _) = gen_00_chain(&mut rng);
        for _ in 0..100 {
            let (new_info, _new_ids) = {
                let old_info: Vec<_> = chain.state.sections.other().map(|(_, info)| info).collect();
                let info = old_info.choose(&mut rng).expect("neighbour infos");
                if rng.gen_bool(0.5) {
                    gen_section_info(&mut rng, SecInfoGen::Add(info))
                } else {
                    gen_section_info(&mut rng, SecInfoGen::Remove(info))
                }
            };

            add_neighbour_elders_info(&mut chain, new_info);
            assert!(chain.state.our_history.validate());
            check_infos_for_duplication(&chain);
        }
    }
}
