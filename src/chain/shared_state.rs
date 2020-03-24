// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    AccumulatedEvent, AgeCounter, EldersInfo, MemberInfo, MemberPersona, MemberState,
    MIN_AGE_COUNTER,
};
use crate::{
    error::RoutingError, id::PublicId, location::DstLocation, relocation::RelocateDetails, Prefix,
    XorName,
};
use bincode::serialize;
use itertools::Itertools;
use std::{
    collections::{BTreeMap, VecDeque},
    fmt::{self, Debug, Formatter},
    iter, mem,
};

// Number of recent keys we keep: i.e how many other section churns we can handle before a
// message send with a previous version of a section is no longer trusted.
// With low churn rate, a ad hoc 20 should be big enough to avoid losing messages.
const MAX_THEIR_RECENT_KEYS: usize = 20;

/// Section state that is shared among all elders of a section via Parsec consensus.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedState {
    /// Indicate whether nodes are shared state because genesis event was seen
    #[serde(skip)]
    pub handled_genesis_event: bool,
    /// The latest few fully signed infos of our own sections.
    /// This is not a `BTreeSet` as it is ordered according to the sequence of pushes into it.
    pub our_infos: NonEmptyList<EldersInfo>,
    /// Info about all members of our section - elders, adults and infants.
    pub our_members: BTreeMap<XorName, MemberInfo>,
    /// Maps our neighbours' prefixes to their latest signed elders infos.
    /// Note that after a split, the neighbour's latest section info could be the one from the
    /// pre-split parent section, so the value's prefix doesn't always match the key.
    pub neighbour_infos: BTreeMap<Prefix<XorName>, EldersInfo>,
    /// Our section's key history for Secure Message Delivery
    pub our_history: SectionProofChain,
    /// BLS public keys of other sections
    pub their_keys: BTreeMap<Prefix<XorName>, SectionKeyInfo>,
    /// Other sections' knowledge of us
    pub their_knowledge: BTreeMap<Prefix<XorName>, u64>,
    /// Recent keys removed from their_keys
    pub their_recent_keys: VecDeque<(Prefix<XorName>, SectionKeyInfo)>,
    /// Backlog of completed events that need to be processed when churn completes.
    pub churn_event_backlog: VecDeque<AccumulatedEvent>,
    /// Queue of pending relocations.
    pub relocate_queue: VecDeque<RelocateDetails>,
}

impl SharedState {
    pub fn new(
        elders_info: EldersInfo,
        bls_keys: bls::PublicKeySet,
        ages: BTreeMap<PublicId, AgeCounter>,
    ) -> Self {
        let pk_info = SectionKeyInfo::from_elders_info(&elders_info, bls_keys.public_key());
        let our_history = SectionProofChain::from_genesis(pk_info);
        let their_key_info = our_history.last_key_info();
        let their_keys = iter::once((*their_key_info.prefix(), their_key_info.clone())).collect();

        let our_members = elders_info
            .member_nodes()
            .map(|p2p_node| {
                let info = MemberInfo {
                    age_counter: *ages.get(p2p_node.public_id()).unwrap_or(&MIN_AGE_COUNTER),
                    state: MemberState::Joined,
                    p2p_node: p2p_node.clone(),
                };
                (*p2p_node.name(), info)
            })
            .collect();

        Self {
            handled_genesis_event: false,
            our_infos: NonEmptyList::new(elders_info),
            neighbour_infos: Default::default(),
            our_members,
            our_history,
            their_keys,
            their_knowledge: Default::default(),
            their_recent_keys: Default::default(),
            churn_event_backlog: Default::default(),
            relocate_queue: VecDeque::new(),
        }
    }

    pub fn update(&mut self, new: Option<Self>) {
        if self.handled_genesis_event {
            log_or_panic!(
                log::Level::Error,
                "shared state update - genesis event already handled",
            );
        }

        if let Some(new) = new {
            if self.our_infos.len() > 1 && *self != new {
                log_or_panic!(
                    log::Level::Error,
                    "shared state update - mismatch: old: {:?} --- new: {:?}",
                    self,
                    new
                );
            }

            *self = new;
        }

        self.handled_genesis_event = true;
    }

    pub fn our_infos(&self) -> impl Iterator<Item = &EldersInfo> + DoubleEndedIterator {
        self.our_infos.iter()
    }

    /// Returns our own current section info.
    pub fn our_info(&self) -> &EldersInfo {
        self.our_infos.last()
    }

    pub fn our_prefix(&self) -> &Prefix<XorName> {
        self.our_info().prefix()
    }

    pub fn our_version(&self) -> u64 {
        self.our_info().version()
    }

    /// Returns an iterator over the members that have not state == `Left`.
    pub fn our_active_members(&self) -> impl Iterator<Item = (&XorName, &MemberInfo)> {
        self.our_members
            .iter()
            .filter(|(_, member)| member.state != MemberState::Left)
    }

    /// Returns an iterator over the members that have state == `Joined`.
    pub fn our_joined_members(&self) -> impl Iterator<Item = (&XorName, &MemberInfo)> {
        self.our_members
            .iter()
            .filter(|(_, member)| member.state == MemberState::Joined)
    }

    /// Returns mutable iterator over the members that have state == `Joined`.
    pub fn our_joined_members_mut(&mut self) -> impl Iterator<Item = (&XorName, &mut MemberInfo)> {
        self.our_members
            .iter_mut()
            .filter(|(_, member)| member.state == MemberState::Joined)
    }

    /// Returns the current persona corresponding to the given PublicId or `None` if such a member
    /// doesn't exist
    pub fn get_persona(&self, pub_id: &PublicId) -> Option<MemberPersona> {
        if self.our_info().is_member(pub_id) {
            Some(MemberPersona::Elder)
        } else {
            self.our_members.get(pub_id.name()).map(|member| {
                if member.is_mature() {
                    MemberPersona::Adult
                } else {
                    MemberPersona::Infant
                }
            })
        }
    }

    /// Remove all entries from `our_members` whose name does not match our prefix and returns them.
    pub fn remove_our_members_not_matching_our_prefix(&mut self) -> BTreeMap<XorName, MemberInfo> {
        let (our_members, sibling_members) = mem::take(&mut self.our_members)
            .into_iter()
            .partition(|(name, _)| self.our_prefix().matches(name));
        self.our_members = our_members;
        sibling_members
    }

    pub fn push_our_new_info(&mut self, elders_info: EldersInfo, proof_block: SectionProofBlock) {
        self.our_history.push(proof_block);
        self.our_infos.push(elders_info);

        let key_info = self.our_history.last_key_info().clone();
        self.update_their_keys(&key_info);
    }

    /// Updates the entry in `their_keys` for `prefix` to the latest known key; if a split
    /// occurred in the meantime, the keys for sections covering the rest of the address space are
    /// initialised to the old key that was stored for their common ancestor
    /// NOTE: the function as it is currently is not merge-safe.
    pub fn update_their_keys(&mut self, key_info: &SectionKeyInfo) {
        if let Some((&old_pfx, old_version)) = self
            .their_keys
            .iter()
            .find(|(pfx, _)| pfx.is_compatible(key_info.prefix()))
            .map(|(pfx, info)| (pfx, info.version()))
        {
            if old_version >= key_info.version() || old_pfx.is_extension_of(key_info.prefix()) {
                // Do not overwrite newer version or prefix extensions
                return;
            }

            let old_key_info = self
                .their_keys
                .remove(&old_pfx)
                .expect("Bug in BTreeMap for update_their_keys");

            self.their_recent_keys
                .push_front((old_pfx, old_key_info.clone()));
            if self.their_recent_keys.len() > MAX_THEIR_RECENT_KEYS {
                let _ = self.their_recent_keys.pop_back();
            }

            trace!("    from {:?} to {:?}", old_key_info, key_info);

            let old_pfx_sibling = old_pfx.sibling();
            let mut current_pfx = key_info.prefix().sibling();
            while !self.their_keys.contains_key(&current_pfx) && current_pfx != old_pfx_sibling {
                let _ = self.their_keys.insert(current_pfx, old_key_info.clone());
                current_pfx = current_pfx.popped().sibling();
            }
        }
        let _ = self.their_keys.insert(*key_info.prefix(), key_info.clone());
    }

    /// Updates the entry in `their_knowledge` for `prefix` to the `version`; if a split
    /// occurred in the meantime, the versions for sections covering the rest of the address space
    /// are initialised to the old version that was stored for their common ancestor
    /// NOTE: the function as it is currently is not merge-safe.
    pub fn update_their_knowledge(&mut self, prefix: Prefix<XorName>, version: u64) {
        if let Some((&old_pfx, &old_version)) = self
            .their_knowledge
            .iter()
            .find(|(pfx, _)| pfx.is_compatible(&prefix))
        {
            if old_version >= version || old_pfx.is_extension_of(&prefix) {
                // Do not overwrite newer version or prefix extensions
                return;
            }

            let _ = self.their_knowledge.remove(&old_pfx);

            trace!(
                "    from {:?}/{:?} to {:?}/{:?}",
                old_pfx,
                old_version,
                prefix,
                version
            );

            let old_pfx_sibling = old_pfx.sibling();
            let mut current_pfx = prefix.sibling();
            while !self.their_knowledge.contains_key(&current_pfx) && current_pfx != old_pfx_sibling
            {
                let _ = self.their_knowledge.insert(current_pfx, old_version);
                current_pfx = current_pfx.popped().sibling();
            }
        }
        let _ = self.their_knowledge.insert(prefix, version);
    }

    /// Return a relocating state of a node relocating now.
    /// Ensure that node knows enough to trust node_knowledge proving index.
    pub fn create_relocating_state(&self) -> MemberState {
        let node_knowledge = self
            .their_knowledge
            .get(self.our_prefix())
            .copied()
            .unwrap_or(0);
        MemberState::Relocating { node_knowledge }
    }

    /// Returns the reference to their_keys and any recent keys we still hold.
    pub fn get_their_key_infos(&self) -> impl Iterator<Item = (&Prefix<XorName>, &SectionKeyInfo)> {
        self.their_keys
            .iter()
            .chain(self.their_recent_keys.iter().map(|(p, k)| (p, k)))
    }

    #[cfg(feature = "mock_base")]
    /// Returns their_knowledge
    pub fn get_their_knowledge(&self) -> &BTreeMap<Prefix<XorName>, u64> {
        &self.their_knowledge
    }

    /// Returns the index of the public key in our_history that will be trusted by the target
    /// location
    pub fn proving_index(&self, target: &DstLocation) -> u64 {
        let (prefix, &index) = if let Some(pair) = self
            .their_knowledge
            .iter()
            .filter(|(prefix, _)| target.is_compatible(prefix))
            .min_by_key(|(_, index)| *index)
        {
            pair
        } else {
            return 0;
        };

        if let Some(sibling_index) = self.their_knowledge.get(&prefix.sibling()) {
            // The sibling section might not have processed the split yet, so it might still be in
            // `target`'s location. Because of that, we need to return index that would be trusted
            // by them too.
            index.min(*sibling_index)
        } else {
            index
        }
    }
}

/// Vec-like container that is guaranteed to contain at least one element.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct NonEmptyList<T> {
    head: Vec<T>,
    tail: T,
}

impl<T> NonEmptyList<T> {
    pub fn new(first: T) -> Self {
        Self {
            head: Vec::new(),
            tail: first,
        }
    }

    pub fn push(&mut self, item: T) {
        self.head.push(mem::replace(&mut self.tail, item))
    }

    pub fn len(&self) -> usize {
        self.head.len() + 1
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> + DoubleEndedIterator {
        self.head.iter().chain(iter::once(&self.tail))
    }

    pub fn last(&self) -> &T {
        &self.tail
    }
}

impl<T> Debug for NonEmptyList<T>
where
    T: Debug,
{
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "[{:?}]", self.iter().format(", "))
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SectionProofBlock {
    key_info: SectionKeyInfo,
    sig: bls::Signature,
}

impl SectionProofBlock {
    pub fn new(key_info: SectionKeyInfo, sig: bls::Signature) -> Self {
        Self { key_info, sig }
    }

    pub fn key_info(&self) -> &SectionKeyInfo {
        &self.key_info
    }

    pub fn verify_with_pk(&self, pk: bls::PublicKey) -> bool {
        if let Ok(to_verify) = self.key_info.serialise_for_signature() {
            pk.verify(&self.sig, to_verify)
        } else {
            false
        }
    }

    pub fn prefix(&self) -> &Prefix<XorName> {
        self.key_info.prefix()
    }

    pub fn version(&self) -> u64 {
        self.key_info.version()
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SectionProofSlice {
    /// The version of the section key to use as root of trust.
    version: u64,
    /// The prefix of section key to use as root of trust.
    prefix: Prefix<XorName>,
    /// chain of trust to the section, if empty use root of trust.
    blocks: Vec<SectionProofBlock>,
}

impl SectionProofSlice {
    #[cfg(any(feature = "mock_base", test))]
    pub fn from_genesis(key_info: SectionKeyInfo) -> Self {
        Self {
            version: key_info.version,
            prefix: key_info.prefix,
            blocks: Vec::new(),
        }
    }

    pub fn last_prefix_version(&self) -> (&Prefix<XorName>, u64) {
        self.blocks
            .last()
            .map(|block| (block.prefix(), block.version()))
            .unwrap_or((&self.prefix, self.version))
    }

    #[cfg(all(test, feature = "mock"))]
    pub fn all_prefix_version(&self) -> impl DoubleEndedIterator<Item = (&Prefix<XorName>, u64)> {
        iter::once((&self.prefix, self.version)).chain(
            self.blocks
                .iter()
                .map(|block| (block.prefix(), block.version())),
        )
    }

    pub fn last_new_key_info(&self) -> Option<&SectionKeyInfo> {
        self.blocks.last().map(|block| block.key_info())
    }

    fn last_trusted_key_info<'a>(
        &'a self,
        last_trusted: &'a SectionKeyInfo,
    ) -> Option<&'a SectionKeyInfo> {
        let block_offset = last_trusted.version().saturating_sub(self.version) as usize;

        if block_offset == 0 {
            if last_trusted.version() != self.version || last_trusted.prefix() != &self.prefix {
                return None;
            }
        } else if let Some(block) = self.blocks.get(block_offset - 1) {
            if block.key_info() != last_trusted {
                return None;
            }
        } else {
            // Root of trust not found
            return None;
        }

        let mut current = last_trusted;
        for block in &self.blocks[block_offset..] {
            if !validate_next_block(current, block) {
                return None;
            }

            current = block.key_info();
        }

        Some(current)
    }

    // Verify this proof chain against the given key infos.
    pub fn check_trust<'a, I>(&'a self, their_key_infos: I) -> TrustStatus<'a>
    where
        I: IntoIterator<Item = (&'a Prefix<XorName>, &'a SectionKeyInfo)>,
    {
        let first_version = self.version;
        let (last_prefix, last_version) = self.last_prefix_version();
        let inclusive_range = first_version..=last_version;

        let mut max_known_version = 0;
        let mut found_prefix_keys = false;

        for proof_key_info in their_key_infos
            .into_iter()
            .filter(|&(pfx, _)| last_prefix.is_compatible(pfx))
            .map(|(_, info)| info)
        {
            max_known_version = std::cmp::max(max_known_version, proof_key_info.version());
            found_prefix_keys = true;

            if inclusive_range.contains(&proof_key_info.version()) {
                // We can validate trust with that key: we are done.
                if let Some(trusted_info) = self.last_trusted_key_info(proof_key_info) {
                    return TrustStatus::Trusted(trusted_info.key());
                } else {
                    return TrustStatus::ProofInvalid;
                }
            }
        }

        if found_prefix_keys && self.version > max_known_version {
            TrustStatus::ProofTooNew
        } else {
            TrustStatus::ProofInvalid
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SectionProofChain {
    genesis_key_info: SectionKeyInfo,
    blocks: Vec<SectionProofBlock>,
}

impl SectionProofChain {
    pub fn from_genesis(key_info: SectionKeyInfo) -> Self {
        Self {
            genesis_key_info: key_info,
            blocks: Vec::new(),
        }
    }

    pub fn push(&mut self, block: SectionProofBlock) {
        if !validate_next_block(self.last_key_info(), &block) {
            log_or_panic!(
                log::Level::Error,
                "Invalid next block: {:?} -> {:?}",
                self.last_key_info(),
                block
            );
            return;
        }

        self.blocks.push(block)
    }

    #[cfg(test)]
    pub fn validate(&self) -> bool {
        let mut current = &self.genesis_key_info;
        for block in &self.blocks {
            if !validate_next_block(current, block) {
                return false;
            }

            current = block.key_info();
        }
        true
    }

    pub fn first_key_info(&self) -> &SectionKeyInfo {
        &self.genesis_key_info
    }

    pub fn last_key_info(&self) -> &SectionKeyInfo {
        self.blocks
            .last()
            .map(|block| block.key_info())
            .unwrap_or(&self.genesis_key_info)
    }

    pub fn slice_from(&self, first_index: usize) -> SectionProofSlice {
        if first_index == 0 || self.blocks.is_empty() {
            return SectionProofSlice {
                version: self.genesis_key_info.version,
                prefix: self.genesis_key_info.prefix,
                blocks: self.blocks.clone(),
            };
        }

        let genesis_index = std::cmp::min(first_index, self.blocks.len()) - 1;
        let genesis_key_info = self.blocks[genesis_index].key_info().clone();

        let block_first_index = genesis_index + 1;
        let blocks = if block_first_index >= self.blocks.len() {
            vec![]
        } else {
            self.blocks[block_first_index..].to_vec()
        };

        SectionProofSlice {
            version: genesis_key_info.version,
            prefix: genesis_key_info.prefix,
            blocks,
        }
    }
}

fn validate_next_block(last: &SectionKeyInfo, next: &SectionProofBlock) -> bool {
    if next.version() != last.version() + 1 {
        return false;
    }

    if !next.prefix().is_compatible(last.prefix())
        || next.prefix().bit_count() > last.prefix().bit_count() + 1
    {
        return false;
    }

    if !next.verify_with_pk(*last.key()) {
        return false;
    }

    true
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SectionKeyInfo {
    /// The section version. This increases monotonically whenever the set of elders changes.
    /// Identical to `ElderInfo`'s.
    version: u64,
    /// The section prefix. It matches all the members' names.
    prefix: Prefix<XorName>,
    /// The section BLS public key set
    key: bls::PublicKey,
}

impl SectionKeyInfo {
    pub fn new(version: u64, prefix: Prefix<XorName>, key: bls::PublicKey) -> Self {
        Self {
            version,
            prefix,
            key,
        }
    }

    pub fn from_elders_info(elders_info: &EldersInfo, key: bls::PublicKey) -> Self {
        Self::new(elders_info.version(), *elders_info.prefix(), key)
    }

    pub fn key(&self) -> &bls::PublicKey {
        &self.key
    }

    pub fn prefix(&self) -> &Prefix<XorName> {
        &self.prefix
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn serialise_for_signature(&self) -> Result<Vec<u8>, RoutingError> {
        Ok(serialize(&self)?)
    }
}

// Result of a message trust check.
#[derive(Debug)]
pub enum TrustStatus<'a> {
    // Message is trusted. Contains the latest section public key.
    Trusted(&'a bls::PublicKey),
    // Message is untrusted because the proof is invalid.
    ProofInvalid,
    // Message trust cannot be determined because the proof starts at version that is newer than
    // our latest one.
    ProofTooNew,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        chain::EldersInfo,
        id::P2pNode,
        parsec::generate_bls_threshold_secret_key,
        rng::{self, MainRng},
        unwrap, FullId, Prefix, XorName,
    };
    use rand::Rng;
    use std::{collections::BTreeMap, str::FromStr};

    fn gen_elders_info(rng: &mut MainRng, pfx: Prefix<XorName>, version: u64) -> EldersInfo {
        let sec_size = 5;
        let mut members = BTreeMap::new();
        (0..sec_size).for_each(|index| {
            let pub_id = *FullId::within_range(rng, &pfx.range_inclusive()).public_id();
            let _ = members.insert(
                pub_id,
                P2pNode::new(pub_id, ([127, 0, 0, 1], 9000 + index).into()),
            );
        });
        unwrap!(EldersInfo::new_for_test(members, pfx, version))
    }

    // start_pfx: the prefix of our section as string
    // updates: our section prefix followed by the prefixes of the sections we update the keys for,
    //          in sequence; every entry in the vector will get its own key.
    // expected: vec of pairs (prefix, index)
    //           the prefix is the prefix of the section whose key we check
    //           the index is the index in the `updates` vector, which should have generated the
    //           key we expect to get for the given prefix
    fn update_keys_and_check(rng: &mut MainRng, updates: Vec<&str>, expected: Vec<(&str, usize)>) {
        update_keys_and_check_with_version(rng, updates.into_iter().enumerate().collect(), expected)
    }

    fn update_keys_and_check_with_version(
        rng: &mut MainRng,
        updates: Vec<(usize, &str)>,
        expected: Vec<(&str, usize)>,
    ) {
        // Arrange
        //
        let keys_to_update = updates
            .into_iter()
            .map(|(version, pfx_str)| {
                let pfx = unwrap!(Prefix::<XorName>::from_str(pfx_str));
                let elders_info = gen_elders_info(rng, pfx, version as u64);
                let bls_keys = generate_bls_threshold_secret_key(rng, 1).public_keys();
                let key_info =
                    SectionKeyInfo::from_elders_info(&elders_info, bls_keys.public_key());
                (key_info, elders_info, bls_keys)
            })
            .collect::<Vec<_>>();
        let expected_keys = expected
            .into_iter()
            .map(|(pfx_str, index)| {
                let pfx = unwrap!(Prefix::<XorName>::from_str(pfx_str));
                (pfx, Some(index))
            })
            .collect::<Vec<_>>();

        let mut state = {
            let start_section = unwrap!(keys_to_update.first());
            let info = start_section.1.clone();
            let keys = start_section.2.clone();
            SharedState::new(info, keys, Default::default())
        };

        // Act
        //
        for (key_info, _, _) in keys_to_update.iter().skip(1) {
            state.update_their_keys(key_info);
        }

        // Assert
        //
        let actual_keys = state
            .get_their_key_infos()
            .map(|(p, info)| {
                (
                    *p,
                    keys_to_update
                        .iter()
                        .position(|(key_info, _, _)| key_info == info),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(actual_keys, expected_keys);
    }

    #[test]
    fn single_prefix_multiple_updates() {
        update_keys_and_check(
            &mut rng::new(),
            vec!["0", "1", "1", "1", "1"],
            vec![("0", 0), ("1", 4), ("1", 3), ("1", 2), ("1", 1)],
        );
    }

    #[test]
    fn single_prefix_multiple_updates_out_of_order() {
        // Late version ignored
        update_keys_and_check_with_version(
            &mut rng::new(),
            vec![(0, "0"), (0, "1"), (2, "1"), (1, "1"), (3, "1")],
            vec![("0", 0), ("1", 4), ("1", 2), ("1", 1)],
        );
    }

    #[test]
    fn simple_split() {
        update_keys_and_check(
            &mut rng::new(),
            vec!["0", "10", "11", "101"],
            vec![("0", 0), ("100", 1), ("101", 3), ("11", 2), ("10", 1)],
        );
    }

    #[test]
    fn simple_split_out_of_order() {
        // Late version ignored
        update_keys_and_check_with_version(
            &mut rng::new(),
            vec![(0, "0"), (5, "10"), (5, "11"), (7, "101"), (6, "10")],
            vec![("0", 0), ("100", 1), ("101", 3), ("11", 2), ("10", 1)],
        );
    }

    #[test]
    fn our_section_not_sibling_of_ancestor() {
        // 01 Not the sibling of the single bit parent prefix of 111
        update_keys_and_check(
            &mut rng::new(),
            vec!["01", "1", "111"],
            vec![("01", 0), ("10", 1), ("110", 1), ("111", 2), ("1", 1)],
        );
    }

    #[test]
    fn multiple_split() {
        update_keys_and_check(
            &mut rng::new(),
            vec!["0", "1", "1011001"],
            vec![
                ("0", 0),
                ("100", 1),
                ("1010", 1),
                ("1011000", 1),
                ("1011001", 2),
                ("101101", 1),
                ("10111", 1),
                ("11", 1),
                ("1", 1),
            ],
        );
    }

    // Perform a series of updates to `their_knowledge`, then verify that the proving indices for
    // the given dst locations are as expected.
    //
    // - `updates` - pairs of (prefix, version) to pass to `update_their_knowledge`
    // - `expected_proving_indices` - pairs of (prefix, index) where the dst location name is
    //   generated such that it matches `prefix` and `index` is the expected proving index.
    fn update_their_knowledge_and_check_proving_index(
        rng: &mut MainRng,
        updates: Vec<(&str, u64)>,
        expected_proving_indices: Vec<(&str, u64)>,
    ) {
        let mut state = SharedState::new(
            gen_elders_info(rng, Default::default(), 0),
            generate_bls_threshold_secret_key(rng, 1).public_keys(),
            Default::default(),
        );

        for (prefix_str, version) in updates {
            let prefix = unwrap!(prefix_str.parse());
            state.update_their_knowledge(prefix, version);
        }

        for (dst_name_prefix_str, expected_index) in expected_proving_indices {
            let dst_name_prefix: Prefix<_> = unwrap!(dst_name_prefix_str.parse());
            let dst_name = dst_name_prefix.substituted_in(rng.gen());
            let dst = DstLocation::Section(dst_name);

            assert_eq!(state.proving_index(&dst), expected_index);
        }
    }

    #[test]
    fn update_their_knowledge_after_split_from_one_sibling() {
        let mut rng = rng::new();
        update_their_knowledge_and_check_proving_index(
            &mut rng,
            vec![("1", 1), ("10", 2)],
            vec![("10", 1), ("11", 1)],
        )
    }

    #[test]
    fn update_their_knowledge_after_split_from_both_siblings() {
        let mut rng = rng::new();
        update_their_knowledge_and_check_proving_index(
            &mut rng,
            vec![("1", 1), ("10", 2), ("11", 2)],
            vec![("10", 2), ("11", 2)],
        )
    }
}
