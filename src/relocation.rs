// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Relocation related types and utilities.

use crate::{
    crypto::{self, Keypair, Verifier},
    error::Error,
    messages::RoutingMsgUtils,
    network::NetworkUtils,
    peer::PeerUtils,
    section::{SectionPeersUtils, SectionUtils},
};
use sn_messaging::{
    node::{
        MemberInfo, Network, Peer, RelocateDetails, RelocatePayload, RelocatePromise, RoutingMsg,
        Section, SignedRelocateDetails, Variant,
    },
    MessageType,
};
use std::{marker::Sized, net::SocketAddr};
use tokio::sync::mpsc;
use xor_name::XorName;

/// Find all nodes to relocate after a churn event and create the relocate actions for them.
pub(crate) fn actions(
    section: &Section,
    network: &Network,
    churn_name: &XorName,
    churn_signature: &bls::Signature,
) -> Vec<(MemberInfo, RelocateAction)> {
    // Find the peers that pass the relocation check and take only the oldest ones to avoid
    // relocating too many nodes at the same time.
    let candidates: Vec<_> = section
        .members()
        .joined()
        .filter(|info| check(info.peer.age(), churn_signature))
        .collect();

    let max_age = if let Some(age) = candidates.iter().map(|info| (*info).peer.age()).max() {
        age
    } else {
        return vec![];
    };

    candidates
        .into_iter()
        .filter(|info| info.peer.age() == max_age)
        .map(|info| {
            (
                *info,
                RelocateAction::new(section, network, &info.peer, churn_name),
            )
        })
        .collect()
}

/// Details of a relocation: which node to relocate, where to relocate it to and what age it should
/// get once relocated.
pub trait RelocateDetailsUtils {
    fn new(section: &Section, network: &Network, peer: &Peer, destination: XorName) -> Self;

    fn with_age(
        section: &Section,
        network: &Network,
        peer: &Peer,
        destination: XorName,
        age: u8,
    ) -> RelocateDetails;
}

impl RelocateDetailsUtils for RelocateDetails {
    fn new(section: &Section, network: &Network, peer: &Peer, destination: XorName) -> Self {
        Self::with_age(
            section,
            network,
            peer,
            destination,
            peer.age().saturating_add(1),
        )
    }

    fn with_age(
        section: &Section,
        network: &Network,
        peer: &Peer,
        destination: XorName,
        age: u8,
    ) -> RelocateDetails {
        let destination_key = *network
            .key_by_name(&destination)
            .unwrap_or_else(|| section.chain().root_key());

        RelocateDetails {
            pub_id: *peer.name(),
            destination,
            destination_key,
            age,
        }
    }
}

/// RoutingMsg with Variant::Relocate in a convenient wrapper.
pub trait SignedRelocateDetailsUtils {
    fn new(signed_msg: RoutingMsg) -> Result<Self, Error>
    where
        Self: Sized;

    fn relocate_details(&self) -> Result<&RelocateDetails, Error>;

    fn signed_msg(&self) -> &RoutingMsg;

    fn destination(&self) -> Result<&XorName, Error>;
}

impl SignedRelocateDetailsUtils for SignedRelocateDetails {
    fn new(signed_msg: RoutingMsg) -> Result<Self, Error> {
        if let Variant::Relocate(_) = signed_msg.variant() {
            Ok(Self { signed_msg })
        } else {
            Err(Error::InvalidMessage)
        }
    }

    fn relocate_details(&self) -> Result<&RelocateDetails, Error> {
        if let Variant::Relocate(details) = &self.signed_msg.variant() {
            Ok(&details)
        } else {
            error!("SignedRelocateDetails does not contain Variant::Relocate");
            Err(Error::InvalidMessage)
        }
    }

    fn signed_msg(&self) -> &RoutingMsg {
        &self.signed_msg
    }

    fn destination(&self) -> Result<&XorName, Error> {
        Ok(&self.relocate_details()?.destination)
    }
}

pub trait RelocatePayloadUtils {
    fn new(details: SignedRelocateDetails, new_name: &XorName, old_keypair: &Keypair) -> Self;

    fn verify_identity(&self, new_name: &XorName) -> bool;

    fn relocate_details(&self) -> Result<&RelocateDetails, Error>;
}

impl RelocatePayloadUtils for RelocatePayload {
    fn new(details: SignedRelocateDetails, new_name: &XorName, old_keypair: &Keypair) -> Self {
        let signature_of_new_name_with_old_key = crypto::sign(&new_name.0, old_keypair);

        Self {
            details,
            signature_of_new_name_with_old_key,
        }
    }

    fn verify_identity(&self, new_name: &XorName) -> bool {
        let details = if let Ok(details) = self.details.relocate_details() {
            details
        } else {
            return false;
        };

        let pub_key = if let Ok(pub_key) = crypto::pub_key(&details.pub_id) {
            pub_key
        } else {
            return false;
        };

        pub_key
            .verify(&new_name.0, &self.signature_of_new_name_with_old_key)
            .is_ok()
    }

    fn relocate_details(&self) -> Result<&RelocateDetails, Error> {
        self.details.relocate_details()
    }
}

pub(crate) enum RelocateState {
    // Node is undergoing delayed relocation. This happens when the node is selected for relocation
    // while being an elder. It must keep fulfilling its duties as elder until its demoted, then it
    // can send the bytes (which are serialized `RelocatePromise` message) back to the elders who
    // will exchange it for an actual `Relocate` message.
    Delayed(RoutingMsg),
    // Relocation in progress. The sender is used to pass messages to the bootstrap task.
    InProgress(mpsc::Sender<(MessageType, SocketAddr)>),
}

/// Action to relocate a node.
#[derive(Debug)]
pub(crate) enum RelocateAction {
    /// Relocate the node instantly.
    Instant(RelocateDetails),
    /// Relocate the node after they are no longer our elder.
    Delayed(RelocatePromise),
}

impl RelocateAction {
    pub fn new(section: &Section, network: &Network, peer: &Peer, churn_name: &XorName) -> Self {
        let destination = destination(peer.name(), churn_name);

        if section.is_elder(peer.name()) {
            RelocateAction::Delayed(RelocatePromise {
                name: *peer.name(),
                destination,
            })
        } else {
            RelocateAction::Instant(RelocateDetails::new(section, network, peer, destination))
        }
    }

    pub fn destination(&self) -> &XorName {
        match self {
            Self::Instant(details) => &details.destination,
            Self::Delayed(promise) => &promise.destination,
        }
    }

    #[cfg(test)]
    pub fn name(&self) -> &XorName {
        match self {
            Self::Instant(details) => &details.pub_id,
            Self::Delayed(promise) => &promise.name,
        }
    }
}

// Relocation check - returns whether a member with the given age is a candidate for relocation on
// a churn event with the given signature.
pub(crate) fn check(age: u8, churn_signature: &bls::Signature) -> bool {
    // Evaluate the formula: `signature % 2^age == 0` Which is the same as checking the signature
    // has at least `age` trailing zero bits.
    trailing_zeros(&churn_signature.to_bytes()[..]) >= age as u32
}

// Compute the destination for the node with `relocating_name` to be relocated to. `churn_name` is
// the name of the joined/left node that triggered the relocation.
fn destination(relocating_name: &XorName, churn_name: &XorName) -> XorName {
    XorName::from_content(&[&relocating_name.0, &churn_name.0])
}

// Returns the number of trailing zero bits of the byte slice.
fn trailing_zeros(bytes: &[u8]) -> u32 {
    let mut output = 0;

    for &byte in bytes.iter().rev() {
        if byte == 0 {
            output += 8;
        } else {
            output += byte.trailing_zeros();
            break;
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agreement::test_utils::proven,
        peer::test_utils::arbitrary_unique_peers,
        routing::tests::SecretKeySet,
        section::{MemberInfoUtils, SectionAuthorityProviderUtils},
        ELDER_SIZE, MIN_AGE,
    };
    use anyhow::Result;
    use assert_matches::assert_matches;
    use itertools::Itertools;
    use proptest::prelude::*;
    use rand::{rngs::SmallRng, Rng, SeedableRng};
    use secured_linked_list::SecuredLinkedList;
    use sn_messaging::node::SectionAuthorityProvider;
    use xor_name::Prefix;

    #[test]
    fn byte_slice_trailing_zeros() {
        assert_eq!(trailing_zeros(&[0]), 8);
        assert_eq!(trailing_zeros(&[1]), 0);
        assert_eq!(trailing_zeros(&[2]), 1);
        assert_eq!(trailing_zeros(&[4]), 2);
        assert_eq!(trailing_zeros(&[8]), 3);
        assert_eq!(trailing_zeros(&[0, 0]), 16);
        assert_eq!(trailing_zeros(&[1, 0]), 8);
        assert_eq!(trailing_zeros(&[2, 0]), 9);
    }

    const MAX_AGE: u8 = MIN_AGE + 4;

    proptest! {
        #[test]
        fn proptest_actions(
            peers in arbitrary_unique_peers(2..ELDER_SIZE + 1, MIN_AGE..MAX_AGE),
            signature_trailing_zeros in 0..MAX_AGE,
            seed in any::<u64>().no_shrink())
        {
            proptest_actions_impl(peers, signature_trailing_zeros, seed).unwrap()
        }
    }

    fn proptest_actions_impl(
        peers: Vec<Peer>,
        signature_trailing_zeros: u8,
        seed: u64,
    ) -> Result<()> {
        let mut rng = SmallRng::seed_from_u64(seed);

        let sk_set = SecretKeySet::random();
        let sk = sk_set.secret_key();
        let pk = sk.public_key();

        // Create `Section` with `peers` as its members and set the `ELDER_SIZE` oldest peers as
        // the elders.
        let section_auth = SectionAuthorityProvider::new(
            peers
                .iter()
                .sorted_by_key(|peer| peer.age())
                .rev()
                .take(ELDER_SIZE)
                .copied(),
            Prefix::default(),
            sk_set.public_keys(),
        );
        let section_auth = proven(sk, section_auth)?;

        let mut section = Section::new(pk, SecuredLinkedList::new(pk), section_auth)?;

        for peer in &peers {
            let info = MemberInfo::joined(*peer);
            let info = proven(sk, info)?;

            assert!(section.update_member(info));
        }

        let network = Network::new();

        // Simulate a churn event whose signature has the given number of trailing zeros.
        let churn_name = rng.gen();
        let churn_signature = signature_with_trailing_zeros(signature_trailing_zeros as u32);

        let actions = actions(&section, &network, &churn_name, &churn_signature);
        let actions: Vec<_> = actions
            .into_iter()
            .map(|(_, action)| action)
            .sorted_by_key(|action| *action.name())
            .collect();

        // Only the oldest matching peers should be relocated.
        let expected_relocated_age = peers
            .iter()
            .map(Peer::age)
            .filter(|age| *age <= signature_trailing_zeros)
            .max();

        let expected_relocated_peers: Vec<_> = peers
            .iter()
            .filter(|peer| Some(peer.age()) == expected_relocated_age)
            .sorted_by_key(|peer| *peer.name())
            .collect();

        assert_eq!(expected_relocated_peers.len(), actions.len());

        // Verify the relocate action is correct depending on whether the peer is elder or not.
        // NOTE: `zip` works here, because both collections are sorted by name.
        for (peer, action) in expected_relocated_peers.into_iter().zip(actions) {
            assert_eq!(peer.name(), action.name());

            if section.is_elder(peer.name()) {
                assert_matches!(action, RelocateAction::Delayed(_));
            } else {
                assert_matches!(action, RelocateAction::Instant(_));
            }
        }

        Ok(())
    }

    // Fetch a `bls::Signature` with the given number of trailing zeros. The signature is generated
    // from an unspecified random data using an unspecified random `SecretKey`. That is OK because
    // the relocation algorithm doesn't care about whether the signature is valid. It only
    // cares about its number of trailing zeros.
    fn signature_with_trailing_zeros(trailing_zeros_count: u32) -> bls::Signature {
        use std::{cell::RefCell, collections::HashMap};

        // Cache the signatures to avoid expensive re-computation.
        thread_local! {
            static CACHE: RefCell<HashMap<u32, bls::Signature>> = RefCell::new(HashMap::new());
        }

        CACHE.with(|cache| {
            cache
                .borrow_mut()
                .entry(trailing_zeros_count)
                .or_insert_with(|| gen_signature_with_trailing_zeros(trailing_zeros_count))
                .clone()
        })
    }

    fn gen_signature_with_trailing_zeros(trailing_zeros_count: u32) -> bls::Signature {
        let mut rng = SmallRng::seed_from_u64(0);
        let sk: bls::SecretKey = rng.gen();

        loop {
            let data: u64 = rng.gen();
            let signature = sk.sign(&data.to_be_bytes());

            if trailing_zeros(&signature.to_bytes()) == trailing_zeros_count {
                return signature;
            }
        }
    }
}
