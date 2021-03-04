// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    consensus::Proven,
    network::Network,
    section::{EldersInfo, Section},
};
use bls_signature_aggregator::Proof;
use xor_name::{Prefix, XorName};

/// Helper structure to make sure that during splits, our and the sibling sections are updated
/// consistently.
///
/// # Usage
///
/// Each mutation to be applied to our `Section` or `Network` must pass through this barrier
/// first. Call the corresponding handler (`handle_our_section`, `handle_their_key`) and then call
/// `take`. If it returns `Some` for our and/or sibling section, apply it to the corresponding
/// state, otherwise do nothing.
#[derive(Default)]
pub(crate) struct SplitBarrier {
    our: Option<State>,
    sibling: Option<State>,
}

impl SplitBarrier {
    pub fn handle_our_elders(
        &mut self,
        our_name: &XorName,
        current_section: &Section,
        current_network: &Network,
        elders_info: Proven<EldersInfo>,
        key_proof: Proof,
    ) {
        if elders_info
            .value
            .prefix
            .is_extension_of(current_section.prefix())
        {
            if elders_info.value.prefix.matches(our_name) {
                update(&mut self.our, current_section, current_network, |state| {
                    state.update_elders(elders_info.clone(), key_proof.clone())
                });
                update(
                    &mut self.sibling,
                    current_section,
                    current_network,
                    |state| state.update_sibling_info(elders_info, key_proof),
                );
            } else {
                update(
                    &mut self.sibling,
                    current_section,
                    current_network,
                    |state| state.update_elders(elders_info.clone(), key_proof.clone()),
                );
                update(&mut self.our, current_section, current_network, |state| {
                    state.update_sibling_info(elders_info, key_proof)
                });
            }
        } else {
            update(&mut self.our, current_section, current_network, |state| {
                state.update_elders(elders_info, key_proof)
            });
        }
    }

    pub fn handle_their_key(
        &mut self,
        our_name: &XorName,
        current_section: &Section,
        current_network: &Network,
        key: Proven<(Prefix, bls::PublicKey)>,
    ) {
        if key.value.0.matches(our_name) {
            update(
                &mut self.sibling,
                current_section,
                current_network,
                |state| state.update_their_key(key),
            )
        } else {
            update(&mut self.our, current_section, current_network, |state| {
                state.update_their_key(key)
            })
        }
    }

    // Takes out the `State` diffs to be applied to our (and siblings, in case of a split)
    // `Section` and `Network` if the invariants described above are met.
    // Returns `(our_state, sibling_state)`.
    pub fn take(&mut self, current_prefix: &Prefix) -> (Option<State>, Option<State>) {
        let our = if let Some(state) = &self.our {
            state
        } else {
            return (None, None);
        };

        if our.section.prefix() == current_prefix {
            if let Some(sibling) = &self.sibling {
                if sibling.section.prefix().is_extension_of(current_prefix) {
                    return (None, None);
                }
            } else {
                return (self.our.take(), None);
            }
        }

        let sibling = if let Some(state) = &self.sibling {
            state
        } else {
            return (None, None);
        };

        if !our.network.has_key(sibling.section.chain().last_key()) {
            return (None, None);
        }

        if our.network.get(sibling.section.prefix()) != Some(sibling.section.elders_info()) {
            return (None, None);
        }

        if !sibling.network.has_key(our.section.chain().last_key()) {
            return (None, None);
        }

        if sibling.network.get(our.section.prefix()) != Some(our.section.elders_info()) {
            return (None, None);
        }

        (self.our.take(), self.sibling.take())
    }
}

pub(crate) struct State {
    /// Info about our section.
    pub section: Section,
    /// Info about the rest of the network.
    pub network: Network,
}

impl State {
    fn update_elders(&mut self, elders_info: Proven<EldersInfo>, key_proof: Proof) -> bool {
        if self.section.update_elders(elders_info, key_proof) {
            self.network.prune_neighbours(self.section.prefix());
            true
        } else {
            false
        }
    }

    fn update_sibling_info(&mut self, elders_info: Proven<EldersInfo>, key_proof: Proof) -> bool {
        if self
            .network
            .update_neighbour_info(elders_info, Some(key_proof), self.section.chain())
        {
            self.network.prune_neighbours(self.section.prefix());
            true
        } else {
            false
        }
    }

    fn update_their_key(&mut self, key: Proven<(Prefix, bls::PublicKey)>) -> bool {
        if key.value.0 == *self.section.prefix() {
            // Ignore our keys. Use `update_elders` for that.
            return false;
        }

        self.network.update_their_key(key)
    }
}

fn update(
    barrier_state: &mut Option<State>,
    current_section: &Section,
    current_network: &Network,
    f: impl FnOnce(&mut State) -> bool,
) {
    if let Some(state) = barrier_state {
        let _ = f(state);
    } else {
        let mut state = State {
            section: current_section.clone(),
            network: current_network.clone(),
        };
        if f(&mut state) {
            *barrier_state = Some(state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::test_utils::{prove, proven},
        peer::Peer,
        section::{test_utils::gen_addr, MemberInfo},
        SectionChain, ELDER_SIZE, MIN_AGE, RECOMMENDED_SECTION_SIZE,
    };
    use anyhow::Result;
    use itertools::Itertools;
    use rand::{seq::IteratorRandom, Rng};

    #[test]
    fn split_empty_prefix() -> Result<()> {
        let mut rng = rand::thread_rng();

        let sk: bls::SecretKey = rng.gen();
        let pk = sk.public_key();

        let prefix0 = Prefix::default().pushed(false);
        let prefix1 = Prefix::default().pushed(true);

        let members0: Vec<_> = (0..RECOMMENDED_SECTION_SIZE)
            .map(|_| gen_peer(&mut rng, &prefix0))
            .collect();
        let members1: Vec<_> = (0..RECOMMENDED_SECTION_SIZE)
            .map(|_| gen_peer(&mut rng, &prefix1))
            .collect();

        let our_name = members0
            .iter()
            .chain(&members1)
            .choose(&mut rng)
            .expect("members are empty")
            .name();

        // Create the pre-split `Section`.
        let chain = SectionChain::new(pk);

        let elders = members0
            .iter()
            .chain(&members1)
            .sorted_by_key(|peer| peer.age())
            .take(ELDER_SIZE)
            .copied();

        let elders_info = EldersInfo::new(elders, Prefix::default());
        let elders_info = proven(&sk, elders_info)?;

        let mut section = Section::new(chain, elders_info)?;

        for peer in members0.iter().chain(&members1).copied() {
            let info = MemberInfo::joined(peer);
            let info = proven(&sk, info)?;
            assert!(section.update_member(info));
        }

        let network = Network::new();

        // Create the ops to trigger the split.
        let (op0, op1) = gen_ops(&mut rng, &sk, prefix0, &members0)?;
        let (op2, op3) = gen_ops(&mut rng, &sk, prefix1, &members1)?;
        let ops = [op0, op1, op2, op3];

        // Apply the ops in every possible order
        for op_sequence in ops.iter().permutations(ops.len()) {
            let mut section = section.clone();
            let mut network = network.clone();

            let mut barrier = SplitBarrier::default();
            let mut our = None;
            let mut sibling = None;

            // Apply the ops. Once the barrier produces both our and sibling states,
            // proceed to validate them.
            for op in op_sequence {
                match op {
                    Op::OurElders {
                        elders_info,
                        key_proof,
                    } => barrier.handle_our_elders(
                        our_name,
                        &section,
                        &network,
                        elders_info.clone(),
                        key_proof.clone(),
                    ),
                    Op::TheirKey(key) => {
                        barrier.handle_their_key(our_name, &section, &network, key.clone())
                    }
                }

                match barrier.take(section.prefix()) {
                    (Some(new_our), Some(new_sibling)) => {
                        our = Some(new_our);
                        sibling = Some(new_sibling);
                        break;
                    }
                    (Some(our), None) => {
                        section = our.section;
                        network = our.network;
                    }
                    (None, Some(_)) => unreachable!(),
                    (None, None) => continue,
                }
            }

            let (our, sibling) = if let (Some(our), Some(sibling)) = (our, sibling) {
                (our, sibling)
            } else {
                panic!("the barrier should have given the post-split states");
            };

            assert_ne!(our.section.chain().last_key(), &pk);
            assert_ne!(sibling.section.chain().last_key(), &pk);
            assert_ne!(
                our.section.chain().last_key(),
                sibling.section.chain().last_key()
            );

            assert!(our.network.has_key(sibling.section.chain().last_key()));
            assert!(sibling.network.has_key(our.section.chain().last_key()));

            assert_eq!(
                our.network.get(sibling.section.prefix()),
                Some(sibling.section.elders_info())
            );
            assert_eq!(
                sibling.network.get(our.section.prefix()),
                Some(our.section.elders_info())
            );
        }

        Ok(())
    }

    enum Op {
        OurElders {
            elders_info: Proven<EldersInfo>,
            key_proof: Proof,
        },
        TheirKey(Proven<(Prefix, bls::PublicKey)>),
    }

    fn gen_ops(
        rng: &mut impl Rng,
        sk: &bls::SecretKey,
        prefix: Prefix,
        members: &[Peer],
    ) -> Result<(Op, Op)> {
        let new_sk: bls::SecretKey = rng.gen();
        let new_pk = new_sk.public_key();

        let elders = members
            .iter()
            .sorted_by_key(|peer| peer.age())
            .take(ELDER_SIZE)
            .copied();
        let elders_info = EldersInfo::new(elders, prefix);
        let elders_info = proven(&new_sk, elders_info)?;
        let key_proof = prove(sk, &new_pk)?;
        let their_key = proven(sk, (prefix, new_pk))?;

        Ok((
            Op::OurElders {
                elders_info,
                key_proof,
            },
            Op::TheirKey(their_key),
        ))
    }

    fn gen_peer(rng: &mut impl Rng, prefix: &Prefix) -> Peer {
        Peer::new(
            prefix.substituted_in(rng.gen()),
            gen_addr(),
            rng.gen_range(MIN_AGE, MIN_AGE + 5),
        )
    }
}
