// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod approved;
mod bootstrapping;
mod comm;
mod joining;

use self::{approved::Approved, bootstrapping::Bootstrapping, comm::Comm, joining::Joining};
use crate::{
    consensus::{self, Proof, Proven},
    error::{Error, Result},
    event::{Connected, Event},
    id::{FullId, P2pNode, PublicId},
    location::{DstLocation, SrcLocation},
    messages::{Message, Variant},
    network_params::NetworkParams,
    rng::MainRng,
    section::{EldersInfo, MemberInfo, SectionKeyShare, SectionProofChain, SharedState, MIN_AGE},
    timer::Timer,
    TransportConfig,
};
use bytes::Bytes;
use qp2p::IncomingConnections;
use serde::Serialize;
use std::{iter, net::SocketAddr};
use tokio::sync::mpsc;
use xor_name::{Prefix, XorName};

#[cfg(feature = "mock")]
pub use self::{bootstrapping::BOOTSTRAP_TIMEOUT, joining::JOIN_TIMEOUT};

// Type to hold the various states a node goes through during its lifetime.
#[allow(clippy::large_enum_variant)]
enum State {
    Bootstrapping(Bootstrapping),
    Joining(Joining),
    Approved(Approved),
}

// Node's information.
#[derive(Clone)]
pub(crate) struct NodeInfo {
    pub full_id: FullId,
    pub network_params: NetworkParams,
    events_tx: mpsc::UnboundedSender<Event>,
}

impl NodeInfo {
    pub fn public_id(&self) -> &PublicId {
        self.full_id.public_id()
    }

    pub fn name(&self) -> &XorName {
        self.full_id.public_id().name()
    }

    /// Send provided Event to the user which shall receive it through the EventStream
    pub fn send_event(&mut self, event: Event) {
        if let Err(err) = self.events_tx.send(event) {
            trace!("Error reporting new Event: {:?}", err);
        }
    }
}

// Node's current stage whcich is responsible
// for accessing current info and trigger operations.
pub(crate) struct Stage {
    state: State,
    comm: Comm,
}

impl Stage {
    // Private constructor
    fn new(state: State, comm: Comm) -> Result<(Self, IncomingConnections)> {
        let incoming_conns = comm.listen()?;

        let stage = Self { state, comm };

        Ok((stage, incoming_conns))
    }

    // Create the approved stage for the first node in the network.
    pub async fn first_node(
        transport_config: TransportConfig,
        full_id: FullId,
        network_params: NetworkParams,
    ) -> Result<(
        Self,
        IncomingConnections,
        mpsc::UnboundedReceiver<u64>,
        mpsc::UnboundedReceiver<Event>,
    )> {
        let comm = Comm::new(transport_config).await?;
        let connection_info = comm.our_connection_info()?;
        let p2p_node = P2pNode::new(*full_id.public_id(), connection_info);

        let mut rng = MainRng::default();
        let secret_key_set = consensus::generate_secret_key_set(&mut rng, 1);
        let public_key_set = secret_key_set.public_keys();
        let secret_key_share = secret_key_set.secret_key_share(0);

        // Note: `ElderInfo` is normally signed with the previous key, but as we are the first node
        // of the network there is no previous key. Sign with the current key instead.
        let elders_info = create_first_elders_info(&public_key_set, &secret_key_share, p2p_node)?;
        let shared_state =
            create_first_shared_state(&public_key_set, &secret_key_share, elders_info)?;

        let section_key_share = SectionKeyShare {
            public_key_set,
            index: 0,
            secret_key_share,
        };

        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let mut node_info = NodeInfo {
            full_id,
            network_params,
            events_tx,
        };

        node_info.send_event(Event::Connected(Connected::First));
        node_info.send_event(Event::PromotedToElder);

        let (timer_tx, timer_rx) = mpsc::unbounded_channel();
        let timer = Timer::new(timer_tx);

        let state = Approved::new(
            comm.clone(),
            shared_state,
            Some(section_key_share),
            node_info.clone(),
            timer,
        )?;

        let (stage, incomming_connections) = Self::new(State::Approved(state), comm)?;

        Ok((stage, incomming_connections, timer_rx, events_rx))
    }

    pub async fn bootstrap(
        transport_config: TransportConfig,
        full_id: FullId,
        network_params: NetworkParams,
    ) -> Result<(
        Self,
        IncomingConnections,
        mpsc::UnboundedReceiver<u64>,
        mpsc::UnboundedReceiver<Event>,
    )> {
        let (comm, addr) = Comm::from_bootstrapping(transport_config).await?;

        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let node_info = NodeInfo {
            full_id,
            network_params,
            events_tx,
        };

        let (timer_tx, timer_rx) = mpsc::unbounded_channel();
        let timer = Timer::new(timer_tx);

        let state =
            Bootstrapping::new(None, vec![addr], comm.clone(), node_info.clone(), timer).await?;
        let state = State::Bootstrapping(state);
        let (stage, incomming_connections) = Self::new(state, comm)?;

        Ok((stage, incomming_connections, timer_rx, events_rx))
    }

    pub fn approved(&self) -> Option<&Approved> {
        match &self.state {
            State::Approved(stage) => Some(stage),
            _ => None,
        }
    }

    /// Send provided Event to the user which shall receive it through the EventStream
    pub fn send_event(&mut self, event: Event) {
        self.node_info_mut().send_event(event);
    }

    /// Returns current FullId of the node
    pub fn full_id(&self) -> &FullId {
        &self.node_info().full_id
    }

    /// Returns connection info of this node.
    pub fn our_connection_info(&mut self) -> Result<SocketAddr> {
        self.comm.our_connection_info()
    }

    /// Send a message.
    pub async fn send_message(
        &mut self,
        src: SrcLocation,
        dst: DstLocation,
        content: Bytes,
    ) -> Result<()> {
        match &mut self.state {
            State::Approved(stage) => {
                stage
                    .send_routing_message(src, dst, Variant::UserMessage(content), None)
                    .await
            }
            _ => Err(Error::InvalidState),
        }
    }

    pub async fn send_message_to_target(
        &mut self,
        recipient: &SocketAddr,
        msg: Bytes,
    ) -> Result<()> {
        self.comm.send_message_to_target(recipient, msg).await
    }

    /// Process a message accordng to current stage.
    pub async fn process_message(&mut self, sender: SocketAddr, msg: Message) -> Result<()> {
        if !self.in_dst_location(&msg).await? {
            return Ok(());
        }

        match &mut self.state {
            State::Bootstrapping(stage) => {
                if let Some(joining) = stage.process_message(sender, msg).await? {
                    self.state = State::Joining(joining);
                }

                Ok(())
            }
            State::Joining(stage) => {
                let new_state = stage.process_message(sender, msg).await?;
                if let Some(approved) = new_state {
                    self.state = State::Approved(approved);
                }

                Ok(())
            }
            State::Approved(stage) => {
                let new_state = stage.process_message(sender, msg).await?;
                if let Some(bootstrapping) = new_state {
                    self.state = State::Bootstrapping(bootstrapping);
                }

                Ok(())
            }
        }
    }

    pub async fn process_timeout(&mut self, token: u64) -> Result<()> {
        match &mut self.state {
            State::Bootstrapping(stage) => stage.process_timeout(token).await,
            State::Joining(stage) => stage.process_timeout(token).await,
            State::Approved(stage) => stage.process_timeout(token).await,
        }
    }

    // Checks whether the given location represents self.
    async fn in_dst_location(&mut self, msg: &Message) -> Result<bool> {
        let in_dst = match &mut self.state {
            State::Bootstrapping(_) | State::Joining(_) => match msg.dst() {
                DstLocation::Node(name) => name == self.node_info().full_id.public_id().name(),
                DstLocation::Section(_) => false,
                DstLocation::Direct => true,
            },
            State::Approved(stage) => {
                let is_dst_location = msg.dst().contains(
                    stage.node_info.full_id.public_id().name(),
                    stage.shared_state.our_prefix(),
                );

                // Relay a message to the network if the message
                // is not for us, or if it is for the section.
                if !is_dst_location || msg.dst().is_section() {
                    // Relay closer to the destination or
                    // broadcast to the rest of our section.
                    stage.relay_message(msg).await?;
                }

                is_dst_location
            }
        };

        Ok(in_dst)
    }

    /// Our `Prefix` once we are a part of the section.
    pub fn our_prefix(&self) -> Option<&Prefix> {
        match &self.state {
            State::Bootstrapping(_) | State::Joining(_) => None,
            State::Approved(stage) => Some(stage.shared_state.our_prefix()),
        }
    }

    pub fn name_and_prefix(&self) -> String {
        match &self.state {
            State::Bootstrapping(state) => format!("{}(?) ", state.node_info.name()),
            State::Joining(state) => format!(
                "{}({:b}?) ",
                state.node_info.name(),
                state.target_section_elders_info().prefix,
            ),
            State::Approved(state) => {
                if state.is_our_elder(state.node_info.public_id()) {
                    format!(
                        "{}({:b}v{}!) ",
                        state.node_info.name(),
                        state.shared_state.our_prefix(),
                        state.shared_state.our_history.last_key_index()
                    )
                } else {
                    format!(
                        "{}({:b}) ",
                        state.node_info.name(),
                        state.shared_state.our_prefix()
                    )
                }
            }
        }
    }

    fn node_info(&self) -> &NodeInfo {
        match &self.state {
            State::Bootstrapping(state) => &state.node_info,
            State::Joining(state) => &state.node_info,
            State::Approved(state) => &state.node_info,
        }
    }

    fn node_info_mut(&mut self) -> &mut NodeInfo {
        match &mut self.state {
            State::Bootstrapping(state) => &mut state.node_info,
            State::Joining(state) => &mut state.node_info,
            State::Approved(state) => &mut state.node_info,
        }
    }
}

// Create `EldersInfo` for the first node.
fn create_first_elders_info(
    pk_set: &bls::PublicKeySet,
    sk_share: &bls::SecretKeyShare,
    p2p_node: P2pNode,
) -> Result<Proven<EldersInfo>> {
    let name = *p2p_node.name();
    let node = (name, p2p_node);
    let elders_info = EldersInfo::new(iter::once(node).collect(), Prefix::default());
    let proof = create_first_proof(pk_set, sk_share, &elders_info)?;
    Ok(Proven::new(elders_info, proof))
}

fn create_first_shared_state(
    pk_set: &bls::PublicKeySet,
    sk_share: &bls::SecretKeyShare,
    elders_info: Proven<EldersInfo>,
) -> Result<SharedState> {
    let mut shared_state = SharedState::new(
        SectionProofChain::new(elders_info.proof.public_key),
        elders_info,
    );

    for p2p_node in shared_state.sections.our().elders.values() {
        let member_info = MemberInfo::joined(p2p_node.clone(), MIN_AGE);
        let proof = create_first_proof(pk_set, sk_share, &member_info)?;
        let _ = shared_state
            .our_members
            .update(member_info, proof, &shared_state.our_history);
    }

    Ok(shared_state)
}

fn create_first_proof<T: Serialize>(
    pk_set: &bls::PublicKeySet,
    sk_share: &bls::SecretKeyShare,
    payload: &T,
) -> Result<Proof> {
    let bytes = bincode::serialize(payload)?;
    let signature_share = sk_share.sign(&bytes);
    let signature = pk_set
        .combine_signatures(iter::once((0, &signature_share)))
        .map_err(|_| Error::InvalidSignatureShare)?;

    Ok(Proof {
        public_key: pk_set.public_key(),
        signature,
    })
}
