// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    client::{Client, ClientDetails},
    common::Base,
    proving_node::{ProvingNode, ProvingNodeDetails},
    relocating_node::{RelocatingNode, RelocatingNodeDetails},
};
use crate::{
    cache::Cache,
    crust::CrustUser,
    error::{InterfaceError, RoutingError},
    event::Event,
    id::{FullId, PublicId},
    messages::{DirectMessage, HopMessage, Message, Request, UserMessage},
    outbox::EventBox,
    routing_table::{Authority, Prefix},
    state_machine::{State, Transition},
    timer::Timer,
    types::RoutingActionSender,
    xor_name::XorName,
    Service,
};
use maidsafe_utilities::serialisation;
use std::{
    collections::{BTreeSet, HashSet},
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    time::Duration,
};

// Time (in seconds) after which bootstrap is cancelled (and possibly retried).
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(20);

// State to transition into after bootstrap process is complete.
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
pub enum TargetState {
    Client {
        msg_expiry_dur: Duration,
    },
    RelocatingNode,
    ProvingNode {
        old_full_id: FullId,
        our_section: (Prefix<XorName>, BTreeSet<PublicId>),
    },
}

// State of Client or Node while bootstrapping.
pub struct Bootstrapping {
    action_sender: RoutingActionSender,
    bootstrap_blacklist: HashSet<SocketAddr>,
    bootstrap_connection: Option<(PublicId, u64)>,
    cache: Box<Cache>,
    crust_service: Service,
    full_id: FullId,
    min_section_size: usize,
    target_state: TargetState,
    timer: Timer,
}

impl Bootstrapping {
    pub fn new(
        action_sender: RoutingActionSender,
        cache: Box<Cache>,
        target_state: TargetState,
        mut crust_service: Service,
        full_id: FullId,
        min_section_size: usize,
        timer: Timer,
    ) -> Option<Self> {
        match target_state {
            TargetState::Client { .. } => {
                let _ = crust_service.start_bootstrap(HashSet::new(), CrustUser::Client);
            }
            TargetState::RelocatingNode | TargetState::ProvingNode { .. } => {
                if let Err(error) = crust_service.start_listening_tcp() {
                    error!("Failed to start listening: {:?}", error);
                    return None;
                }
            }
        }
        Some(Bootstrapping {
            action_sender,
            cache: cache,
            crust_service,
            full_id,
            min_section_size,
            timer: timer,
            bootstrap_blacklist: HashSet::new(),
            bootstrap_connection: None,
            target_state,
        })
    }

    pub fn into_target_state(self, proxy_pub_id: PublicId, outbox: &mut EventBox) -> State {
        match self.target_state {
            TargetState::Client { msg_expiry_dur } => State::Client(Client::from_bootstrapping(
                ClientDetails {
                    crust_service: self.crust_service,
                    full_id: self.full_id,
                    min_section_size: self.min_section_size,
                    msg_expiry_dur,
                    proxy_pub_id,
                    timer: self.timer,
                },
                outbox,
            )),
            TargetState::RelocatingNode => {
                let details = RelocatingNodeDetails {
                    action_sender: self.action_sender,
                    cache: self.cache,
                    crust_service: self.crust_service,
                    full_id: self.full_id,
                    min_section_size: self.min_section_size,
                    proxy_pub_id,
                    timer: self.timer,
                };

                if let Some(node) = RelocatingNode::from_bootstrapping(details) {
                    State::RelocatingNode(node)
                } else {
                    outbox.send_event(Event::RestartRequired);
                    State::Terminated
                }
            }
            TargetState::ProvingNode {
                old_full_id,
                our_section,
                ..
            } => {
                let details = ProvingNodeDetails {
                    action_sender: self.action_sender,
                    cache: self.cache,
                    crust_service: self.crust_service,
                    full_id: self.full_id,
                    min_section_size: self.min_section_size,
                    old_full_id,
                    our_section,
                    proxy_pub_id,
                    timer: self.timer,
                };

                State::ProvingNode(ProvingNode::from_bootstrapping(details, outbox))
            }
        }
    }

    fn client_restriction(&self) -> bool {
        match self.target_state {
            TargetState::Client { .. } => true,
            TargetState::RelocatingNode | TargetState::ProvingNode { .. } => false,
        }
    }

    fn send_bootstrap_request(&mut self, pub_id: PublicId) {
        debug!("{} Sending BootstrapRequest to {}.", self, pub_id);

        let token = self.timer.schedule(BOOTSTRAP_TIMEOUT);
        self.bootstrap_connection = Some((pub_id, token));

        let serialised_public_id = match serialisation::serialise(self.full_id.public_id()) {
            Ok(rslt) => rslt,
            Err(e) => {
                error!("Failed to serialise public ID: {:?}", e);
                return;
            }
        };
        let signature = self
            .full_id
            .signing_private_key()
            .sign_detached(&serialised_public_id);
        let direct_message = DirectMessage::BootstrapRequest(signature);

        self.send_message(&pub_id, Message::Direct(direct_message));
    }

    fn disconnect_peer(&mut self, pub_id: &PublicId) {
        debug!(
            "{} Disconnecting {}. Calling crust::Service::disconnect.",
            self, pub_id
        );
        let _ = self.crust_service.disconnect(pub_id);
    }

    fn rebootstrap(&mut self) {
        if let Some((bootstrap_id, _)) = self.bootstrap_connection.take() {
            debug!(
                "{} Dropping bootstrap node {:?} and retrying.",
                self, bootstrap_id
            );
            let _ = self.crust_service.disconnect(&bootstrap_id);
            let crust_user = if self.client_restriction() {
                CrustUser::Client
            } else {
                CrustUser::Node
            };
            let _ = self
                .crust_service
                .start_bootstrap(self.bootstrap_blacklist.clone(), crust_user);
        }
    }
}

impl Base for Bootstrapping {
    fn crust_service(&self) -> &Service {
        &self.crust_service
    }

    fn full_id(&self) -> &FullId {
        &self.full_id
    }

    fn in_authority(&self, _: &Authority<XorName>) -> bool {
        false
    }

    fn min_section_size(&self) -> usize {
        self.min_section_size
    }

    fn handle_client_send_request(
        &mut self,
        _: Authority<XorName>,
        _: Request,
        _: u8,
    ) -> Result<(), InterfaceError> {
        warn!(
            "{} - Cannot handle ClientSendRequest - not bootstrapped.",
            self
        );
        // TODO: return Err here eventually. Returning Ok for now to
        // preserve the pre-refactor behaviour.
        Ok(())
    }

    fn handle_node_send_message(
        &mut self,
        _: Authority<XorName>,
        _: Authority<XorName>,
        _: UserMessage,
        _: u8,
    ) -> Result<(), InterfaceError> {
        warn!(
            "{} - Cannot handle NodeSendMessage - not bootstrapped.",
            self
        );
        // TODO: return Err here eventually. Returning Ok for now to
        // preserve the pre-refactor behaviour.
        Ok(())
    }

    fn handle_timeout(&mut self, token: u64, _: &mut EventBox) -> Transition {
        if let Some((bootstrap_id, bootstrap_token)) = self.bootstrap_connection {
            if bootstrap_token == token {
                debug!(
                    "{} - Timeout when trying to bootstrap against {:?}.",
                    self, bootstrap_id
                );

                self.rebootstrap();
            }
        }

        Transition::Stay
    }

    fn handle_bootstrap_connect(
        &mut self,
        pub_id: PublicId,
        socket_addr: SocketAddr,
    ) -> Transition {
        match self.bootstrap_connection {
            None => {
                debug!("{} Received BootstrapConnect from {}.", self, pub_id);
                // Established connection. Pending Validity checks
                self.send_bootstrap_request(pub_id);
                let _ = self.bootstrap_blacklist.insert(socket_addr);
            }
            Some((bootstrap_id, _)) if bootstrap_id == pub_id => {
                warn!(
                    "{} Got more than one BootstrapConnect for peer {}.",
                    self, pub_id
                );
            }
            _ => {
                self.disconnect_peer(&pub_id);
            }
        }

        Transition::Stay
    }

    fn handle_bootstrap_failed(&mut self, outbox: &mut EventBox) -> Transition {
        info!("{} Failed to bootstrap. Terminating.", self);
        outbox.send_event(Event::Terminated);
        Transition::Terminate
    }

    fn handle_lost_peer(&mut self, pub_id: PublicId, _outbox: &mut EventBox) -> Transition {
        info!("{} Lost connection to proxy {:?}.", self, pub_id);
        self.rebootstrap();
        Transition::Stay
    }

    fn handle_listener_started(&mut self, port: u16, outbox: &mut EventBox) -> Transition {
        if self.client_restriction() {
            error!("{} - A client must not run a crust listener.", self);
            outbox.send_event(Event::Terminated);
            return Transition::Terminate;
        }
        trace!("{} - Listener started on port {}.", self, port);
        let _ = self
            .crust_service
            .start_bootstrap(HashSet::new(), CrustUser::Node);
        Transition::Stay
    }

    fn handle_listener_failed(&mut self, outbox: &mut EventBox) -> Transition {
        if self.client_restriction() {
            error!("{} - A client must not run a crust listener.", self);
        } else {
            error!("{} - Failed to start listening.", self);
        }
        outbox.send_event(Event::Terminated);
        Transition::Terminate
    }

    fn handle_direct_message(
        &mut self,
        msg: DirectMessage,
        pub_id: PublicId,
        _: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        use self::DirectMessage::*;
        match msg {
            BootstrapResponse(Ok(())) => Ok(Transition::IntoBootstrapped {
                proxy_public_id: pub_id,
            }),
            BootstrapResponse(Err(error)) => {
                info!("{} Connection failed: {}", self, error);
                self.rebootstrap();
                Ok(Transition::Stay)
            }
            _ => {
                debug!("{} - Unhandled direct message: {:?}", self, msg);
                Ok(Transition::Stay)
            }
        }
    }

    fn handle_hop_message(
        &mut self,
        msg: HopMessage,
        _: PublicId,
        _: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        debug!("{} - Unhandled hop message: {:?}", self, msg);
        Ok(Transition::Stay)
    }
}

impl Display for Bootstrapping {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Bootstrapping({})", self.name())
    }
}

#[cfg(all(test, feature = "mock_base"))]
mod tests {
    use super::*;
    use crate::cache::NullCache;
    use crate::id::FullId;
    use crate::mock_crust::crust::{Config, Service};
    use crate::mock_crust::{self, Network};
    use crate::outbox::EventBuf;
    use crate::state_machine::StateMachine;
    use crate::states::common::from_crust_bytes;
    use crate::CrustEvent;
    use maidsafe_utilities::event_sender::{MaidSafeEventCategory, MaidSafeObserver};
    use std::sync::mpsc;

    #[test]
    // Check that losing our proxy connection while in the `Bootstrapping` state doesn't stall and
    // instead triggers a re-bootstrap attempt..
    fn lose_proxy_connection() {
        let min_section_size = 8;
        let network = Network::new(min_section_size, None);

        // Start a bare-bones Crust service, set it to listen on TCP and to accept bootstrap
        // connections.
        let (category_tx, _category_rx) = mpsc::channel();
        let (event_tx, event_rx) = mpsc::channel();
        let event_sender =
            MaidSafeObserver::new(event_tx, MaidSafeEventCategory::Crust, category_tx);
        let handle0 = network.new_service_handle(None, None);
        let config = Config::with_contacts(&[handle0.endpoint()]);
        let mut crust_service = unwrap!(Service::with_handle(
            &handle0,
            event_sender,
            *FullId::new().public_id(),
        ));

        unwrap!(crust_service.start_listening_tcp());
        if let CrustEvent::ListenerStarted::<_>(_) = unwrap!(event_rx.try_recv()) {
        } else {
            panic!("Should have received `ListenerStarted` event.");
        }
        let _ = crust_service.set_accept_bootstrap(true);

        // Construct a `StateMachine` which will start in the `Bootstrapping` state and bootstrap
        // off the Crust service above.
        let handle1 = network.new_service_handle(Some(config.clone()), None);
        let mut outbox = EventBuf::new();
        let mut state_machine = mock_crust::make_current(&handle1, || {
            let full_id = FullId::new();
            let pub_id = *full_id.public_id();
            StateMachine::new(
                move |action_sender, crust_service, timer, _outbox2| {
                    Bootstrapping::new(
                        action_sender,
                        Box::new(NullCache),
                        TargetState::Client {
                            msg_expiry_dur: Duration::from_secs(60),
                        },
                        crust_service,
                        full_id,
                        min_section_size,
                        timer,
                    )
                    .map_or(State::Terminated, State::Bootstrapping)
                },
                pub_id,
                Some(config),
                &mut outbox,
            )
            .1
        });

        // Check the Crust service received the `BootstrapAccept`.
        network.deliver_messages();
        if let CrustEvent::BootstrapAccept::<_>(_, CrustUser::Client) = unwrap!(event_rx.try_recv())
        {
        } else {
            panic!("Should have received `BootstrapAccept` event.");
        }

        // The state machine should have received the `BootstrapConnect` event and this will have
        // caused it to send a `BootstrapRequest` and add the Crust service to its
        // `bootstrap_blacklist`.
        match *state_machine.current() {
            State::Bootstrapping(ref state) => assert!(state.bootstrap_blacklist.is_empty()),
            _ => panic!("Should be in `Bootstrapping` state."),
        }
        network.deliver_messages();
        unwrap!(state_machine.step(&mut outbox));
        assert!(outbox.take_all().is_empty());
        match *state_machine.current() {
            State::Bootstrapping(ref state) => assert_eq!(state.bootstrap_blacklist.len(), 1),
            _ => panic!("Should be in `Bootstrapping` state."),
        }

        // Check the Crust service received the `BootstrapRequest`, then drop the service to trigger
        // `LostPeer` event in the state machine.
        network.deliver_messages();
        if let CrustEvent::NewMessage::<_>(_, _, serialised_msg) = unwrap!(event_rx.try_recv()) {
            match unwrap!(from_crust_bytes(serialised_msg)) {
                Message::Direct(DirectMessage::BootstrapRequest(_)) => (),
                _ => panic!("Should have received a `BootstrapRequest`."),
            }
        } else {
            panic!("Should have received `NewMessage` event.");
        }
        drop(crust_service);
        network.deliver_messages();

        // Check the state machine received the `LostPeer` and sent `Terminate` via the `outbox`
        // since it can't re-bootstrap (there are no more bootstrap contacts).
        unwrap!(state_machine.step(&mut outbox));
        assert!(outbox.take_all().is_empty());
        network.deliver_messages();

        unwrap!(state_machine.step(&mut outbox));
        let events = outbox.take_all();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], Event::Terminated);
    }
}
