// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use super::{Client, JoiningNode, Node};
use super::common::Base;
use {CrustEvent, Service};
use action::Action;
use cache::Cache;
use crust::CrustUser;
use error::RoutingError;
use event::Event;
use id::{FullId, PublicId};
use maidsafe_utilities::serialisation;
use messages::{DirectMessage, Message};
use outbox::EventBox;
use routing_table::{Authority, Prefix};
use rust_sodium::crypto::sign;
use state_machine::{State, Transition};
use stats::Stats;
use std::collections::{BTreeSet, HashSet};
use std::fmt::{self, Debug, Formatter};
use std::net::SocketAddr;
use std::time::Duration;
use timer::Timer;
use types::RoutingActionSender;
use xor_name::XorName;

// Time (in seconds) after which bootstrap is cancelled (and possibly retried).
const BOOTSTRAP_TIMEOUT_SECS: u64 = 20;

// State to transition into after bootstrap process is complete.
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[cfg_attr(feature = "cargo-clippy", allow(large_enum_variant))]
pub enum TargetState {
    Client { msg_expiry_dur: Duration },
    JoiningNode,
    Node {
        old_full_id: FullId,
        our_section: (Prefix<XorName>, BTreeSet<PublicId>),
    },
}

// State of Client, JoiningNode or Node while bootstrapping.
pub struct Bootstrapping {
    action_sender: RoutingActionSender,
    bootstrap_blacklist: HashSet<SocketAddr>,
    bootstrap_connection: Option<(PublicId, u64)>,
    cache: Box<Cache>,
    target_state: TargetState,
    crust_service: Service,
    full_id: FullId,
    min_section_size: usize,
    stats: Stats,
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
            TargetState::JoiningNode |
            TargetState::Node { .. } => {
                if let Err(error) = crust_service.start_listening_tcp() {
                    error!("Failed to start listening: {:?}", error);
                    return None;
                }
            }
        }
        Some(Bootstrapping {
            action_sender: action_sender,
            bootstrap_blacklist: HashSet::new(),
            bootstrap_connection: None,
            cache: cache,
            target_state: target_state,
            crust_service: crust_service,
            full_id: full_id,
            min_section_size: min_section_size,
            stats: Stats::new(),
            timer: timer,
        })
    }

    pub fn handle_action(&mut self, action: Action) -> Transition {
        match action {
            Action::ClientSendRequest { ref result_tx, .. } |
            Action::NodeSendMessage { ref result_tx, .. } => {
                warn!("{:?} Cannot handle {:?} - not bootstrapped.", self, action);
                // TODO: return Err here eventually. Returning Ok for now to
                // preserve the pre-refactor behaviour.
                let _ = result_tx.send(Ok(()));
            }
            Action::Id { result_tx } => {
                let _ = result_tx.send(*self.id());
            }
            Action::Timeout(token) => self.handle_timeout(token),
            Action::ResourceProofResult(..) => {
                warn!("{:?} Cannot handle {:?} - not bootstrapped.", self, action);
            }
            Action::Terminate => {
                return Transition::Terminate;
            }
        }
        Transition::Stay
    }

    pub fn handle_crust_event(
        &mut self,
        crust_event: CrustEvent<PublicId>,
        outbox: &mut EventBox,
    ) -> Transition {
        match crust_event {
            CrustEvent::BootstrapConnect(pub_id, socket_addr) => {
                self.handle_bootstrap_connect(pub_id, socket_addr)
            }
            CrustEvent::BootstrapFailed => self.handle_bootstrap_failed(outbox),
            CrustEvent::LostPeer(pub_id) => {
                info!("{:?} Lost connection to proxy {:?}.", self, pub_id);
                self.rebootstrap();
                Transition::Stay
            }
            CrustEvent::NewMessage(pub_id, _, bytes) => {
                match self.handle_new_message(pub_id, bytes) {
                    Ok(transition) => transition,
                    Err(error) => {
                        debug!("{:?} {:?}", self, error);
                        Transition::Stay
                    }
                }
            }
            CrustEvent::ListenerStarted(port) => {
                if self.client_restriction() {
                    error!("{:?} A client must not run a crust listener.", self);
                    outbox.send_event(Event::Terminate);
                    return Transition::Terminate;
                }
                trace!("{:?} Listener started on port {}.", self, port);
                let _ = self.crust_service.start_bootstrap(
                    HashSet::new(),
                    CrustUser::Node,
                );
                Transition::Stay
            }
            CrustEvent::ListenerFailed => {
                if self.client_restriction() {
                    error!("{:?} A client must not run a crust listener.", self);
                } else {
                    error!("{:?} Failed to start listening.", self);
                }
                outbox.send_event(Event::Terminate);
                Transition::Terminate
            }
            _ => {
                debug!("{:?} Unhandled crust event {:?}", self, crust_event);
                Transition::Stay
            }
        }
    }

    pub fn into_target_state(self, proxy_public_id: PublicId, outbox: &mut EventBox) -> State {
        match self.target_state {
            TargetState::Client { msg_expiry_dur } => {
                State::Client(Client::from_bootstrapping(
                    self.crust_service,
                    self.full_id,
                    self.min_section_size,
                    proxy_public_id,
                    self.stats,
                    self.timer,
                    msg_expiry_dur,
                    outbox,
                ))
            }
            TargetState::JoiningNode => {
                if let Some(joining_node) =
                    JoiningNode::from_bootstrapping(
                        self.action_sender,
                        self.cache,
                        self.crust_service,
                        self.full_id,
                        self.min_section_size,
                        proxy_public_id,
                        self.stats,
                        self.timer,
                    )
                {
                    State::JoiningNode(joining_node)
                } else {
                    outbox.send_event(Event::RestartRequired);
                    State::Terminated
                }
            }
            TargetState::Node {
                old_full_id,
                our_section,
                ..
            } => {
                State::Node(Node::from_bootstrapping(
                    our_section,
                    self.action_sender,
                    self.cache,
                    self.crust_service,
                    old_full_id,
                    self.full_id,
                    self.min_section_size,
                    proxy_public_id,
                    self.stats,
                    self.timer,
                ))
            }
        }
    }

    fn client_restriction(&self) -> bool {
        match self.target_state {
            TargetState::Client { .. } => true,
            TargetState::JoiningNode |
            TargetState::Node { .. } => false,
        }
    }

    fn handle_timeout(&mut self, token: u64) {
        if let Some((bootstrap_id, bootstrap_token)) = self.bootstrap_connection {
            if bootstrap_token == token {
                debug!(
                    "{:?} Timeout when trying to bootstrap against {:?}.",
                    self,
                    bootstrap_id
                );

                self.rebootstrap();
            }
        }
    }

    fn handle_bootstrap_connect(
        &mut self,
        pub_id: PublicId,
        socket_addr: SocketAddr,
    ) -> Transition {
        match self.bootstrap_connection {
            None => {
                debug!("{:?} Received BootstrapConnect from {}.", self, pub_id);
                // Established connection. Pending Validity checks
                self.send_bootstrap_request(pub_id);
                let _ = self.bootstrap_blacklist.insert(socket_addr);
            }
            Some((bootstrap_id, _)) if bootstrap_id == pub_id => {
                warn!(
                    "{:?} Got more than one BootstrapConnect for peer {}.",
                    self,
                    pub_id
                );
            }
            _ => {
                self.disconnect_peer(&pub_id);
            }
        }

        Transition::Stay
    }

    fn handle_bootstrap_failed(&mut self, outbox: &mut EventBox) -> Transition {
        info!("{:?} Failed to bootstrap. Terminating.", self);
        outbox.send_event(Event::Terminate);
        Transition::Terminate
    }

    fn handle_new_message(
        &mut self,
        pub_id: PublicId,
        bytes: Vec<u8>,
    ) -> Result<Transition, RoutingError> {
        match serialisation::deserialise(&bytes) {
            Ok(Message::Direct(direct_msg)) => Ok(self.handle_direct_message(direct_msg, pub_id)),
            Ok(message) => {
                debug!("{:?} Unhandled new message: {:?}", self, message);
                Ok(Transition::Stay)
            }
            Err(error) => Err(From::from(error)),
        }
    }

    fn handle_direct_message(
        &mut self,
        direct_message: DirectMessage,
        pub_id: PublicId,
    ) -> Transition {
        use self::DirectMessage::*;
        match direct_message {
            BootstrapResponse(Ok(())) => Transition::IntoBootstrapped { proxy_public_id: pub_id },
            BootstrapResponse(Err(error)) => {
                info!("{:?} Connection failed: {}", self, error);
                self.rebootstrap();
                Transition::Stay
            }
            _ => {
                debug!(
                    "{:?} - Unhandled direct message: {:?}",
                    self,
                    direct_message
                );
                Transition::Stay
            }
        }
    }

    fn send_bootstrap_request(&mut self, pub_id: PublicId) {
        debug!("{:?} Sending BootstrapRequest to {}.", self, pub_id);

        let token = self.timer.schedule(
            Duration::from_secs(BOOTSTRAP_TIMEOUT_SECS),
        );
        self.bootstrap_connection = Some((pub_id, token));

        let serialised_public_id = match serialisation::serialise(self.full_id.public_id()) {
            Ok(rslt) => rslt,
            Err(e) => {
                error!("Failed to serialise public ID: {:?}", e);
                return;
            }
        };
        let signature =
            sign::sign_detached(&serialised_public_id, self.full_id.signing_private_key());
        let direct_message = DirectMessage::BootstrapRequest(signature);

        self.stats().count_direct_message(&direct_message);
        self.send_message(&pub_id, Message::Direct(direct_message));
    }

    fn disconnect_peer(&mut self, pub_id: &PublicId) {
        debug!(
            "{:?} Disconnecting {}. Calling crust::Service::disconnect.",
            self,
            pub_id
        );
        let _ = self.crust_service.disconnect(pub_id);
    }

    fn rebootstrap(&mut self) {
        if let Some((bootstrap_id, _)) = self.bootstrap_connection.take() {
            debug!(
                "{:?} Dropping bootstrap node {:?} and retrying.",
                self,
                bootstrap_id
            );
            let _ = self.crust_service.disconnect(&bootstrap_id);
            let crust_user = if self.client_restriction() {
                CrustUser::Client
            } else {
                CrustUser::Node
            };
            let _ = self.crust_service.start_bootstrap(
                self.bootstrap_blacklist.clone(),
                crust_user,
            );
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

    fn stats(&mut self) -> &mut Stats {
        &mut self.stats
    }

    fn in_authority(&self, _: &Authority<XorName>) -> bool {
        false
    }

    fn min_section_size(&self) -> usize {
        self.min_section_size
    }
}

impl Debug for Bootstrapping {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Bootstrapping({})", self.name())
    }
}

#[cfg(all(test, feature = "use-mock-crust"))]
mod tests {
    use super::*;
    use CrustEvent;
    use cache::NullCache;
    use id::FullId;
    use maidsafe_utilities::event_sender::{MaidSafeEventCategory, MaidSafeObserver};
    use mock_crust::{self, Network};
    use mock_crust::crust::{Config, Service};
    use outbox::EventBuf;
    use state_machine::StateMachine;
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
                        TargetState::Client { msg_expiry_dur: Duration::from_secs(60) },
                        crust_service,
                        full_id,
                        min_section_size,
                        timer,
                    ).map_or(State::Terminated, State::Bootstrapping)
                },
                pub_id,
                Some(config),
                &mut outbox,
            ).1
        });

        // Check the Crust service received the `BootstrapAccept`.
        network.deliver_messages();
        if let CrustEvent::BootstrapAccept::<_>(_, CrustUser::Client) =
            unwrap!(event_rx.try_recv())
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
            match unwrap!(serialisation::deserialise(&serialised_msg)) {
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
        assert_eq!(events[0], Event::Terminate);
    }
}
