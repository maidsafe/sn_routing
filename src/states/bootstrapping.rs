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
#[cfg_attr(feature="cargo-clippy", allow(large_enum_variant))]
pub enum TargetState {
    Client,
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
    pub fn new(action_sender: RoutingActionSender,
               cache: Box<Cache>,
               target_state: TargetState,
               mut crust_service: Service,
               full_id: FullId,
               min_section_size: usize,
               timer: Timer)
               -> Option<Self> {
        match target_state {
            TargetState::Client => {
                let _ = crust_service.start_bootstrap(HashSet::new(), CrustUser::Client);
            }
            TargetState::JoiningNode => {
                let _ = crust_service.start_bootstrap(HashSet::new(), CrustUser::Node);
            }
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
            Action::Config { result_tx } => {
                let _ = result_tx.send(self.crust_service.config());
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

    pub fn handle_crust_event(&mut self,
                              crust_event: CrustEvent<PublicId>,
                              outbox: &mut EventBox)
                              -> Transition {
        match crust_event {
            CrustEvent::BootstrapConnect(pub_id, socket_addr) => {
                self.handle_bootstrap_connect(pub_id, socket_addr)
            }
            CrustEvent::BootstrapFailed => self.handle_bootstrap_failed(outbox),
            CrustEvent::NewMessage(pub_id, bytes) => {
                match self.handle_new_message(pub_id, bytes) {
                    Ok(transition) => transition,
                    Err(error) => {
                        debug!("{:?} - {:?}", self, error);
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
                self.crust_service.set_service_discovery_listen(true);
                let _ = self.crust_service
                    .start_bootstrap(HashSet::new(), CrustUser::Node);
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
            TargetState::Client { .. } => {
                State::Client(Client::from_bootstrapping(self.crust_service,
                                                         self.full_id,
                                                         self.min_section_size,
                                                         proxy_public_id,
                                                         self.stats,
                                                         self.timer,
                                                         outbox))
            }
            TargetState::JoiningNode => {
                if let Some(joining_node) =
                    JoiningNode::from_bootstrapping(self.action_sender,
                                                    self.cache,
                                                    self.crust_service,
                                                    self.full_id,
                                                    self.min_section_size,
                                                    proxy_public_id,
                                                    self.stats,
                                                    self.timer) {
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
                State::Node(Node::from_bootstrapping(our_section,
                                                     self.action_sender,
                                                     self.cache,
                                                     self.crust_service,
                                                     old_full_id,
                                                     self.full_id,
                                                     self.min_section_size,
                                                     proxy_public_id,
                                                     self.stats,
                                                     self.timer))
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
                debug!("{:?} Timeout when trying to bootstrap against {:?}.",
                       self,
                       bootstrap_id);

                self.rebootstrap();
            }
        }
    }

    fn handle_bootstrap_connect(&mut self,
                                pub_id: PublicId,
                                socket_addr: SocketAddr)
                                -> Transition {
        match self.bootstrap_connection {
            None => {
                debug!("{:?} Received BootstrapConnect from {}.", self, pub_id);
                // Established connection. Pending Validity checks
                self.send_client_identify(pub_id);
                let _ = self.bootstrap_blacklist.insert(socket_addr);
            }
            Some((bootstrap_id, _)) if bootstrap_id == pub_id => {
                warn!("{:?} Got more than one BootstrapConnect for peer {}.",
                      self,
                      pub_id);
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

    fn handle_new_message(&mut self,
                          pub_id: PublicId,
                          bytes: Vec<u8>)
                          -> Result<Transition, RoutingError> {
        match serialisation::deserialise(&bytes) {
            Ok(Message::Direct(direct_msg)) => Ok(self.handle_direct_message(direct_msg, pub_id)),
            Ok(message) => {
                debug!("{:?} - Unhandled new message: {:?}", self, message);
                Ok(Transition::Stay)
            }
            Err(error) => Err(From::from(error)),
        }
    }

    fn handle_direct_message(&mut self,
                             direct_message: DirectMessage,
                             pub_id: PublicId)
                             -> Transition {
        match direct_message {
            DirectMessage::BootstrapIdentify => self.handle_bootstrap_identify(pub_id),
            DirectMessage::BootstrapDeny => self.handle_bootstrap_deny(),
            _ => {
                debug!("{:?} - Unhandled direct message: {:?}",
                       self,
                       direct_message);
                Transition::Stay
            }
        }
    }

    fn handle_bootstrap_identify(&mut self, public_id: PublicId) -> Transition {
        Transition::IntoBootstrapped { proxy_public_id: public_id }
    }

    fn handle_bootstrap_deny(&mut self) -> Transition {
        info!("{:?} Connection failed: Proxy node needs a larger routing table to accept clients.",
              self);
        self.rebootstrap();
        Transition::Stay
    }

    fn send_client_identify(&mut self, pub_id: PublicId) {
        debug!("{:?} - Sending ClientIdentify to {}.", self, pub_id);

        let token = self.timer
            .schedule(Duration::from_secs(BOOTSTRAP_TIMEOUT_SECS));
        self.bootstrap_connection = Some((pub_id, token));

        let serialised_public_id = match serialisation::serialise(self.full_id.public_id()) {
            Ok(rslt) => rslt,
            Err(e) => {
                error!("Failed to serialise public ID: {:?}", e);
                return;
            }
        };
        let signature = sign::sign_detached(&serialised_public_id,
                                            self.full_id.signing_private_key());

        let direct_message = DirectMessage::ClientIdentify {
            serialised_public_id: serialised_public_id,
            signature: signature,
            client_restriction: self.client_restriction(),
        };

        self.stats().count_direct_message(&direct_message);
        self.send_message(&pub_id, Message::Direct(direct_message));
    }

    fn disconnect_peer(&mut self, pub_id: &PublicId) {
        debug!("{:?} Disconnecting {}. Calling crust::Service::disconnect.",
               self,
               pub_id);
        let _ = self.crust_service.disconnect(*pub_id);
    }

    fn rebootstrap(&mut self) {
        if let Some((bootstrap_id, _)) = self.bootstrap_connection.take() {
            debug!("{:?} Dropping bootstrap node {:?} and retrying.",
                   self,
                   bootstrap_id);
            self.crust_service.disconnect(bootstrap_id);
            let crust_user = if self.client_restriction() {
                CrustUser::Client
            } else {
                CrustUser::Node
            };
            let _ = self.crust_service
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

    fn stats(&mut self) -> &mut Stats {
        &mut self.stats
    }

    fn in_authority(&self, _: &Authority<XorName>) -> bool {
        false
    }
}

impl Debug for Bootstrapping {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Bootstrapping({})", self.name())
    }
}
