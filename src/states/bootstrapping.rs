// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use crust::{PeerId, Service};
use crust::Event as CrustEvent;
use maidsafe_utilities::serialisation;
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::sign;
use std::collections::HashSet;
use std::fmt::{self, Debug, Formatter};
use std::net::SocketAddr;
use std::sync::mpsc::Sender;
use std::time::Duration;

use action::Action;
use cache::Cache;
use error::RoutingError;
use event::Event;
use id::{FullId, PublicId};
use messages::{DirectMessage, Message};
use state_machine::Transition;
use stats::Stats;
use super::Client;
use timer::Timer;
use xor_name::XorName;

/// Time (in seconds) after which bootstrap is cancelled (and possibly retried).
const BOOTSTRAP_TIMEOUT_SECS: u64 = 20;

pub struct Bootstrapping {
    bootstrap_blacklist: HashSet<SocketAddr>,
    bootstrap_info: Option<(PeerId, u64)>,
    cache: Box<Cache>,
    client_restriction: bool,
    crust_service: Service,
    event_sender: Sender<Event>,
    full_id: FullId,
    stats: Stats,
    timer: Timer,
}

impl Bootstrapping {
    pub fn new(bootstrap_blacklist: HashSet<SocketAddr>,
               cache: Box<Cache>,
               client_restriction: bool,
               mut crust_service: Service,
               event_sender: Sender<Event>,
               full_id: FullId,
               timer: Timer)
               -> Self {
        let _ = crust_service.start_bootstrap(bootstrap_blacklist.clone());

        Bootstrapping {
            bootstrap_blacklist: bootstrap_blacklist,
            bootstrap_info: None,
            cache: cache,
            client_restriction: client_restriction,
            crust_service: crust_service,
            event_sender: event_sender,
            full_id: full_id,
            stats: Default::default(),
            timer: timer,
        }
    }

    pub fn handle_action(&mut self, action: Action) -> Transition {
        match action {
            Action::ClientSendRequest { ref result_tx, .. } |
            Action::NodeSendMessage { ref result_tx, .. } => {
                warn!("{:?} - Cannot handle {:?} - not bootstrapped", self, action);
                let _ = result_tx.send(Ok(()));
                Transition::Stay
            }
            Action::Timeout(token) => self.handle_timeout(token),
            Action::Terminate => Transition::Terminate,
            _ => {
                debug!("{:?} - Unhandled action {:?}", self, action);
                Transition::Stay
            }
        }
    }

    pub fn handle_crust_event(&mut self, crust_event: CrustEvent) -> Transition {
        match crust_event {
            CrustEvent::BootstrapConnect(peer_id, socket_addr) => {
                self.handle_bootstrap_connect(peer_id, socket_addr)
            }
            CrustEvent::BootstrapFailed => self.handle_bootstrap_failed(),
            CrustEvent::NewMessage(peer_id, bytes) => {
                match self.handle_new_message(peer_id, bytes) {
                    Ok(transition) => transition,
                    Err(error) => {
                        debug!("{:?} - {:?}", self, error);
                        Transition::Stay
                    }
                }
            }
            _ => {
                debug!("{:?} Unhandled crust event {:?}", self, crust_event);
                Transition::Stay
            }
        }
    }

    pub fn into_client(self,
                       proxy_public_id: PublicId,
                       proxy_peer_id: PeerId,
                       quorum_size: usize)
                       -> Client {
        Client::from_bootstrapping(proxy_public_id,
                                   proxy_peer_id,
                                   quorum_size,
                                   self.cache,
                                   self.client_restriction,
                                   self.crust_service,
                                   self.event_sender,
                                   self.full_id,
                                   self.stats,
                                   self.timer)
    }

    pub fn name(&self) -> &XorName {
        self.full_id.public_id().name()
    }

    fn handle_timeout(&mut self, token: u64) -> Transition {
        if let Some((bootstrap_id, bootstrap_token)) = self.bootstrap_info {
            if bootstrap_token == token {
                debug!("{:?} Timeout when trying to bootstrap against {:?}.",
                       self,
                       bootstrap_id);

                self.rebootstrap();
            }
        }

        Transition::Stay
    }

    fn handle_bootstrap_connect(&mut self, peer_id: PeerId, socket_addr: SocketAddr) -> Transition {
        match self.bootstrap_info {
            None => {
                debug!("{:?} Received BootstrapConnect from {:?}.", self, peer_id);
                // Established connection. Pending Validity checks
                let _ = self.send_client_identify(peer_id);
                let _ = self.bootstrap_blacklist.insert(socket_addr);
            }
            Some((bootstrap_id, _)) if bootstrap_id == peer_id => {
                warn!("{:?} Got more than one BootstrapConnect for peer {:?}.",
                      self,
                      peer_id);
            }
            _ => {
                self.disconnect_peer(&peer_id);
            }
        }

        Transition::Stay
    }

    fn handle_bootstrap_failed(&mut self) -> Transition {
        debug!("{:?} Failed to bootstrap.", self);
        let _ = self.event_sender.send(Event::Terminate);
        Transition::Terminate
    }

    fn handle_new_message(&mut self,
                          peer_id: PeerId,
                          bytes: Vec<u8>)
                          -> Result<Transition, RoutingError> {
        match serialisation::deserialise(&bytes) {
            Ok(Message::Direct(direct_msg)) => Ok(self.handle_direct_message(direct_msg, peer_id)),
            Ok(message) => {
                debug!("{:?} - Unhandled new message: {:?}", self, message);
                Ok(Transition::Stay)
            }
            Err(error) => Err(From::from(error)),
        }
    }

    fn handle_direct_message(&mut self,
                             direct_message: DirectMessage,
                             peer_id: PeerId)
                             -> Transition {
        match direct_message {
            DirectMessage::BootstrapIdentify { public_id, current_quorum_size } => {
                self.handle_bootstrap_identify(public_id, peer_id, current_quorum_size)
            }
            DirectMessage::BootstrapDeny => self.handle_bootstrap_deny(),
            _ => {
                debug!("{:?} - Unhandled direct message: {:?}",
                       self,
                       direct_message);
                Transition::Stay
            }
        }
    }

    fn handle_bootstrap_identify(&mut self,
                                 public_id: PublicId,
                                 peer_id: PeerId,
                                 current_quorum_size: usize)
                                 -> Transition {
        if *public_id.name() == XorName(sha256::hash(&public_id.signing_public_key().0).0) {
            warn!("{:?} Incoming Connection not validated as a proper node - dropping",
                  self);
            self.rebootstrap();
            return Transition::Stay;
        }

        Transition::IntoClient {
            proxy_public_id: public_id,
            proxy_peer_id: peer_id,
            quorum_size: current_quorum_size,
        }
    }

    fn handle_bootstrap_deny(&mut self) -> Transition {
        info!("{:?} Connection failed: Proxy node needs a larger routing table to accept \
               clients.",
              self);
        self.rebootstrap();
        Transition::Stay
    }

    fn send_client_identify(&mut self, peer_id: PeerId) -> Result<(), RoutingError> {
        debug!("{:?} - Sending ClientIdentify to {:?}.", self, peer_id);

        let token = self.timer.schedule(Duration::from_secs(BOOTSTRAP_TIMEOUT_SECS));
        self.bootstrap_info = Some((peer_id, token));

        let serialised_public_id = try!(serialisation::serialise(self.full_id.public_id()));
        let signature = sign::sign_detached(&serialised_public_id,
                                            self.full_id.signing_private_key());

        let direct_message = DirectMessage::ClientIdentify {
            serialised_public_id: serialised_public_id,
            signature: signature,
            client_restriction: self.client_restriction,
        };

        self.send_direct_message(&peer_id, direct_message)
    }

    fn send_direct_message(&mut self,
                           dst_id: &PeerId,
                           direct_message: DirectMessage)
                           -> Result<(), RoutingError> {
        self.stats.count_direct_message(&direct_message);

        let priority = direct_message.priority();
        let message = Message::Direct(direct_message);

        let raw_bytes = match serialisation::serialise(&message) {
            Err(error) => {
                error!("{:?} Failed to serialise message {:?}: {:?}",
                       self,
                       message,
                       error);
                return Err(error.into());
            }
            Ok(bytes) => bytes,
        };

        self.send_or_drop(dst_id, raw_bytes, priority)
    }

    fn send_or_drop(&mut self,
                    peer_id: &PeerId,
                    bytes: Vec<u8>,
                    priority: u8)
                    -> Result<(), RoutingError> {
        self.stats.count_bytes(bytes.len());

        if let Err(err) = self.crust_service.send(*peer_id, bytes.clone(), priority) {
            info!("{:?} Connection to {:?} failed. Calling crust::Service::disconnect.",
                  self,
                  peer_id);
            self.crust_service.disconnect(*peer_id);
            return Err(err.into());
        }
        Ok(())
    }

    fn disconnect_peer(&mut self, peer_id: &PeerId) {
        debug!("{:?} Disconnecting {:?}. Calling crust::Service::disconnect.",
               self,
               peer_id);
        let _ = self.crust_service.disconnect(*peer_id);
    }

    fn rebootstrap(&mut self) {
        if let Some((bootstrap_id, _)) = self.bootstrap_info.take() {
            debug!("{:?} Dropping bootstrap node {:?} and retrying.",
                   self,
                   bootstrap_id);
            self.crust_service.disconnect(bootstrap_id);
            let _ = self.crust_service.start_bootstrap(self.bootstrap_blacklist.clone());
        }
    }
}

impl Debug for Bootstrapping {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Bootstrapping({})", self.name())
    }
}
