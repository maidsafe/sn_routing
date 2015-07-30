// Copyright 2015 MaidSafe.net limited.
//
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

use cbor::{CborError};
use rand;
use sodiumoxide;
use std::sync::mpsc;
use std::boxed::Box;
use std::marker::PhantomData;

use crust;
use NameType;
use node_interface::{Interface, CreatePersonas};
use routing_membrane::RoutingMembrane;
use id::Id;
use public_id::PublicId;
use who_are_you::IAm;
use types::{MessageId, SourceAddress, DestinationAddress, Address};
use utils::{encode, decode};
use authority::{Authority};
use messages::{RoutingMessage, SignedMessage, MessageType};
use error::{RoutingError};
use std::thread::spawn;
use std::collections::BTreeMap;

static MAX_BOOTSTRAP_CONNECTIONS : usize = 1;

type ConnectionManager = crust::ConnectionManager;
type Event = crust::Event;
pub type Endpoint = crust::Endpoint;
type PortAndProtocol = crust::Port;

type RoutingResult = Result<(), RoutingError>;

/// DHT node
pub struct RoutingNode<F, G> where F : Interface + 'static,
                                   G : CreatePersonas<F> {
    genesis         : Box<G>,
    phantom_data    : PhantomData<F>,
    id              : Id,
    next_message_id : MessageId,
    bootstraps      : BTreeMap<Endpoint, Option<NameType>>,
}

impl<F, G> RoutingNode<F, G> where F : Interface + 'static,
                                   G : CreatePersonas<F> {
    pub fn new(genesis: G) -> RoutingNode<F, G> {
        sodiumoxide::init();  // enable shared global (i.e. safe to multithread now)

        RoutingNode { genesis         : Box::new(genesis),
                      phantom_data    : PhantomData,
                      id              : Id::new(),
                      next_message_id : rand::random::<MessageId>(),
                      bootstraps      : BTreeMap::new(),
                    }
    }

    /// Run the Routing Node.
    /// This is a blocking call which will start a CRUST connection
    /// manager and the CRUST bootstrapping procedures.
    /// If CRUST finds a bootstrap connection, the routing node will
    /// attempt to request a name from the network and connect to its close group.
    /// If CRUST reports a new connection on the listening port, before bootstrapping,
    /// routing node will consider itself the first node.
    //  This might be moved into the constructor new
    //  For an initial draft, kept it as a separate function call.
    pub fn run(&mut self) -> Result<(), RoutingError> {
        let relocated_name : Option<NameType>;
        let our_bootstrap  : Option<(Endpoint, NameType)>;

        let (event_output, event_input) = mpsc::channel();
        let mut cm = crust::ConnectionManager::new(event_output.clone());
        let _ = cm.start_accepting(vec![]);

        println!("Node is accepting connections on {:?}", cm.get_own_endpoints());
        cm.bootstrap(MAX_BOOTSTRAP_CONNECTIONS);

        loop {
            match event_input.recv() {
                Err(_) => return Err(RoutingError::FailedToBootstrap),
                Ok(crust::Event::NewMessage(endpoint, bytes)) => {
                    //println!("Event::NewMessage({:?}, bytes)", endpoint);

                    let self_id = self.id.clone();
                    let opt_bootstrap_name = self.bootstraps.get(&endpoint).cloned();

                    if let Some(opt_name) = opt_bootstrap_name {
                        match opt_name {
                            Some(name) => {
                                if let Ok(signed_message) = decode::<SignedMessage>(&bytes) {
                                    match signed_message.get_routing_message() {
                                        Err(_) => continue,
                                        Ok(message) => {
                                            match message.message_type {
                                                MessageType::PutPublicIdResponse(
                                                    ref new_public_id, ref _orig_request) => {
                                                      our_bootstrap  = Some((endpoint, name));
                                                      relocated_name = Some(new_public_id.name());
                                                      info!("Received name {:?} from network; original name was {:?}",
                                                          relocated_name, self.id.name());
                                                      break;
                                                },
                                                _ => continue,
                                            }
                                        }
                                    }
                                }
                            },
                            None => {
                                if let Ok(he_is_msg) = decode::<IAm>(&bytes) {
                                    match he_is_msg.address {
                                        Address::Node(node_name) => {
                                            info!("Name of our relay node is {:?}", node_name);
                                            self.bootstraps.insert(endpoint.clone(), Some(node_name.clone()));

                                            let put_public_id_msg
                                                = try!(self.construct_put_public_id_msg(
                                                         &PublicId::new(&self_id),
                                                         &node_name));

                                            let serialised_message = try!(encode(&put_public_id_msg));

                                            ignore(cm.send(endpoint, serialised_message));
                                        },
                                        _ => continue, // only care about a Node
                                    }
                                }
                                else { continue }
                            }
                        }
                    }
                },
                Ok(crust::Event::NewConnection(endpoint)) => {
                    if self.bootstraps.is_empty() {
                        // break from listening to CM
                        // and first start RoutingMembrane
                        our_bootstrap  = None;
                        relocated_name = Some(NameType(sodiumoxide::crypto::hash::sha512
                            ::hash(&self.id.name().0).0));
                        info!("Acting on new connection {:?}; no longer bootstrapping.", endpoint);
                        break;
                    } else {
                        // aggressively refuse a connection when we already have
                        // and drop it.
                        cm.drop_node(endpoint);
                    }
                },
                Ok(crust::Event::LostConnection(_endpoint)) => {

                },
                Ok(crust::Event::NewBootstrapConnection(endpoint)) => {
                    //println!("Event::NewBootstrapConnection({:?})", endpoint);
                    if !self.bootstraps.contains_key(&endpoint) {
                        // register the bootstrap endpoint
                        self.bootstraps.insert(endpoint.clone(), None);

                        info!("Established bootstrap connection on {:?}", endpoint);

                        let i_am_message = try!(encode(&IAm {
                            address   : Address::Client(self.id.signing_public_key()),
                            public_id : PublicId::new(&self.id)
                        }));

                        ignore(cm.send(endpoint, i_am_message));
                    }
                }
            }
        }

        // Drop bootstrap connections which we're not using.
        for ep in self.bootstraps.iter() {
            match our_bootstrap {
                Some((ref b_ep, _)) if *ep.0 != *b_ep => {
                    cm.drop_node(ep.0.clone());
                },
                _ => cm.drop_node(ep.0.clone())
            }
        }

        if let Some((ref b_ep, ref b_name)) = our_bootstrap {
            let find_group_msg = try!(self.construct_find_group_msg_as_client(b_name));
            ignore(cm.send(b_ep.clone(), try!(encode(&find_group_msg))));
        }

        match relocated_name {
            Some(new_name) => {
                self.id.assign_relocated_name(new_name);

                //println!(">>>>>>>>>>>>>>>>>>>>>>>>>>> Starting RoutingMembrane");

                let mut membrane = RoutingMembrane::<F>::new(
                    cm, event_output, event_input, our_bootstrap,
                    self.id.clone(),
                    self.genesis.create_personas());

                spawn(move || membrane.run());
            },
            None => { return Err(RoutingError::FailedToBootstrap); }
        };

        Ok(())
    }

    fn construct_put_public_id_msg(&mut self, our_unrelocated_id : &PublicId,
                                              relay_name         : &NameType)
            -> Result<SignedMessage, CborError> {

        let message_id = self.get_next_message_id();

        let message =  RoutingMessage {
            destination  : DestinationAddress::Direct(our_unrelocated_id.name()),
            source       : SourceAddress::RelayedForClient(relay_name.clone(),
                                                           self.id.signing_public_key()),
            orig_message : None,
            message_type : MessageType::PutPublicId(our_unrelocated_id.clone()),
            message_id   : message_id.clone(),
            authority    : Authority::ManagedNode,
        };

        SignedMessage::new(&message, self.id.signing_private_key())
    }


    fn construct_find_group_msg_as_client(&mut self, bootstrap_name: &NameType)
        -> Result<SignedMessage, CborError> {
        let name       = self.id.name();
        let message_id = self.get_next_message_id();

        let message = RoutingMessage {
            destination  : DestinationAddress::Direct(name),
            source       : SourceAddress::RelayedForClient(bootstrap_name.clone(),
                                                           self.id.signing_public_key()),
            orig_message : None,
            message_type : MessageType::FindGroup,
            message_id   : message_id,
            authority    : Authority::ManagedNode,
        };

        SignedMessage::new(&message, self.id.signing_private_key())
    }

    fn get_next_message_id(&mut self) -> MessageId {
        let temp = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        return temp;
    }
}

fn ignore<R,E>(_: Result<R,E>) {}

#[cfg(test)]
mod test {

}
