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

use std::sync::mpsc;
use std::thread::spawn;
use std::collections::BTreeMap;
use sodiumoxide::crypto::sign::{verify_detached, Signature};
use sodiumoxide::crypto::sign;
use time::{Duration, SteadyTime};

use crust;
use crust::{ConnectionManager, Endpoint};

use action::Action;
use event::Event;
use NameType;
use name_type::{closer_to_target_or_equal};
use routing_table::{RoutingTable, NodeInfo};
use id::Id;
use public_id::PublicId;
use who_are_you::IAm;
use types;
use types::{MessageId, Bytes, Address};
use utils::{encode, decode};
use data::{Data, DataRequest};
use authority::{Authority, our_authority};
use messages::{RoutingMessage, SignedMessage, MessageType,
               ConnectRequest, ConnectResponse, ErrorReturn, GetDataResponse};
use error::{RoutingError, ResponseError};
use refresh_accumulator::RefreshAccumulator;


//use lru_time_cache::LruCache;
//use message_filter::MessageFilter;
//use NameType;
//use name_type::{closer_to_target_or_equal};
//use node_interface::Interface;
//use routing_table::{RoutingTable, NodeInfo};
//use relay::{RelayMap};
//use sendable::Sendable;
//use types;
//use types::{MessageId, Bytes, DestinationAddress, SourceAddress, Address};
//use authority::{Authority, our_authority};
//use who_are_you::IAm;
//use messages::{RoutingMessage, SignedMessage, MessageType,
//               ConnectRequest, ConnectResponse, ErrorReturn, GetDataResponse};

//use node_interface::MethodCall;

//use id::Id;
//use public_id::PublicId;
//use utils;
//use utils::{encode, decode};
//use sentinel::pure_sentinel::PureSentinel;
//use event::Event;
//

type RoutingResult = Result<(), RoutingError>;

enum ConnectionName {
   Relay(Address),
   Routing(NameType),
   OurBootstrap(NameType),
   ReflectionOnToUs,
   UnidentifiedConnection,
   // ClaimedConnection(PublicId),
}

static MAX_BOOTSTRAP_CONNECTIONS : usize = 1;

/// Routing Node
pub struct RoutingNode {
    // for CRUST
    crust_sender        : mpsc::Sender<crust::Event>,
    crust_receiver      : mpsc::Receiver<crust::Event>,
    connection_manager  : crust::ConnectionManager,
    accepting_on        : Vec<crust::Endpoint>,
    bootstraps          : BTreeMap<Endpoint, Option<NameType>>,
    // for RoutingNode
    action_receiver     : mpsc::Receiver<Action>,
    // for Routing
    id                  : Id,
    // routing_table       : RoutingTable,
    // relay_map           : RelayMap,
    // filter              : MessageFilter<types::FilterType>,
    // public_id_cache     : LruCache<NameType, PublicId>,
    // connection_cache    : BTreeMap<NameType, SteadyTime>,
    // refresh_accumulator : RefreshAccumulator,
}

impl RoutingNode {
    pub fn new(action_sender   : mpsc::Sender<Action>,
               action_receiver : mpsc::Receiver<Action>,
               event_sender    : mpsc::Sender<Event> ) -> Result<RoutingNode, RoutingError> {
        let id = Id::new();

        let (crust_sender, crust_receiver) = mpsc::channel::<crust::Event>();
        let mut cm = crust::ConnectionManager::new(crust_sender.clone());
        let _ = cm.start_accepting(vec![]);
        let accepting_on = cm.get_own_endpoints();

        Ok(RoutingNode {
            crust_sender        : crust_sender,
            crust_receiver      : crust_receiver,
            connection_manager  : cm,
            accepting_on        : accepting_on,
            bootstraps          : BTreeMap::new(),
            action_receiver     : action_receiver,
            id                  : id,
        })
    }



    pub fn bootstrap(&mut self) {
        // TODO (ben 05/08/2015) To be continued
        // cm.bootstrap(MAX_BOOTSTRAP_CONNECTIONS);
        // let bootstraps : BTreeMap<Endpoint, Option<NameType>>
        //     = match crust_receiver.recv() {
        //     Ok(crust::Event::NewConnection(endpoint)) => BTreeMap::new(),
        //     Ok(crust::Event::NewBootstrapConnection(endpoint)) => {
        //         RoutingNode::bootstrap(cm)
        //     },
        //     _ => {
        //         error!("The first event received from Crust is not a new connection.");
        //         return Err(RoutingError::FailedToBootstrap)
        //     }
        // };
    }

    fn request_network_name(&mut cm : crust::ConnectionManager)
        -> Result<NameType,RoutingError>  {

    }

    /// When CRUST receives a connect to our listening port and establishes a new connection,
    /// the endpoint is given here as new connection
    fn handle_new_connection(&mut self, endpoint : Endpoint) {
        unimplemented!()
    }

    /// When CRUST reports a lost connection, ensure we remove the endpoint anywhere
    fn handle_lost_connection(&mut self, endpoint : Endpoint) {
        unimplemented!()
    }

    /// This the fundamental functional function in routing.
    /// It only handles messages received from connections in our routing table;
    /// i.e. this is a pure SAFE message (and does not function as the start of a relay).
    /// If we are the relay node for a message from the SAFE network to a node we relay for,
    /// then we will pass out the message to the client or bootstrapping node;
    /// no relay-messages enter the SAFE network here.
    fn message_received(&mut self, message_wrap : SignedMessage,
                       ) -> RoutingResult {

        let message = try!(message_wrap.get_routing_message());

        // filter check
        if self.filter.check(&message.get_filter()) {
            // should just return quietly
            debug!("FILTER BLOCKED message {:?} from {:?} to {:?}", message.message_type,
                message.source(), message.destination());
            return Err(RoutingError::FilterCheckFailed);
        }
        debug!("message {:?} from {:?} to {:?}", message.message_type,
            message.source(), message.destination());
        // add to filter
        self.filter.add(message.get_filter());

        // TODO: Caching will be implemented differently, kept code for reference.
        //       Feel free to delete it.
        //
        //// Caching on GetData and GetDataRequest
        //match message.message_type {
        //    // Add to cache, only for ImmutableData; For StructuredData caching
        //    // can result in old versions being returned.
        //    MessageType::GetDataResponse(ref response) => {
        //        match response.data {
        //            Data::ImmutableData(ref immutable_data) => {
        //                let from = message.from_group()
        //                                  .unwrap_or(message.non_relayed_source());

        //                ignore(self.mut_interface().handle_cache_put(
        //                    message.from_authority(),
        //                    from,
        //                    Data::ImmutableData(immutable_data.clone())));
        //            },
        //            _ => {}
        //        }
        //    },
        //    // check cache
        //    MessageType::GetData(ref data_request) => {
        //        let from = message.from_group()
        //                          .unwrap_or(message.non_relayed_source());

        //        let method_call = self.mut_interface().handle_cache_get(
        //                        data_request.clone(),
        //                        message.non_relayed_destination(),
        //                        from);

        //        match method_call {
        //            Ok(MethodCall::Reply { data }) => {
        //                let response = GetDataResponse {
        //                    data           : data,
        //                    orig_request   : message_wrap.clone(),
        //                    group_pub_keys : BTreeMap::new()
        //                };
        //                let our_authority = our_authority(&message, &self.routing_table);
        //                ignore(self.send_reply(
        //                    &message, our_authority, MessageType::GetDataResponse(response)));
        //            },
        //            _ => (),

        //        }
        //    },
        //    _ => {}
        //}

        // Forward
        ignore(self.send_swarm_or_parallel_or_relay_with_signature(
            &message, message_wrap.signature().clone()));

        let address_in_close_group_range =
            self.address_in_close_group_range(&message.destination());

        // Handle FindGroupResponse
        match  message.message_type {
            MessageType::FindGroupResponse(ref vec_of_public_ids) =>
                ignore(self.handle_find_group_response(
                            vec_of_public_ids.clone(),
                            address_in_close_group_range.clone())),
             _ => (),
        };

        if !address_in_close_group_range {
            return Ok(());
        }

        // Drop message before Sentinel check if it is a direct message type (Connect, ConnectResponse)
        // and this node is in the group but the message destination is another group member node.
        match  message.message_type {
            MessageType::ConnectRequest(_) |
            MessageType::ConnectResponse(_) =>
                match message.destination() {
                    Authority::ClientManager(_)  => return Ok(()), // TODO: Should be error
                    Authority::NaeManager(_)     => return Ok(()), // TODO: Should be error
                    Authority::NodeManager(_)    => return Ok(()), // TODO: Should be error
                    Authority::ManagedNode(name) => if name != self.id.name() { return Ok(()) },
                    Authority::Client(_, _)      => return Ok(()), // TODO: Should be error
                },
            _ => (),
        }
        //
        // pre-sentinel message handling
        match message.message_type {
            //MessageType::GetKey => self.handle_get_key(header, body),
            //MessageType::GetGroupKey => self.handle_get_group_key(header, body),
            MessageType::ConnectRequest(request) => self.handle_connect_request(request, message_wrap),
            _ => {
                // Sentinel check

                // switch message type
                match message.message_type {
                    MessageType::ConnectResponse(response) =>
                        self.handle_connect_response(response),
                    MessageType::FindGroup =>
                         self.handle_find_group(message),
                    // Handled above for some reason.
                    //MessageType::FindGroupResponse(find_group_response) => self.handle_find_group_response(find_group_response),
                    MessageType::GetData(ref request) =>
                        self.handle_get_data(message_wrap, message.clone(), request.clone()),
                    MessageType::GetDataResponse(ref response) =>
                        self.handle_node_data_response(message_wrap, message.clone(),
                                                       response.clone()),
                    MessageType::PutDataResponse(ref response, ref _map) =>
                        self.handle_put_data_response(message_wrap, message.clone(),
                                                      response.clone()),
                    MessageType::PutData(ref data) =>
                          self.handle_put_data(message_wrap, message.clone(), data.clone()),
                    MessageType::PutPublicId(ref id) =>
                        self.handle_put_public_id(message_wrap, message.clone(), id.clone()),
                    MessageType::Refresh(ref tag, ref data) =>
                        self.handle_refresh(message.clone(), tag.clone(), data.clone()),
                     MessageType::Post(ref data) =>
                         self.handle_post(message_wrap, message.clone(), data.clone()),
                    MessageType::PostResponse(ref response, _)
                        => self.handle_post_response(message_wrap,
                                                     message.clone(),
                                                     response.clone()),
                    _ => {
                        Err(RoutingError::UnknownMessageType)
                    }
                }
            }
        }
    }

    /// Scan all passing messages for the existance of nodes in the address space.
    /// If a node is detected with a name that would improve our routing table,
    /// then try to connect.  During a delay of 5 seconds, we collapse
    /// all re-occurances of this name, and block a new connect request
    /// TODO: The behaviour of this function has been adapted to serve as a filter
    /// to cover for the lack of a filter on FindGroupResponse
    fn refresh_routing_table(&mut self, from_node : &NameType) {
      // disable refresh when scanning on small routing_table size
      let time_now = SteadyTime::now();
      if !self.connection_cache.contains_key(from_node) {
          if self.routing_table.check_node(from_node) {
              ignore(self.send_connect_request_msg(&from_node));
          }
          self.connection_cache.entry(from_node.clone())
              .or_insert(time_now);
       }

       let mut prune_blockage : Vec<NameType> = Vec::new();
       for (blocked_node, time) in self.connection_cache.iter_mut() {
           // clear block for nodes
           if time_now - *time > Duration::seconds(10) {
               prune_blockage.push(blocked_node.clone());
           }
       }
       for prune_name in prune_blockage {
           self.connection_cache.remove(&prune_name);
       }
    }

    // -----Name-based Send Functions----------------------------------------

    fn send_out_as_relay(&mut self, name: &Address, msg: Bytes) {
        let mut failed_endpoints : Vec<Endpoint> = Vec::new();
        match self.relay_map.get_endpoints(name) {
            Some(&(_, ref endpoints)) => {
                for endpoint in endpoints {
                    match self.connection_manager.send(endpoint.clone(), msg.clone()) {
                        Ok(_) => break,
                        Err(_) => {
                            info!("Dropped relay connection {:?} on failed attempt
                                to relay for node {:?}", endpoint, name);
                            failed_endpoints.push(endpoint.clone());
                        }
                    };
                }
            },
            None => {}
        };
        for failed_endpoint in failed_endpoints {
            self.relay_map.drop_endpoint(&failed_endpoint);
            self.connection_manager.drop_node(failed_endpoint);
        }
    }

    fn send_swarm_or_parallel(&self, msg : &RoutingMessage) -> Result<(), RoutingError> {
        let destination = msg.non_relayed_destination();
        let signed_message = try!(SignedMessage::new(&msg, self.id.signing_private_key()));
        self.send_swarm_or_parallel_signed_message(&signed_message, &destination)
    }

    #[allow(dead_code)]
    fn send_swarm_or_parallel_with_signature(&self, msg: &RoutingMessage,
        signature : Signature) -> Result<(), RoutingError> {
        let destination = msg.non_relayed_destination();
        let signed_message = try!(SignedMessage::with_signature(&msg,
            signature));
        self.send_swarm_or_parallel_signed_message(&signed_message, &destination)
    }

    fn send_swarm_or_parallel_signed_message(&self, signed_message : &SignedMessage,
        destination: &NameType) -> Result<(), RoutingError> {

        if self.routing_table.size() > 0 {
            let bytes = try!(encode(&signed_message));

            for peer in self.routing_table.target_nodes(&destination) {
                match peer.connected_endpoint {
                    Some(peer_endpoint) => {
                        ignore(self.connection_manager.send(peer_endpoint, bytes.clone()));
                    },
                    None => {}
                };
            }

            // FIXME(ben 24/07/2015)
            // if the destination is within range for us,
            // we are also part of the effective close group for destination.
            // RoutingTable does not include ourselves in the target nodes,
            // so we should check the filter (to avoid eternal looping)
            // and also handle it ourselves.
            // Instead we can for now rely on swarming to send it back to us.
            Ok(())
        } else {
            match self.bootstrap {
                Some((ref bootstrap_endpoint, _)) => {
                    let msg = try!(encode(&signed_message));

                    match self.connection_manager.send(bootstrap_endpoint.clone(), msg) {
                        Ok(_)  => Ok(()),
                        Err(e) => Err(RoutingError::Io(e))
                    }
                },
                None => {
                    // FIXME(ben 24/07/2015)
                    // This is a patch for the above: if we have no routing table connections,
                    // we are the only member of the effective close group for the target.
                    // In this case we can reflect it back to ourselves
                    // - and take the risk of piling up the stack; or holding other messages;
                    // afterall we are the only node on the network, as far as we know.

                    // if routing table size is zero any target is in range, so no need to check
                    self.send_reflective_to_us(signed_message)
                }
            }
        }
    }

    // When we swarm a message, we are also part of the effective close group.
    // This is catered for under normal swarm, as our neighbours will send the message back,
    // when we have no routing table connections, we explicitly have no choice, but to loop
    // it back to ourselves
    // this is the logically correct behaviour.
    fn send_reflective_to_us(&self, signed_message: &SignedMessage) -> Result<(), RoutingError> {
        unimplemented!()
        // TODO (ben 4/08/2015) use the action_sender to send a message back to ourselves.
        // let bytes = try!(encode(&signed_message));
        // let new_event = CrustEvent::NewMessage(self.reflective_endpoint.clone(), bytes);
        // match self.sender_clone.send(new_event) {
        //     Ok(_) => {},
        //     // FIXME(ben 24/07/2015) we have a broken channel with crust,
        //     // should terminate node
        //     Err(_) => return Err(RoutingError::FailedToBootstrap)
        // };
        // Ok(())
    }

    fn send_swarm_or_parallel_or_relay(&mut self, msg: &RoutingMessage)
        -> Result<(), RoutingError> {

        let destination = msg.destination_address();
        let signed_message = try!(SignedMessage::new(msg, &self.id.signing_private_key()));
        self.send_swarm_or_parallel_or_relay_signed_message(
            &signed_message, &destination)
    }

    fn send_swarm_or_parallel_or_relay_with_signature(&mut self, msg: &RoutingMessage,
        signature: Signature) -> Result<(), RoutingError> {

        let destination = msg.destination_address();
        let signed_message = try!(SignedMessage::with_signature(
            msg, signature));
        self.send_swarm_or_parallel_or_relay_signed_message(
            &signed_message, &destination)
    }

    fn send_swarm_or_parallel_or_relay_signed_message(&mut self,
        signed_message: &SignedMessage, destination: &Authority)
        -> Result<(), RoutingError> {
        unimplemented!()
        // if destination_address.non_relayed_destination() == self.id.name() {
        //     let bytes = try!(encode(signed_message));
        //
        //     match *destination_address {
        //         DestinationAddress::RelayToClient(_, public_key) => {
        //             self.send_out_as_relay(&Address::Client(public_key), bytes.clone());
        //         },
        //         DestinationAddress::RelayToNode(_, node_address) => {
        //             self.send_out_as_relay(&Address::Node(node_address), bytes.clone());
        //         },
        //         DestinationAddress::Direct(_) => {},
        //     }
        //     Ok(())
        // }
        // else {
        //     self.send_swarm_or_parallel_signed_message(
        //         signed_message, &destination_address.non_relayed_destination())
        // }
    }

    fn send_connect_request_msg(&mut self, peer_id: &Authority) -> RoutingResult {
        unimplemented!()
        // // FIXME: We're sending all accepting connections as local since we don't differentiate
        // // between local and external yet.
        // let connect_request = ConnectRequest {
        //     local_endpoints: self.accepting_on.clone(),
        //     external_endpoints: vec![],
        //     requester_id: self.id.name(),
        //     receiver_id: peer_id.clone(),
        //     requester_fob: PublicId::new(&self.id),
        // };
        //
        // let message =  RoutingMessage {
        //     destination  : peer_id,
        //     source       : self.my_source_address(),
        //     orig_message : None,
        //     message_type : MessageType::ConnectRequest(connect_request),
        //     message_id   : self.get_next_message_id(),
        //     authority    : Authority::ManagedNode
        // };
        //
        // self.send_swarm_or_parallel(&message)
    }

    // ---- I Am connection identification --------------------------------------------------------

    fn handle_i_am(&mut self, endpoint: &Endpoint, serialised_message: Bytes)
        -> RoutingResult {
            unimplemented!()
    }

    // -----Address and various functions----------------------------------------

    fn drop_bootstrap(&mut self) {
        match self.bootstrap {
            Some((ref endpoint, name)) => {
                if self.routing_table.size() > 0 {
                    info!("Dropped bootstrap on {:?} {:?}", endpoint, name);
                    self.connection_manager.drop_node(endpoint.clone());
                }
            },
            None => {}
        };
        self.bootstrap = None;
    }

    fn address_in_close_group_range(&self, destination_auth: &Authority) -> bool {
        let address = match destination_auth {
            Authority::ClientManager(name) => name,
            Authority::NaeManager(name)    => name,
            Authority::NodeManager(name)   => name,
            Authority::ManagedNode(name)   => name,
            Authority::Client(_, _)        => return false,
        };

        if self.routing_table.size() < types::QUORUM_SIZE  ||
           *address == self.id.name().clone()
        {
            return true;
        }

        match self.routing_table.our_close_group().last() {
            Some(furthest_close_node) => {
                closer_to_target_or_equal(&address, &furthest_close_node.id(), &self.id.name())
            },
            None => false  // ...should never reach here
        }
    }

    fn get_next_message_id(&mut self) -> MessageId {
        let temp = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        return temp;
    }

    fn lookup_endpoint(&self, endpoint: &Endpoint) -> Option<ConnectionName> {
        // prioritise routing table
        match self.routing_table.lookup_endpoint(&endpoint) {
            Some(name) => Some(ConnectionName::Routing(name)),
            // secondly look in the relay_map
            None => match self.relay_map.lookup_endpoint(&endpoint) {
                Some(name) => Some(ConnectionName::Relay(name)),
                // check to see if it is our bootstrap_endpoint
                None => match self.bootstrap {
                    Some((ref bootstrap_ep, ref bootstrap_name)) => {
                        if bootstrap_ep == endpoint {
                            Some(ConnectionName::OurBootstrap(bootstrap_name.clone()))
                        } else {
                            None
                        }
                    },
                    None => match self.relay_map.lookup_unknown_connection(&endpoint) {
                        true => Some(ConnectionName::UnidentifiedConnection),
                        false => None
                    }
                }
            }
        }
    }

    // -----Message Handlers from Routing Table connections----------------------------------------

    // Routing handle put_data
    fn handle_put_data(&mut self, signed_message: SignedMessage, message: RoutingMessage,
                       data: Data) -> RoutingResult {
        unimplemented!()
    }

    fn handle_post(&mut self, signed_message: SignedMessage, message: RoutingMessage, data: Data)
            -> RoutingResult {
        unimplemented!()
    }

    fn handle_put_data_response(&mut self, _signed_message: SignedMessage,
            message: RoutingMessage, response: ErrorReturn) -> RoutingResult {
        unimplemented!()
    }

    fn handle_post_response(&mut self, signed_message: SignedMessage,
                                       message: RoutingMessage,
                                       response: ErrorReturn) -> RoutingResult {
        unimplemented!()
    }

    fn handle_connect_request(&mut self,
                              connect_request: ConnectRequest,
                              message:         SignedMessage
                             ) -> RoutingResult {
        unimplemented!()
    }

    fn handle_refresh(&mut self, message: RoutingMessage, tag: u64, payload: Vec<u8>) -> RoutingResult {
        unimplemented!()
    }

    fn handle_connect_response(&mut self, connect_response: ConnectResponse) -> RoutingResult {
        unimplemented!()
    }

    /// On bootstrapping a node can temporarily publish its PublicId in the group.
    /// No handle_get_public_id is needed - this is handled by routing_node
    /// before the membrane instantiates.
    // TODO (Ben): check whether to accept id into group;
    // restrict on minimal similar number of leading bits.
    fn handle_put_public_id(&mut self, signed_message: SignedMessage, message: RoutingMessage,
        public_id: PublicId) -> RoutingResult {
        unimplemented!()
    }

    fn handle_find_group(&mut self, original_message: RoutingMessage) -> RoutingResult {
        unimplemented!()
    }

    fn handle_find_group_response(&mut self,
                                  find_group_response: Vec<PublicId>,
                                  refresh_our_own_group: bool) -> RoutingResult {
        unimplemented!()
    }

    fn handle_get_data(&mut self, orig_message: SignedMessage,
                                  message: RoutingMessage,
                                  data_request: DataRequest) -> RoutingResult {
        unimplemented!()
    }

    fn handle_node_get_data_response(&mut self, _signed_message : SignedMessage,
            message: RoutingMessage, response: GetDataResponse) -> RoutingResult {
        unimplemented!()
    }

    fn handle_client_get_data_response(&mut self, _orig_message : SignedMessage,
            message: RoutingMessage, response: GetDataResponse) -> RoutingResult {
        unimplemented!()
    }
}

fn ignore<R,E>(_result: Result<R,E>) {}
