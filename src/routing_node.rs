// Copyright 2015 MaidSafe.net limited
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe
// Software.

extern crate rand;
extern crate chrono;

use sodiumoxide;
use crust;
use lru_time_cache::LruCache;
use std::sync::{Arc, mpsc, Mutex};
use std::sync::mpsc::{Receiver};
use facade::*;
use super::*;
use std::net::{SocketAddr};
use std::str::FromStr;
use std::collections::HashSet;
use std::net::{SocketAddrV4, Ipv4Addr};

use routing_table::RoutingTable;
use types::{DhtId, MessageId};
use message_header::MessageHeader;
use messages;
use messages::get_data::GetData;
use messages::get_data_response::GetDataResponse;
use messages::put_data::PutData;
use messages::put_data_response::PutDataResponse;
use messages::connect_request::ConnectRequest;
use messages::connect_response::ConnectResponse;
use messages::connect_success::ConnectSuccess;
use messages::find_group::FindGroup;
use messages::find_group_response::FindGroupResponse;
use messages::{RoutingMessage, MessageTypeTag};
use rustc_serialize::{Decodable, Encodable};
use cbor::{Encoder, Decoder};

use types::RoutingTrait;

type ConnectionManager = crust::ConnectionManager<DhtId>;
type Event             = crust::Event<DhtId>;
type Bytes             = Vec<u8>;

type RecvResult = Result<(),()>;

/// DHT node
pub struct RoutingNode<F: Facade> {
    facade: Arc<Mutex<F>>,
    pmid: types::Pmid,
    own_id: DhtId,
    event_input: Receiver<Event>,
    connection_manager: ConnectionManager,
    all_connections: HashSet<DhtId>,
    routing_table: RoutingTable,
    accepting_on: Option<u16>,
    next_message_id: MessageId,
    bootstrap_node_id: Option<DhtId>,
    filter: LruCache<types::FilterType, ()>,
}

impl<F> RoutingNode<F> where F: Facade {
    pub fn new(id: DhtId, my_facade: F) -> RoutingNode<F> {
        sodiumoxide::init(); // enable shared global (i.e. safe to mutlithread now)
        let (event_output, event_input) = mpsc::channel();
        let pmid = types::Pmid::new();
        let own_id = pmid.get_name();
        let cm = crust::ConnectionManager::new(own_id.clone(), event_output);
        let accepting_on = cm.start_accepting().ok();

        RoutingNode { facade: Arc::new(Mutex::new(my_facade)),
                      pmid : pmid,
                      own_id : own_id.clone(),
                      event_input: event_input,
                      connection_manager: cm,
                      all_connections: HashSet::new(),
                      routing_table : RoutingTable::new(own_id),
                      accepting_on: accepting_on,
                      next_message_id: rand::random::<MessageId>(),
                      bootstrap_node_id: None,
                      filter: LruCache::with_expiry_duration(
                        chrono::duration::Duration::minutes(20))
                    }
    }

    pub fn accepting_on(&self) -> Option<SocketAddr> {
        self.accepting_on.and_then(|port| {
            SocketAddr::from_str(&format!("127.0.0.1:{}", port)).ok()
        })
    }

    /// Retreive something from the network (non mutating) - Direct call
    pub fn get(&self, type_id: u64, name: DhtId) { unimplemented!()}

    /// Add something to the network, will always go via ClientManager group
    pub fn put(&self, name: DhtId, content: Vec<u8>) { unimplemented!() }

    /// Mutate something on the network (you must prove ownership) - Direct call
    pub fn post(&self, name: DhtId, content: Vec<u8>) { unimplemented!() }

    pub fn add_bootstrap(&mut self, endpoint: SocketAddr) {
        // let msg = self.construct_find_group_msg();
        // let msg = self.encode(&msg);
        let _ = self.connection_manager.connect(endpoint, vec![0]);
    }

    pub fn run(&mut self) {
        loop {
            let event = self.event_input.recv();

            if event.is_err() { return; }

            match event.unwrap() {
                crust::Event::NewMessage(id, bytes) => {
                    if self.message_received(&id, bytes).is_err() {
                      println!("failed to Parse message !!! check  from - {:?} ", id);
                        // let _ = self.connection_manager.drop_node(id);  // discuss : no need to drop
                    }
                },
                crust::Event::Connect(id) => {
                    self.handle_connect(id);
                },
                crust::Event::Accept(id, bytes) => {
                    self.handle_accept(id.clone(), bytes);
                },
                crust::Event::LostConnection(id) => {
                    self.handle_lost_connection(id);
                }
            }
        }
    }

    fn next_endpoint_pair(&self) -> Option<(SocketAddr, SocketAddr)> {
        // FIXME: Set the second argument to 'external' address
        // when known.
        self.accepting_on().and_then(|addr| Some((addr, addr)))
    }

    fn handle_connect(&mut self, peer_id: DhtId) {
        if self.all_connections.is_empty() {
            self.bootstrap_node_id = Some(peer_id.clone());
            println!("{:?} bootstrap_node_id added : {:?}", self.own_id, peer_id);
            // send find group
            let msg = self.construct_find_group_msg();
            let msg = self.encode(&msg);
            debug_assert!(self.bootstrap_node_id.is_some());
            let _ = self.connection_manager.send(msg, peer_id.clone());
        }
        self.all_connections.insert(peer_id.clone());
    }

    fn handle_accept(&mut self, peer_id: DhtId, bytes: Bytes) {
        // println!("In handle accept of {:?}", self.own_id);
        self.all_connections.insert(peer_id.clone());
        let connect_succcess_msg = self.decode::<ConnectSuccess>(&bytes);

        if connect_succcess_msg.is_none() {  // TODO handle non routing connection here
            if self.bootstrap_node_id.is_none() &&
             (self.all_connections.len() == 1) && (self.all_connections.contains(&peer_id)) { // zero state only`
                self.bootstrap_node_id = Some(peer_id.clone());
                println!("{:?} bootstrap_node_id added : {:?}", self.own_id, peer_id);
            }
            return;
        }
        let connect_succcess_msg = connect_succcess_msg.unwrap();
        let peer_node_info = routing_table::NodeInfo::new(connect_succcess_msg.peer_fob, true);
        let result = self.routing_table.add_node(peer_node_info);
        if result.0 {
          println!("{:?} added {:?} <RT>", self.own_id, connect_succcess_msg.peer_id);
        } else {
           println!("{:?} failed to add {:?}", self.own_id, connect_succcess_msg.peer_id);
        }
    }

    fn handle_lost_connection(&mut self, peer_id: DhtId) {
        self.routing_table.drop_node(&peer_id);
        self.all_connections.remove(&peer_id);
        // remove from the non routing list
        // handle_curn
    }

    fn message_received(&mut self, peer_id: &DhtId, serialised_message: Bytes) -> RecvResult {
        // Parse
        let msg = self.decode::<RoutingMessage>(&serialised_message);

        if msg.is_none() {
            println!("Problem parsing message of size {} from {:?}",
                     serialised_message.len(), peer_id);
            return Err(());
        }

        let msg    = msg.unwrap();
        let header = msg.message_header;
        let body   = msg.serialised_body;
        println!("{:?} Rxd from {:?} =>  {:?}", self.own_id, peer_id, msg.message_type);
        // filter check
        if self.filter.check(&header.get_filter()) {
          // should just return quietly
          return Err(());
        }
        // add to filter
        self.filter.add(header.get_filter(), ());
        // add to cache
        // cache check / response
        self.send_swarm_or_parallel(&header.destination.dest, &serialised_message);
        // handle relay request/response

        let relay_response = header.destination.reply_to.is_some() &&
                             header.destination.dest == self.own_id;
        if relay_response {
            println!("{:?} relay response sent to nrt {:?}", self.own_id, header.destination.reply_to);
            let _ = self.connection_manager.send(serialised_message, header.destination.reply_to.unwrap());
            return Ok(());
        }

        // TODO(prakash)

        if !self.address_in_close_group_range(&header.destination.dest) {
            println!("{:?} not for us ", self.own_id);
            return Ok(());
        }

        // Drop message before Sentinel check if it is a direct message type (Connect, ConnectResponse)
        // and this node is in the group but the message destination is another group member node.
        // "not for me"

        // Sentinel check

        // switch message type
        match msg.message_type {
            MessageTypeTag::ConnectRequest => self.handle_connect_request(header, body),
            MessageTypeTag::ConnectResponse => self.handle_connect_response(body),
            MessageTypeTag::FindGroup => self.handle_find_group(header, body),
            MessageTypeTag::FindGroupResponse => self.handle_find_group_response(header, body),
            //GetData,
            //GetDataResponse,
            //GetClientKey,
            //GetClientKeyResponse,
            //GetGroupKey,
            //GetGroupKeyResponse,
            //Post,
            //PostResponse,
            //PutData,
            //PutDataResponse,
            //PutKey,
            //AccountTransfer
            _ => {
                println!("unhandled message from {:?}", peer_id);
                Err(())
            }
        }
    }

    fn handle_connect_request(&mut self, original_header: MessageHeader, body: Bytes) -> RecvResult {
        println!("{:?} received ConnectRequest", self.own_id);
        let connect_request = try!(self.decode::<ConnectRequest>(&body).ok_or(()));
        if !(self.routing_table.check_node(&connect_request.requester_id)) {
           return Err(());
        }
        //let (receiver_local, receiver_external) = try!(self.next_endpoint_pair().ok_or(()));  //FIXME this is correct place

        let routing_msg = self.construct_connect_response_msg(&original_header, &connect_request);
        // FIXME(Peter) below method is needed
        // send_swarm_or_parallel();

        if original_header.source.reply_to.is_some() {
            let reply_to_address = original_header.source.reply_to.clone();
            let _ = self.connection_manager.send(self.encode(&routing_msg),
                                                 reply_to_address.unwrap());
        }
        Ok(())
    }

    fn handle_connect_response(&mut self, body: Bytes) -> RecvResult {
        println!("{:?} received ConnectResponse", self.own_id);
        let connect_response = try!(self.decode::<ConnectResponse>(&body).ok_or(()));
        if !(self.routing_table.check_node(&connect_response.receiver_id)) {
           return Ok(())
        }
        // AddNode
        let success_msg = self.construct_success_msg();
        let msg = self.encode(&success_msg);
        let _ = self.connection_manager.connect(connect_response.receiver_external,
                                                msg);
        // workaround for zero state
        if (self.all_connections.len() == 1) && (self.all_connections.contains(&connect_response.receiver_id)) {
            let peer_node_info = routing_table::NodeInfo::new(connect_response.receiver_fob, true);
            let result = self.routing_table.add_node(peer_node_info);
            if result.0 {
                println!("{:?} added {:?} <RT>", self.own_id, connect_response.receiver_id);
            } else {
                println!("{:?} failed to add {:?}", self.own_id, connect_response.receiver_id);
            }
        }
        Ok(())
    }

    fn handle_find_group(&mut self, original_header: MessageHeader, body: Bytes) -> RecvResult {
        println!("{:?} received FindGroup", self.own_id);
        let find_group = try!(self.decode::<FindGroup>(&body).ok_or(()));
        let close_group = self.routing_table.our_close_group();
        let mut group: Vec<types::PublicPmid> =  vec![];;
        for x in close_group {
            group.push(x.fob);
        }
        // add ourselves
        group.push(types::PublicPmid::new(&self.pmid));
        let routing_msg = self.construct_find_group_response_msg(&original_header, &find_group, group);

        // FIXME(Peter) below method is needed
        // send_swarm_or_parallel();
        // if node in my group && in non routing list send it to non_routnig list as well
        if original_header.source.reply_to.is_some() {
            let reply_to_address = original_header.source.reply_to.clone();
            let _ = self.connection_manager.send(self.encode(&routing_msg),
                                                    reply_to_address.unwrap());
        }
        Ok(())
    }

    fn handle_find_group_response(&mut self, original_header: MessageHeader, body: Bytes) -> RecvResult {
        println!("{:?} received FindGroupResponse", self.own_id);
        let find_group_response = try!(self.decode::<FindGroupResponse>(&body).ok_or(()));
        for peer in find_group_response.group {
            if !self.routing_table.check_node(&peer.name) {
                continue;
            }
            let routing_msg = self.construct_connect_request_msg(&peer.name);
            if self.bootstrap_node_id.is_some() {
                let bootstrap_node = self.bootstrap_node_id.clone();
                let _ = self.connection_manager.send(self.encode(&routing_msg), bootstrap_node.unwrap());
            }
            // SendSwarmOrParallel  // FIXME
        }
        Ok(())
    }

    fn handle_get_data(get_data: GetData, original_header: MessageHeader) {
        unimplemented!();
    }

    fn handle_get_data_response(get_data_response: GetDataResponse, original_header: MessageHeader) {
        // need to call facade handle_get_response
        unimplemented!();
    }

    // // for clients, below methods are required
    fn handle_put_data(put_data: PutData, original_header: MessageHeader) {
        // need to call facade handle_get_response
        unimplemented!();
    }

    fn handle_put_data_response(put_data_response: PutDataResponse, original_header: MessageHeader) {
        // need to call facade handle_put_response
        unimplemented!();
    }

    fn decode<T>(&self, bytes: &Bytes) -> Option<T> where T: Decodable {
        let mut dec = Decoder::from_bytes(&bytes[..]);
        dec.decode().next().and_then(|result| result.ok())
    }

    fn encode<T>(&self, value: &T) -> Bytes where T: Encodable
    {
        let mut enc = Encoder::from_memory();
        let _ = enc.encode(&[value]);
        enc.into_bytes()
    }

    fn our_source_address(&self) -> types::SourceAddress {
        if self.bootstrap_node_id.is_some() {
            return types::SourceAddress{ from_node: self.bootstrap_node_id.clone().unwrap(),
                                         from_group: None,
                                         reply_to: Some(self.own_id.clone()) }
        } else {
            return types::SourceAddress{ from_node: self.own_id.clone(),
                                         from_group: None,
                                         reply_to: None }
        }
    }

    fn our_group_address(&self, group_id: DhtId) -> types::SourceAddress {
        types::SourceAddress{ from_node: self.own_id.clone(), from_group: Some(group_id.clone()),
                                reply_to: None }
    }

    fn construct_find_group_msg(&mut self) -> RoutingMessage {
        let header = MessageHeader {
            message_id:  self.get_next_message_id(),
            destination: types::DestinationAddress {
                             dest:     self.own_id.clone(),
                             reply_to: None
                         },
            source:      self.our_source_address(),
            authority:   types::Authority::ManagedNode,
            signature:   None
        };
        RoutingMessage{
            message_type:    messages::MessageTypeTag::FindGroup,
            message_header:  header,
            serialised_body: self.encode(&FindGroup{ requester_id: self.own_id.clone(),
                                                     target_id:    self.own_id.clone()
                                                   })
        }
    }

    fn construct_find_group_response_msg(&mut self, original_header : &MessageHeader,
                                         find_group: &FindGroup,
                                         group: Vec<types::PublicPmid>) -> RoutingMessage {
        let header = MessageHeader {
            message_id:  self.get_next_message_id(),
            destination: original_header.send_to(),
            source:      self.our_group_address(find_group.target_id.clone()),
            authority:   types::Authority::NaeManager,
            signature:   None
        };

        RoutingMessage{
            message_type:    messages::MessageTypeTag::FindGroupResponse,
            message_header:  header,
            serialised_body: self.encode(&FindGroupResponse{ target_id: find_group.target_id.clone(),
                                                             group: group
                                                            })
        }
    }

    fn construct_success_msg(&mut self) -> ConnectSuccess {
        let connect_success = ConnectSuccess {
                                                peer_id: self.own_id.clone(),
                                                peer_fob: types::PublicPmid::new(&self.pmid),
                                              };
        return connect_success
    }

    fn construct_connect_request_msg(&mut self, peer_id: &DhtId) -> RoutingMessage {
        let header = MessageHeader {
            message_id:  self.get_next_message_id(),
            destination: types::DestinationAddress {dest: peer_id.clone(), reply_to: None },
            source:      self.our_source_address(),
            authority:   types::Authority::ManagedNode,
            signature:   None
        };

        let invalid_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0,0,0,0), 0));
        let (requester_local, requester_external)
            = self.next_endpoint_pair().unwrap_or((invalid_addr, invalid_addr));  // FIXME


        let connect_request = ConnectRequest {
            local:          requester_local,
            external:       requester_external,
            requester_id:   self.own_id.clone(),
            receiver_id:    peer_id.clone(),
            requester_fob:  types::PublicPmid::new(&self.pmid),
        };

        RoutingMessage{
            message_type:    MessageTypeTag::ConnectRequest,
            message_header:  header,
            serialised_body: self.encode(&connect_request)
        }
    }

    fn construct_connect_response_msg (&mut self, original_header : &MessageHeader,
                                         connect_request: &ConnectRequest) -> RoutingMessage {
        let header = MessageHeader {
            message_id:  self.get_next_message_id(),
            destination: original_header.send_to(),
            source:      self.our_source_address(),
            authority:   types::Authority::ManagedNode,
            signature:   None  // FIXME
        };
        let invalid_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0,0,0,0), 0));
        let (receiver_local, receiver_external)
            = self.next_endpoint_pair().unwrap_or((invalid_addr, invalid_addr));  // FIXME

        let connect_response = ConnectResponse {
            requester_local:    connect_request.local,
            requester_external: connect_request.external,
            receiver_local:     receiver_local,
            receiver_external:  receiver_external,
            requester_id:       connect_request.requester_id.clone(),
            receiver_id:        self.own_id.clone(),
            receiver_fob:       types::PublicPmid::new(&self.pmid) };

        debug_assert!(connect_request.receiver_id == self.own_id);

        RoutingMessage{
            message_type:    MessageTypeTag::ConnectResponse,
            message_header:  header,
            serialised_body: self.encode(&connect_response)
        }
    }

    fn get_next_message_id(&mut self) -> MessageId {
        let current = self.next_message_id;
        self.next_message_id += 1;
        current
    }

    fn send_swarm_or_parallel(&self, target: &DhtId, serialised_message: &Bytes) {
        for peer in self.get_connected_target(target) {
            let res = self.connection_manager.send(serialised_message.clone(), peer.id.clone());
            if res.is_err() {
                println!("{:?} failed to send to {:?}", self.own_id, peer.id);
            }
        }
    }

    fn get_connected_target(&self, target: &DhtId) -> Vec<routing_table::NodeInfo> {
        let mut nodes = self.routing_table.target_nodes(target.clone());
        nodes.retain(|x| { x.connected });
        nodes
    }

    fn address_in_close_group_range(&self, address: &DhtId) -> bool {
        if self.routing_table.size() < RoutingTable::get_group_size() {
            return true;
        }

        let close_group = self.routing_table.our_close_group();
        RoutingTable::closer_to_target(&address,
                                       &self.routing_table.our_close_group().pop().unwrap().id,
                                       &self.own_id)
    }
}

#[cfg(test)]
mod test {
    // use routing_node::{RoutingNode};
    use facade::{Facade};
    use types::{Authority, DhtId, DestinationAddress};
    use super::super::{Action, RoutingError};
    // use std::thread;
    // use std::net::{SocketAddr};
    // use std::str::FromStr;

    struct NullFacade;

    impl Facade for NullFacade {
      fn handle_get(&mut self, type_id: u64, our_authority: Authority, from_authority: Authority,from_address: DhtId , data: Vec<u8>)->Result<Action, RoutingError> { Err(RoutingError::Success) }
      fn handle_put(&mut self, our_authority: Authority, from_authority: Authority,
                    from_address: DhtId, dest_address: DestinationAddress, data: Vec<u8>)->Result<Action, RoutingError> { Err(RoutingError::Success) }
      fn handle_post(&mut self, our_authority: Authority, from_authority: Authority, from_address: DhtId, data: Vec<u8>)->Result<Action, RoutingError> { Err(RoutingError::Success) }
      fn handle_get_response(&mut self, from_address: DhtId , response: Result<Vec<u8>, RoutingError>) { }
      fn handle_put_response(&mut self, from_authority: Authority,from_address: DhtId , response: Result<Vec<u8>, RoutingError>) { }
      fn handle_post_response(&mut self, from_authority: Authority,from_address: DhtId , response: Result<Vec<u8>, RoutingError>) { }
      fn add_node(&mut self, node: DhtId) {}
      fn drop_node(&mut self, node: DhtId) {}
    }

//FIXME(Peter)
    // #[test]
    // fn test_routing_node() {
    //     let f1 = NullFacade;
    //     let f2 = NullFacade;
    //     let f3 = NullFacade;
    //     let n1 = RoutingNode::new(DhtId::generate_random(), f1);
    //     let n2 = RoutingNode::new(DhtId::generate_random(), f2);
    //     let n3 = RoutingNode::new(DhtId::generate_random(), f3);

    //     let n1_ep = n1.accepting_on().unwrap();
    //     let n2_ep = n2.accepting_on().unwrap();
    //     let n3_ep = n3.accepting_on().unwrap();

    //     fn run_node(n: RoutingNode<NullFacade>, my_ep: SocketAddr, his_ep: SocketAddr)
    //         -> thread::JoinHandle
    //     {
    //         thread::spawn(move || {
    //             let mut n = n;
    //             let bootstrap_ep = SocketAddr::from_str(&format!("127.0.0.1:{}", 5483u16)).unwrap();
    //             if my_ep.port() != bootstrap_ep.port() {
    //                 n.add_bootstrap(bootstrap_ep);
    //             }
    //             n.run();
    //         })
    //     }

    //     let t1 = run_node(n1, n1_ep.clone(), n2_ep.clone());
    //     let t2 = run_node(n2, n2_ep.clone(), n1_ep.clone());
    //     thread::sleep_ms(1000);
    //     println!("Starting node 3 ... ");
    //     let t3 = run_node(n3, n3_ep.clone(), n1_ep.clone());
    //     assert!(t1.join().is_ok());
    //     assert!(t2.join().is_ok());
    //     assert!(t3.join().is_ok());
    // }
}
