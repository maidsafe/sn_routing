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

extern crate time;

use sodiumoxide;
use crust;
use message_filter::MessageFilter;
use std::sync::{Arc, mpsc, Mutex};
use std::sync::mpsc::{Receiver};
use facade::*;
use super::*;
use rand;
use std::net::{SocketAddr};
use std::collections::HashSet;
use std::collections::HashMap;
use std::net::{SocketAddrV4, Ipv4Addr};
use std::time::duration::Duration;

use routing_table::{RoutingTable, NodeInfo};
use types::{DhtId, MessageId, closer_to_target};
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

use crust::connection_manager::Endpoint::Tcp;
type ConnectionManager = crust::ConnectionManager;
type Event             = crust::Event;
type Endpoint          = crust::connection_manager::Endpoint;
type PortAndProtocol   = crust::connection_manager::PortAndProtocol;
type Bytes             = Vec<u8>;

type RecvResult = Result<(),()>;

/// DHT node
pub struct RoutingNode<F: Facade> {
    facade: Arc<Mutex<F>>,
    pmid: types::Pmid,
    own_id: DhtId,
    event_input: Receiver<Event>,
    connection_manager: ConnectionManager,
    pending_connections: HashSet<Endpoint>,
    all_connections: (HashMap<Endpoint, DhtId>, HashMap<DhtId, Endpoint>),
    routing_table: RoutingTable,
    accepting_on: Option<Vec<Endpoint>>,
    next_message_id: MessageId,
    bootstrap_node_id: Option<Endpoint>,
    filter: MessageFilter<types::FilterType>,
}

impl<F> RoutingNode<F> where F: Facade {
    pub fn new(id: DhtId, my_facade: F) -> RoutingNode<F> {
        sodiumoxide::init(); // enable shared global (i.e. safe to mutlithread now)
        let (event_output, event_input) = mpsc::channel();
        let pmid = types::Pmid::new();
        let own_id = pmid.get_name();
        let cm = crust::ConnectionManager::new(event_output);
        // TODO : Default Protocol and Port need to be passed down
        let ports_and_protocols : Vec<PortAndProtocol> = Vec::new();
        let accepting_on = cm.start_listening(ports_and_protocols).ok();

        RoutingNode { facade: Arc::new(Mutex::new(my_facade)),
                      pmid : pmid,
                      own_id : own_id.clone(),
                      event_input: event_input,
                      connection_manager: cm,
                      pending_connections : HashSet::new(),
                      all_connections: (HashMap::new(), HashMap::new()),
                      routing_table : RoutingTable::new(own_id),
                      accepting_on: accepting_on,
                      next_message_id: rand::random::<MessageId>(),
                      bootstrap_node_id: None,
                      filter: MessageFilter::with_expiry_duration(Duration::minutes(20))
                    }
    }

    pub fn accepting_on(&self) -> Option<Vec<crust::connection_manager::Endpoint>> {
        self.accepting_on.clone().and_then(|endpoints| {
            Some(endpoints)
        })
    }

    /// Retreive something from the network (non mutating) - Direct call
    pub fn get(&self, type_id: u64, name: DhtId) { unimplemented!()}

    /// Add something to the network, will always go via ClientManager group
    pub fn put(&self, name: DhtId, content: Vec<u8>) { unimplemented!() }

    /// Mutate something on the network (you must prove ownership) - Direct call
    pub fn post(&self, name: DhtId, content: Vec<u8>) { unimplemented!() }

    pub fn add_bootstrap(&mut self, endpoint: crust::connection_manager::Endpoint) {
        self.pending_connections.insert(endpoint.clone());
        let endpoints = vec![endpoint];
        let _ = self.connection_manager.connect(endpoints);
    }

    pub fn run(&mut self) {
        loop {
            let event = self.event_input.recv();

            if event.is_err() { return; }

            match event.unwrap() {
                crust::Event::NewMessage(endpoint, bytes) => {
                    if self.all_connections.0.contains_key(&endpoint) {
                        let peer_id = self.all_connections.0.get(&endpoint).unwrap().clone();
                        if self.message_received(&peer_id, bytes).is_err() {
                            println!("failed to Parse message !!! check  from - {:?} ", peer_id);
                            // let _ = self.connection_manager.drop_node(id);  // discuss : no need to drop
                        }
                    }
                },
                crust::Event::NewConnection(endpoint) => {
                    self.handle_connect(endpoint);
                },
                // crust::Event::Accept(id, bytes) => {
                //     self.handle_accept(id.clone(), bytes);
                // },
                crust::Event::LostConnection(endpoint) => {
                    self.handle_lost_connection(endpoint);
                },
                crust::Event::FailedToConnect(endpoints) => {
                    for endpoint in endpoints.iter() {
                        self.handle_lost_connection(endpoint.clone());
                    }
                }
            }
        }
    }

    fn next_endpoint_pair(&self) -> Option<(Vec<Endpoint>, Vec<Endpoint>)> {
        // FIXME: Set the second argument to 'external' address
        // when known.
        self.accepting_on().and_then(|addr| Some((addr.clone(), addr)))
    }

    fn handle_connect(&mut self, peer_endpoint: Endpoint) {
        if self.all_connections.0.contains_key(&peer_endpoint) || 
           self.pending_connections.contains(&peer_endpoint) {
            // ignore further request once received request or has added
            return;
        }
        self.pending_connections.insert(peer_endpoint.clone());
        self.bootstrap_node_id = Some(peer_endpoint.clone());
        // println!("{:?} bootstrap_node_id added : {:?}", self.own_id, peer_id);
        // send find group
        let msg = self.construct_find_group_msg();
        let msg = self.encode(&msg);
        debug_assert!(self.bootstrap_node_id.is_some());
        let _ = self.connection_manager.send(peer_endpoint, msg);
    }

    fn handle_accept(&mut self, peer_endpoint: Endpoint, peer_id: DhtId, bytes: Bytes) {
        // println!("In handle accept of {:?}", self.own_id);
        if self.all_connections.0.contains_key(&peer_endpoint) || 
           !self.pending_connections.contains(&peer_endpoint) {
            // ignore further request once added or not in sequence (not recorded as pending)
            return;
        }
        self.pending_connections.remove(&peer_endpoint);
        self.all_connections.0.insert(peer_endpoint.clone(), peer_id.clone());
        self.all_connections.1.insert(peer_id.clone(), peer_endpoint.clone());

        let connect_succcess_msg = self.decode::<ConnectSuccess>(&bytes);

        if connect_succcess_msg.is_none() {  // TODO handle non routing connection here
            if self.bootstrap_node_id.is_none() &&
             (self.all_connections.0.len() == 1) && (self.all_connections.0.contains_key(&peer_endpoint)) { // zero state only`
                self.bootstrap_node_id = Some(peer_endpoint.clone());
                // println!("{:?} bootstrap_node_id added : {:?}", self.own_id, peer_endpoint);
            }
            return;
        }
        let connect_succcess_msg = connect_succcess_msg.unwrap();
        let peer_node_info = NodeInfo::new(connect_succcess_msg.peer_fob, true);
        let result = self.routing_table.add_node(peer_node_info);
        if result.0 {
          println!("{:?} added {:?} <RT size:{}>", self.own_id, connect_succcess_msg.peer_id, self.routing_table.size());
        } else {
           println!("{:?} failed to add {:?}", self.own_id, connect_succcess_msg.peer_id);
        }
    }

    fn handle_lost_connection(&mut self, peer_endpoint: Endpoint) {
        self.pending_connections.remove(&peer_endpoint);
        let removed_entry = self.all_connections.0.remove(&peer_endpoint);
        if removed_entry.is_some() {
            let peer_id = removed_entry.unwrap();
            self.routing_table.drop_node(&peer_id);
            self.all_connections.1.remove(&peer_id);
          // TODO : remove from the non routing list
          // handle_churn
        }
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
        println!("{:?} <= {:?}: {:?} {:?}", self.own_id, peer_id, msg.message_type, header.destination);
        // filter check
        if self.filter.check(&header.get_filter()) {
          // should just return quietly
          return Err(());
        }
        // add to filter
        self.filter.add(header.get_filter());
        // add to cache
        // cache check / response
        self.send_swarm_or_parallel(&header.destination.dest, &serialised_message);
        // handle relay request/response

        let relay_response = header.destination.reply_to.is_some() &&
                             header.destination.dest == self.own_id;
        if relay_response {
            println!("{:?} relay response sent to nrt {:?}", self.own_id, header.destination.reply_to);
            // TODO : what shall happen to relaying message ? routing_node choosing a closest node ?
            for key in self.all_connections.0.keys() {
                let _ = self.connection_manager.send(key.clone(), serialised_message);
                return Ok(());
            }
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
        println!("{:?} received ConnectRequest ", self.own_id);
        let connect_request = try!(self.decode::<ConnectRequest>(&body).ok_or(()));
        if !(self.routing_table.check_node(&connect_request.requester_id)) {
           return Err(());
        }
        //let (receiver_local, receiver_external) = try!(self.next_endpoint_pair().ok_or(()));  //FIXME this is correct place

        let routing_msg = self.construct_connect_response_msg(&original_header, &connect_request);
        // FIXME(Peter) below method is needed
        // send_swarm_or_parallel();

        if original_header.source.reply_to.is_some() {
            let reply_to_address = original_header.source.reply_to.unwrap();
            if self.all_connections.1.contains_key(&reply_to_address) {
                let _ = self.connection_manager.send(self.all_connections.1.get(&reply_to_address).unwrap().clone(),
                                                     self.encode(&routing_msg));
            } else {
                return Err(());
            }
        }
        Ok(())
    }

    fn handle_connect_response(&mut self, body: Bytes) -> RecvResult {
        println!("{:?} received ConnectResponse", self.own_id);
        let connect_response = try!(self.decode::<ConnectResponse>(&body).ok_or(()));
        if !(self.routing_table.check_node(&connect_response.receiver_id)) {
           return Ok(())
        }

        // The following code block is no longer required due to the changes in crust 
        // let success_msg = self.construct_success_msg();
        // let msg = self.encode(&success_msg);
        // let _ = self.connection_manager.connect(msg);

        // workaround for zero state
        if (self.all_connections.0.len() == 1) && (self.all_connections.1.contains_key(&connect_response.receiver_id)) {
            let peer_node_info = NodeInfo::new(connect_response.receiver_fob, true);
            let result = self.routing_table.add_node(peer_node_info);
            if result.0 {
                println!("{:?} added {:?} <RT size:{}>", self.own_id, connect_response.receiver_id, self.routing_table.size());
            } else {
                println!("{:?} failed to add {:?}", self.own_id, connect_response.receiver_id);
            }
        }
        Ok(())
    }

    fn handle_find_group(&mut self, original_header: MessageHeader, body: Bytes) -> RecvResult {
        //println!("{:?} received FindGroup", self.own_id);
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
            let reply_to_address = original_header.source.reply_to.unwrap();
            if self.all_connections.1.contains_key(&reply_to_address) {
                let _ = self.connection_manager.send(self.all_connections.1.get(&reply_to_address).unwrap().clone(),
                                                     self.encode(&routing_msg));
            } else {
                return Err(());
            }
        }
        Ok(())
    }

    fn handle_find_group_response(&mut self, original_header: MessageHeader, body: Bytes) -> RecvResult {
        //println!("{:?} received FindGroupResponse", self.own_id);
        let find_group_response = try!(self.decode::<FindGroupResponse>(&body).ok_or(()));
        for peer in find_group_response.group {
            if !self.routing_table.check_node(&peer.name) {
                continue;
            }
            let routing_msg = self.construct_connect_request_msg(&peer.name);
            if self.bootstrap_node_id.is_some() {
                let bootstrap_node = self.bootstrap_node_id.clone();
                let _ = self.connection_manager.send(bootstrap_node.unwrap(), self.encode(&routing_msg));
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
            return types::SourceAddress{ from_node: self.all_connections.0.get(&self.bootstrap_node_id.clone().unwrap()).unwrap().clone(),
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

        let invalid_addr = vec![Tcp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0,0,0,0), 0)))];
        let (requester_local, requester_external)
            = self.next_endpoint_pair().unwrap_or((invalid_addr.clone(), invalid_addr));  // FIXME


        let connect_request = ConnectRequest {
            local:          match requester_local[0] { Tcp(local) => local },
            external:       match requester_external[0] { Tcp(local) => local },
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

    fn construct_connect_response_msg(&mut self, original_header : &MessageHeader,
                                      connect_request: &ConnectRequest) -> RoutingMessage {
        println!("{:?} construct_connect_response_msg ", self.own_id);
        debug_assert!(connect_request.receiver_id == self.own_id, format!("{:?} == {:?} failed", self.own_id, connect_request.receiver_id));

        let header = MessageHeader {
            message_id:  self.get_next_message_id(),
            destination: original_header.send_to(),
            source:      self.our_source_address(),
            authority:   types::Authority::ManagedNode,
            signature:   None  // FIXME
        };
        let invalid_addr = vec![Tcp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0,0,0,0), 0)))];
        let (receiver_local, receiver_external)
            = self.next_endpoint_pair().unwrap_or((invalid_addr.clone(), invalid_addr));  // FIXME

        let connect_response = ConnectResponse {
            requester_local:    connect_request.local,
            requester_external: connect_request.external,
            receiver_local:     match receiver_local[0] { Tcp(local) => local },
            receiver_external:  match receiver_external[0] { Tcp(local) => local },
            requester_id:       connect_request.requester_id.clone(),
            receiver_id:        self.own_id.clone(),
            receiver_fob:       types::PublicPmid::new(&self.pmid) };

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
            if self.all_connections.1.contains_key(&peer.id) {
                let res = self.connection_manager.send(self.all_connections.1.get(&peer.id).unwrap().clone(),
                                                       serialised_message.clone());
                if res.is_err() {
                    println!("{:?} failed to send to {:?}", self.own_id, peer.id);
                }
            }
        }
    }

    fn get_connected_target(&self, target: &DhtId) -> Vec<NodeInfo> {
        let mut nodes = self.routing_table.target_nodes(target.clone());
        //println!("{:?} get_connected_target routing_table.size:{} target:{:?} -> {:?}", self.own_id, self.routing_table.size(), target, nodes);
        nodes.retain(|x| { x.connected });
        nodes
    }

    fn address_in_close_group_range(&self, address: &DhtId) -> bool {
        if self.routing_table.size() < RoutingTable::get_group_size() {
            return true;
        }

        let close_group = self.routing_table.our_close_group();
        closer_to_target(&address, &self.routing_table.our_close_group().pop().unwrap().id, &self.own_id)
    }

    pub fn id(&self) -> DhtId { self.own_id.clone() }
}

#[cfg(test)]
mod test {
    use routing_node::{RoutingNode};
    use facade::{Facade};
    use types::{Authority, DhtId, DestinationAddress};
    use super::super::{Action, RoutingError};
    use std::thread;
    use std::net::{SocketAddr};
    use std::str::FromStr;

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

    //#[test]
    //fn test_routing_node() {
    //    let f1 = NullFacade;
    //    let f2 = NullFacade;
    //    let f3 = NullFacade;
    //    let n1 = RoutingNode::new(DhtId::generate_random(), f1);
    //    let n2 = RoutingNode::new(DhtId::generate_random(), f2);
    //    let n3 = RoutingNode::new(DhtId::generate_random(), f3);

    //    println!("{:?}->Alice", n1.id());
    //    println!("{:?}->Betty", n2.id());
    //    println!("{:?}->Casey", n3.id());
    //    let n1_ep = n1.accepting_on().unwrap();
    //    let n2_ep = n2.accepting_on().unwrap();
    //    let n3_ep = n3.accepting_on().unwrap();

    //    fn run_node(n: RoutingNode<NullFacade>, my_ep: SocketAddr, his_ep: SocketAddr)
    //        -> thread::JoinHandle
    //    {
    //        thread::spawn(move || {
    //            let mut n = n;
    //            let bootstrap_ep = SocketAddr::from_str(&format!("127.0.0.1:{}", 5483u16)).unwrap();
    //            if my_ep.port() != bootstrap_ep.port() {
    //                n.add_bootstrap(bootstrap_ep);
    //            }
    //            n.run();
    //        })
    //    }

    //    let t1 = run_node(n1, n1_ep.clone(), n2_ep.clone());
    //    let t2 = run_node(n2, n2_ep.clone(), n1_ep.clone());
    //    thread::sleep_ms(1000);
    //    println!("Starting node 3 ... ");
    //    let t3 = run_node(n3, n3_ep.clone(), n1_ep.clone());
    //    assert!(t1.join().is_ok());
    //    assert!(t2.join().is_ok());
    //    assert!(t3.join().is_ok());
    //}
}
#[test]
fn dummy_routing()  {
}
