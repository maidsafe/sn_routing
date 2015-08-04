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

static MAX_BOOTSTRAP_CONNECTIONS : usize = 1;

/// Routing Membrane
pub struct RoutingHandler {
    // for CRUST
    sender_clone        : Sender<CrustEvent>,
    crust_channel       : Receiver<CrustEvent>,
    connection_manager  : crust::ConnectionManager,
    reflective_endpoint : crust::Endpoint,
    accepting_on        : Vec<crust::Endpoint>,
    bootstraps          : BTreeMap<Endpoint, Option<NameType>>,
    // for RoutingNode
    node_channel        : Sender<NodeEvent>,
    // for Routing
    id                  : Id,
    routing_table       : RoutingTable,
    relay_map           : RelayMap,
    filter              : MessageFilter<types::FilterType>,
    public_id_cache     : LruCache<NameType, PublicId>,
    connection_cache    : BTreeMap<NameType, SteadyTime>,
    refresh_accumulator : RefreshAccumulator,
}

impl RoutingHandler {
    pub fn new() -> RoutingHandler {
        let id = Id::new();

        let (crust_output, crust_input) = mpsc::channel();
        let mut cm = crust::ConnectionManager::new(crust_output.clone());
        let _ = cm.start_accepting(vec![]);

        cm.bootstrap(MAX_BOOTSTRAP_CONNECTIONS);
        match crust_input.recv() {
            Ok(crust::Event::NewConnection(endpoint)) => {},
            Ok(crust::Event::NewBootstrapConnection(endpoint)) =>
                RoutingHandler::bootstrap(),
            _ => {
                error!("The first event received from Crust is not a new connection.");
                return Err(RoutingError::FailedToBootstrap)
            }
        }
        RoutingHandler{

        }
    }


    fn send_event_to_user(&self, _event: Event) {
        unimplemented!()
    }

    fn bootstrap(&mut cm : crust::ConnectionManager) {

    }

    fn request_network_name(&mut cm : crust::ConnectionManager)
        -> Result<NameType,RoutingError>  {

    }

    /// When CRUST receives a connect to our listening port and establishes a new connection,
    /// the endpoint is given here as new connection
    fn handle_new_connection(&mut self, endpoint : Endpoint) {
        self.drop_bootstrap();
        match self.lookup_endpoint(&endpoint) {
            Some(ConnectionName::ReflectionOnToUs) => { }
            Some(_) => { },
            None => {
                self.relay_map.register_unknown_connection(endpoint.clone());
                ignore(self.send_i_am_msg(endpoint));
            }
      }
    }

    /// When CRUST reports a lost connection, ensure we remove the endpoint anywhere
    /// TODO: A churn event might be triggered
    fn handle_lost_connection(&mut self, endpoint : Endpoint) {
        // Make sure the endpoint is dropped anywhere
        // The relay map will automatically drop the Name if the last endpoint to it is dropped
        self.relay_map.remove_unknown_connection(&endpoint);
        self.relay_map.drop_endpoint(&endpoint);
        let mut trigger_handle_churn = false;
        match self.routing_table.lookup_endpoint(&endpoint) {
            Some(name) => {
                trigger_handle_churn = self.routing_table
                    .address_in_our_close_group_range(&name);
                self.routing_table.drop_node(&name);
                info!("RT (size : {:?}) connection {:?} disconnected for {:?}.",
                    self.routing_table.size(), endpoint, name);
            },
            None => {}
        };
        let mut drop_bootstrap = false;
        match self.bootstrap {
            Some((ref bootstrap_endpoint, _)) => {
                if &endpoint == bootstrap_endpoint {
                    info!("Bootstrap connection disconnected by relay node.");
                    self.connection_manager.drop_node(endpoint);
                    drop_bootstrap = true;
                }
            },
            None => {}
        };
        if drop_bootstrap { self.bootstrap = None; }

        if trigger_handle_churn {
            info!("Handle CHURN lost node");

            let mut close_group : Vec<NameType> = self.routing_table
                .our_close_group().iter()
                .map(|node_info| node_info.fob.name())
                .collect();

            close_group.insert(0, self.id.name().clone());

            self.send_event_to_user(Event::Churn(close_group));
        };
    }

    fn construct_find_group_msg(&mut self) -> RoutingMessage {
        let name   = self.id.name().clone();
        let message_id = self.get_next_message_id();

        RoutingMessage {
            destination  : DestinationAddress::Direct(name.clone()),
            source       : SourceAddress::Direct(name.clone()),
            orig_message : None,
            message_type : MessageType::FindGroup,
            message_id   : message_id,
            authority    : Authority::ManagedNode,
        }
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
                }
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
        let bytes = try!(encode(&signed_message));
        let new_event = CrustEvent::NewMessage(self.reflective_endpoint.clone(), bytes);
        match self.sender_clone.send(new_event) {
            Ok(_) => {},
            // FIXME(ben 24/07/2015) we have a broken channel with crust,
            // should terminate node
            Err(_) => return Err(RoutingError::FailedToBootstrap)
        };
        Ok(())
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
        signed_message: &SignedMessage, destination_address: &DestinationAddress)
        -> Result<(), RoutingError> {

        if destination_address.non_relayed_destination() == self.id.name() {
            let bytes = try!(encode(signed_message));

            match *destination_address {
                DestinationAddress::RelayToClient(_, public_key) => {
                    self.send_out_as_relay(&Address::Client(public_key), bytes.clone());
                },
                DestinationAddress::RelayToNode(_, node_address) => {
                    self.send_out_as_relay(&Address::Node(node_address), bytes.clone());
                },
                DestinationAddress::Direct(_) => {},
            }
            Ok(())
        }
        else {
            self.send_swarm_or_parallel_signed_message(
                signed_message, &destination_address.non_relayed_destination())
        }
    }

    fn send_connect_request_msg(&mut self, peer_id: &NameType) -> RoutingResult {
        // FIXME: We're sending all accepting connections as local since we don't differentiate
        // between local and external yet.
        let connect_request = ConnectRequest {
            local_endpoints: self.accepting_on.clone(),
            external_endpoints: vec![],
            requester_id: self.id.name(),
            receiver_id: peer_id.clone(),
            requester_fob: PublicId::new(&self.id),
        };

        let message =  RoutingMessage {
            destination  : DestinationAddress::Direct(peer_id.clone()),
            source       : self.my_source_address(),
            orig_message : None,
            message_type : MessageType::ConnectRequest(connect_request),
            message_id   : self.get_next_message_id(),
            authority    : Authority::ManagedNode
        };

        self.send_swarm_or_parallel(&message)
    }

    // ---- I Am connection identification --------------------------------------------------------

    fn handle_i_am(&mut self, endpoint: &Endpoint, serialised_message: Bytes)
        -> RoutingResult {
        match decode::<IAm>(&serialised_message) {
            Ok(i_am) => {
                let mut trigger_handle_churn = false;
                match i_am.public_id.is_relocated() {
                    // if it is relocated, we consider the connection for our routing table
                    true => {
                        // check we have a cache for his public id from the relocation procedure
                        match self.public_id_cache.get(&i_am.public_id.name()) {
                            Some(cached_public_id) => {
                                // check the full fob received corresponds, not just the names
                                if cached_public_id == &i_am.public_id {
                                    let peer_endpoints = vec![endpoint.clone()];
                                    let peer_node_info = NodeInfo::new(i_am.public_id.clone(), peer_endpoints,
                                        Some(endpoint.clone()));
                                    // FIXME: node info cloned for debug printout below
                                    let (added, _) = self.routing_table.add_node(peer_node_info.clone());
                                    // TODO: drop dropped node in connection_manager
                                    if !added {
                                        info!("RT (size : {:?}) refused connection on {:?} as {:?}
                                            from routing table.", self.routing_table.size(),
                                            endpoint, i_am.public_id.name());
                                        self.relay_map.remove_unknown_connection(endpoint);
                                        self.connection_manager.drop_node(endpoint.clone());
                                        return Err(RoutingError::RefusedFromRoutingTable);
                                    }
                                    info!("RT (size : {:?}) added connected node {:?} on {:?}",
                                        self.routing_table.size(), peer_node_info.fob.name(), endpoint);
                                    trigger_handle_churn = self.routing_table
                                        .address_in_our_close_group_range(&peer_node_info.fob.name());
                                } else {
                                    info!("I Am, relocated name {:?} conflicted with cached fob.",
                                        i_am.public_id.name());
                                    self.relay_map.remove_unknown_connection(endpoint);
                                    self.connection_manager.drop_node(endpoint.clone());
                                }
                            },
                            None => {
                                // if we are connecting to an existing group
              // FIXME: ConnectRequest had target name signed by us; so no state held on response
              // I Am by default just has a nonce; now we will accept everyone, but we can avoid state,
              // by repeating the Who Are You message, this time with the nonce as his name.
              // So we check if the doubly signed nonce is his name, if so, add him to RT;
              // if not do second WhoAreYou as above;
              // we can do 512 + 1 bit to flag and break an endless loop
                                match self.routing_table.check_node(&i_am.public_id.name()) {
                                    true => {
                                        let peer_endpoints = vec![endpoint.clone()];
                                        let peer_node_info = NodeInfo::new(i_am.public_id.clone(),
                                            peer_endpoints, Some(endpoint.clone()));
                                        // FIXME: node info cloned for debug printout below
                                        let (added, _) = self.routing_table.add_node(
                                            peer_node_info.clone());
                                        // TODO: drop dropped node in connection_manager
                                        if !added {
                                            info!("RT (size : {:?}) refused connection on {:?} as {:?}
                                                from routing table.", self.routing_table.size(),
                                                endpoint, i_am.public_id.name());
                                            self.relay_map.remove_unknown_connection(endpoint);
                                            self.connection_manager.drop_node(endpoint.clone());
                                            return Err(RoutingError::RefusedFromRoutingTable); }
                                        info!("RT (size : {:?}) added connected node {:?} on {:?}",
                                            self.routing_table.size(), peer_node_info.fob.name(), endpoint);
                                        trigger_handle_churn = self.routing_table
                                            .address_in_our_close_group_range(&peer_node_info.fob.name());
                                    },
                                    false => {
                                        info!("Dropping connection on {:?} as {:?} is relocated,
                                            but not cached, or marked in our RT.",
                                            endpoint, i_am.public_id.name());
                                        self.relay_map.remove_unknown_connection(endpoint);
                                        self.connection_manager.drop_node(endpoint.clone());
                                    }
                                };
                            }
                        }
                    },
                    // if it is not relocated, we consider the connection for our relay_map
                    false => {
                        // move endpoint based on identification
                        match i_am.address {
                            Address::Client(_public_key) => {
                                self.relay_map.add_client(i_am.public_id.clone(), endpoint.clone());
                                self.relay_map.remove_unknown_connection(endpoint);
                            },
                            _ => {}, // only accept identified as client in relay map.
                        }

                    }
                };
                if trigger_handle_churn {
                    info!("Handle CHURN new node {:?}", i_am.public_id.name());
                    let mut close_group : Vec<NameType> = self.routing_table
                            .our_close_group().iter()
                            .map(|node_info| node_info.fob.name())
                            .collect::<Vec<NameType>>();
                    close_group.insert(0, self.id.name().clone());
                    let churn_actions = self.mut_interface().handle_churn(close_group);
                    for action in churn_actions {
                        match action {
                            MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                            MethodCall::Get { name: x, data_request: y, } => self.get(x, y),
                            MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
                            MethodCall::Post { destination: x, content: y } => self.post(x, y),
                            MethodCall::Delete { name: x, data : y } => self.delete(x, y),
                            MethodCall::Forward { destination } =>
                                info!("IGNORED: on handle_churn MethodCall:Forward {} is not a Valid action", destination),
                            MethodCall::Reply { data: _data } =>
                                info!("IGNORED: on handle_churn MethodCall:Reply is not a Valid action")
                        };
                    }
                }
                Ok(())
            },
            Err(_) => Err(RoutingError::UnknownMessageType)
        }
    }

    fn send_i_am_msg(&mut self, endpoint: Endpoint) -> RoutingResult {
        let message = try!(encode(&IAm {
            address: types::Address::Node(self.id.name()),
            public_id : PublicId::new(&self.id)}));
        ignore(self.connection_manager.send(endpoint, message));
        Ok(())
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
        }

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
        // first check whether it is reflected from us to us (bypassing CRUST)
        if endpoint == &self.reflective_endpoint {
            return Some(ConnectionName::ReflectionOnToUs);
        }
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
        let our_authority = our_authority(&message, &self.routing_table);
        let from_authority = message.from_authority();
        let from = message.source_address();
        let to = message.destination_address();

        let source_group = match message.actual_source() {
            Address::Node(_) => {
                match message.from_authority() {
                    Authority::ClientManager(name) => name,
                    Authority::NaeManager(name)    => name,
                    Authority::NodeManager(name)   => name,
                    Authority::ManagedNode      => return Err(RoutingError::BadAuthority),
                    Authority::ManagedClient(_) => return Err(RoutingError::BadAuthority),
                    Authority::Client(_)        => return Err(RoutingError::BadAuthority),
                    Authority::Unknown          => return Err(RoutingError::BadAuthority),
                }
            },
            Address::Client(source) => {
                if !signed_message.verify_signature(&source) {
                    return Err(RoutingError::FailedSignature);
                }
                message.source.non_relayed_source()
            }
        };

        // Temporarily pretend that the sentinel passed, later implement
        // sentinel.
        let resolved = Event::PutDataRequest(message.orig_message.clone(), data.clone(),
                                             source_group,
                                             message.destination.non_relayed_destination(),
                                             message.authority.clone(), our_authority.clone(),
                                             message.message_id.clone());

        match self.mut_interface().handle_put(our_authority.clone(), from_authority, from, to,
                                              data.clone()) {
            Ok(method_calls) => {
                for method_call in method_calls {
                    match method_call {
                        MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                        MethodCall::Get { name: x, data_request: y, } => self.get(x, y),
                        MethodCall::Refresh { type_tag, from_group, payload }
                            => self.refresh(type_tag, from_group, payload),
                        MethodCall::Post { destination: x, content: y, } => self.post(x, y),
                        MethodCall::Delete { name: x, data: y } => self.delete(x, y),
                        MethodCall::Forward { destination } => {
                            let data = try!(resolved.get_data());
                            let msg = try!(resolved.create_forward(
                                MessageType::PutData(data), self.id.name(), destination,
                                self.get_next_message_id()));
                            ignore(self.send_swarm_or_parallel(&msg));
                        },
                        MethodCall::Reply { data } => {
                            let msg = try!(resolved.create_reply(MessageType::PutData(data)));
                            ignore(self.send_swarm_or_parallel(&msg));
                        }
                    }
                }
            },
            Err(InterfaceError::Abort) => {},
            Err(InterfaceError::Response(error)) => {
                let signed_error = ErrorReturn {
                    error: error,
                    orig_request: match resolved.get_orig_message() {
                        Some(message) => message,
                        None => return Err(RoutingError::FailedSignature)
                    }
                };
                let group_pub_keys = if our_authority.is_group() {
                    self.group_pub_keys()
                }
                else {
                    BTreeMap::new()
                };
                let msg = MessageType::PutDataResponse(signed_error, group_pub_keys);
                let msg = try!(resolved.create_reply(msg));
                ignore(self.send_swarm_or_parallel(&msg));
            }
        }
        Ok(())
    }

    fn handle_post(&mut self, signed_message: SignedMessage, message: RoutingMessage, data: Data)
            -> RoutingResult {
        let our_authority = our_authority(&message, &self.routing_table);
        let from_authority = message.from_authority();
        let from = message.source_address();
        let to = message.destination_address();

        match self.mut_interface().handle_post(our_authority.clone(), from_authority, from, to, data) {
            Ok(method_calls) => {
                for method_call in method_calls {
                    match method_call {
                        MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                        MethodCall::Get { name: x, data_request: y, } => self.get(x, y),
                        MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
                        MethodCall::Post { destination: x, content: y, } => self.post(x, y),
                        MethodCall::Delete { name: x, data : y } => self.delete(x, y),
                        MethodCall::Forward { destination } =>
                            ignore(self.forward(&signed_message, &message, destination)),
                        MethodCall::Reply { data } =>
                            ignore(self.send_reply(&message, our_authority.clone(), MessageType::Post(data))),
                    }
                }
            },
            Err(InterfaceError::Abort) => {},
            Err(InterfaceError::Response(error)) => {
                let signed_error = ErrorReturn {
                    error        : error,
                    orig_request : signed_message
                };

                let group_pub_keys = if our_authority.is_group() {
                    self.group_pub_keys()
                }
                else {
                    BTreeMap::new()
                };

                try!(self.send_reply(&message,
                                     our_authority.clone(),
                                     MessageType::PostResponse(signed_error,
                                                               group_pub_keys)));
            }
        }
        Ok(())
    }

    fn handle_node_put_data_response(&mut self, _signed_message: SignedMessage,
            message: RoutingMessage, response: ErrorReturn) -> RoutingResult {
        info!("Handle group PUT data response.");
        let our_authority = our_authority(&message, &self.routing_table);
        let from_authority = message.from_authority();
        let from = message.source.clone();
        let source = match message.source.actual_source() {
            Address::Node(name) => name,
            _ => return Err(RoutingError::BadAuthority),
        };

        let resolved = Event::PutDataResponse(message.orig_message.clone(), response.clone(),
                                              source,
                                              message.destination.non_relayed_destination(),
                                              message.authority.clone(), our_authority.clone(),
                                              message.message_id.clone());

        //let resolved = match self.put_response_sentinel.add_claim(
        //    SentinelPutResponse::new(message.clone(), response.clone(), our_authority.clone()),
        //    source, signed_message.signature().clone(),
        //    signed_message.encoded_body().clone(), quorum, quorum) {
        //        Some(result) =>  match  result {
        //            AddResult::RequestKeys(_) => {
        //                // Get Key Request
        //                return Ok(())
        //            },
        //            AddResult::Resolved(request, serialised_claim) => (request, serialised_claim)
        //        },
        //        None => return Ok(())
        //};

        for method_call in self.mut_interface().handle_put_response(from_authority, from,
                                                                    response.error.clone()) {
            match method_call {
                MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                MethodCall::Get { name: x, data_request: y, } => self.get(x, y),
                MethodCall::Refresh { type_tag, from_group, payload }
                    => self.refresh(type_tag, from_group, payload),
                MethodCall::Post { destination: x, content: y, } => self.post(x, y),
                MethodCall::Delete { name: x, data : y } => self.delete(x, y),
                MethodCall::Forward { destination } => {
                    let response = try!(resolved.get_response());
                    let message_type = MessageType::PutDataResponse(response,
                                                                    self.group_pub_keys());
                    let msg = try!(resolved.create_forward(message_type, self.id.name(), destination,
                                                           self.get_next_message_id()));
                    ignore(self.send_swarm_or_parallel(&msg));
                }
                MethodCall::Reply { data: _data } =>
                    info!("IGNORED: on handle_put_data_response MethodCall:Reply is not a Valid action")
            }
        }
        Ok(())
    }

    fn handle_client_put_data_response(&mut self, signed_message: SignedMessage,
            message: RoutingMessage, response: ErrorReturn) -> RoutingResult {
        info!("Handle client PUT data response.");
        let our_authority = our_authority(&message, &self.routing_table);
        let from_authority = message.from_authority();
        let from = message.source.clone();

        match from.actual_source() {
            Address::Client(public_key) => {
                if !signed_message.verify_signature(&public_key) {
                    return Err(RoutingError::FailedSignature);
                }
            },
            _ => { return Err(RoutingError::BadAuthority); }
        }

        for method_call in self.mut_interface().handle_put_response(from_authority, from, response.error.clone()) {
            match method_call {
                MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                MethodCall::Get { name: x, data_request: y, } => self.get(x, y),
                MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
                MethodCall::Post { destination: x, content: y, } => self.post(x, y),
                MethodCall::Delete { name: x, data : y } => self.delete(x, y),
                MethodCall::Forward { destination } => {
                    let message_id = self.get_next_message_id();
                    let message = RoutingMessage {
                        destination  : DestinationAddress::Direct(destination),
                        source       : SourceAddress::Direct(self.id.name()),
                        orig_message : None,
                        message_type : MessageType::PutDataResponse(response.clone(), BTreeMap::<NameType, sign::PublicKey>::new()),
                        message_id   : message_id,
                        authority    : our_authority.clone(),
                    };
                    ignore(self.forward(&try!(SignedMessage::new(&message, self.id.signing_private_key())), &message, destination));
                }
                MethodCall::Reply { data: _data } =>
                    info!("IGNORED: on handle_put_data_response MethodCall:Reply is not a Valid action")
            }
        }
        Ok(())
    }

    fn handle_post_response(&mut self, signed_message: SignedMessage,
                                       message: RoutingMessage,
                                       response: ErrorReturn) -> RoutingResult {
        info!("Handle POST response.");
        let from_authority = message.from_authority();
        let from = message.source.clone();

        for method_call in self.mut_interface().handle_post_response(from_authority, from, response.error.clone()) {
            match method_call {
                MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                MethodCall::Get { name: x, data_request: y, } => self.get(x, y),
                MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
                MethodCall::Post { destination: x, content: y, } => self.post(x, y),
                MethodCall::Delete { name: x, data : y } => self.delete(x, y),
                MethodCall::Forward { destination } =>
                    ignore(self.forward(&signed_message, &message, destination)),
                MethodCall::Reply { data: _data } =>
                    info!("IGNORED: on handle_put_data_response MethodCall:Reply is not a Valid action")
            }
        }
        Ok(())
    }

    fn handle_connect_request(&mut self,
                              connect_request: ConnectRequest,
                              message:         SignedMessage
                             ) -> RoutingResult {
        if !connect_request.requester_fob.is_relocated() {
            return Err(RoutingError::RejectedPublicId);
        }
        // first verify that the message is correctly self-signed
        if !message.verify_signature(&connect_request.requester_fob
            .signing_public_key()) {
            return Err(RoutingError::FailedSignature);
        }
        // if the PublicId claims to be relocated,
        // check whether we have a temporary record of this relocated Id,
        // which we would have stored after the sentinel group consensus
        // of the relocated Id. If the fobs match, add it to routing_table.
        match self.public_id_cache.get(&connect_request.requester_fob.name()) {
            Some(public_id) => {
                // check the full fob received corresponds, not just the names
                if public_id == &connect_request.requester_fob {
/* FIXME: we will add this node to the routing table on WhoAreYou
                    // Collect the local and external endpoints into a single vector to construct a NodeInfo
                    let mut peer_endpoints = connect_request.local_endpoints.clone();
                    peer_endpoints.extend(connect_request.external_endpoints.clone().into_iter());
                    let peer_node_info =
                        NodeInfo::new(connect_request.requester_fob.clone(), peer_endpoints, None);
                    // Try to add to the routing table.  If unsuccessful, no need to continue.
                    let (added, _) = self.routing_table.add_node(peer_node_info.clone());
                    if !added {
                        return Err(RoutingError::RefusedFromRoutingTable); }
                    info!("RT (size : {:?}) added {:?} ", self.routing_table.size(), peer_node_info.fob.name());
*/
                    // Try to connect to the peer.
                    self.connection_manager.connect(connect_request.local_endpoints.clone());
                    self.connection_manager.connect(connect_request.external_endpoints.clone());
                    self.connection_cache.entry(public_id.name())
                        .or_insert(SteadyTime::now());
                    // Send the response containing our details,
                    // and add the original signature as proof of the request
// FIXME: for TCP rendez-vous connect is not needed
/*                    let routing_msg = self.construct_connect_response_msg(&original_header, &body, &signature, &connect_request);
                    let serialised_message = try!(encode(&routing_msg));

                    // intercept if we can relay it directly
                    match (routing_msg.message_header.destination.dest.clone(),
                        routing_msg.message_header.destination.relay_to.clone()) {
                        (dest, Some(relay)) => {
                            // if we should directly respond to this message, do so
                            if dest == self.id.name()
                                && self.relay_map.contains_relay_for(&relay) {
                                info!("Sending ConnectResponse directly to relay {:?}", relay);
                                self.send_out_as_relay(&relay, serialised_message);
                                return Ok(());
                            }
                        },
                        _ => {}
                    };

                    self.send_swarm_or_parallel(&routing_msg.message_header.destination.dest,
                        &serialised_message);
*/
                }
            },
            None => {}
        };
        Ok(())
    }

    fn handle_refresh(&mut self, message: RoutingMessage, tag: u64, payload: Vec<u8>) -> RoutingResult {
        let group = match message.from_group() {
            Some(g) => g,
            None    => return Err(RoutingError::RefreshNotFromGroup),
        };

        let threshold = (self.routing_table.size() as f32) * 0.8; // 80% chosen arbitrary
        let opt_payloads = self.refresh_accumulator.add_message(threshold as usize,
                                                                tag,
                                                                message.non_relayed_source(),
                                                                group.clone(),
                                                                payload);
        opt_payloads.map(|payload| {
            self.mut_interface().handle_refresh(tag, group, payload);
        });
        Ok(())
    }

    fn handle_connect_response(&mut self, connect_response: ConnectResponse) -> RoutingResult {

        // Verify a connect request was initiated by us.
        let connect_request = try!(decode::<ConnectRequest>(&connect_response.serialised_connect_request));
        if connect_request.requester_id != self.id.name() ||
           !verify_detached(&connect_response.connect_request_signature,
                                  &connect_response.serialised_connect_request[..],
                                  &self.id.signing_public_key()) {
            return Err(RoutingError::Response(ResponseError::InvalidRequest));
        }
        // double check if fob is relocated;
        // this should be okay as we check this before sending out a connect_request
        if !connect_response.receiver_fob.is_relocated() {
            return Err(RoutingError::RejectedPublicId); }
        // Collect the local and external endpoints into a single vector to construct a NodeInfo
        let mut peer_endpoints = connect_response.receiver_local_endpoints.clone();
        peer_endpoints.extend(connect_response.receiver_external_endpoints.clone().into_iter());
  // info!("ConnectResponse from {:?}",  )
  // for peer in peer_endpoint {
  //     info!("")
  // }
        let peer_node_info =
            NodeInfo::new(connect_response.receiver_fob.clone(), peer_endpoints, None);

        // Try to add to the routing table.  If unsuccessful, no need to continue.
        let (added, _) = self.routing_table.add_node(peer_node_info.clone());
        if !added {
           return Err(RoutingError::RefusedFromRoutingTable); }
        info!("RT (size : {:?}) added {:?} on connect response", self.routing_table.size(),
            peer_node_info.fob.name());
        // Try to connect to the peer.
        self.connection_manager.connect(connect_response.receiver_local_endpoints.clone());
        self.connection_manager.connect(connect_response.receiver_external_endpoints.clone());
        Ok(())
    }

    /// On bootstrapping a node can temporarily publish its PublicId in the group.
    /// No handle_get_public_id is needed - this is handled by routing_node
    /// before the membrane instantiates.
    // TODO (Ben): check whether to accept id into group;
    // restrict on minimal similar number of leading bits.
    fn handle_put_public_id(&mut self, signed_message: SignedMessage, message: RoutingMessage,
        public_id: PublicId) -> RoutingResult {
        let our_authority = our_authority(&message, &self.routing_table);
        match (message.from_authority(), our_authority.clone(), public_id.is_relocated()) {
            (Authority::ManagedNode, Authority::NaeManager(_), false) => {
                let mut put_public_id_relocated = public_id.clone();

                let close_group =
                    self.routing_table.our_close_group().into_iter()
                    .map(|node_info| node_info.id())
                    .chain(Some(self.id.name().clone()).into_iter())
                    .collect::<Vec<NameType>>();

                let relocated_name = try!(utils::calculate_relocated_name(close_group,
                                                                          &public_id.name()));
                // assign_relocated_name
                put_public_id_relocated.assign_relocated_name(relocated_name.clone());

                info!("RELOCATED {:?} to {:?}", public_id.name(), relocated_name);
                let mut relocated_message = message.clone();
                relocated_message.message_type =
                    MessageType::PutPublicId(put_public_id_relocated);
                // Forward to relocated_name group, which will actually store the relocated public id
                try!(self.forward(&signed_message, &relocated_message, relocated_name));
                Ok(())
            },
            (Authority::NaeManager(_), Authority::NaeManager(_), true) => {
                // Note: The "if" check is workaround for absense of sentinel. This avoids redundant PutPublicIdResponse responses.
                if !self.public_id_cache.contains_key(&public_id.name()) {
                  self.public_id_cache.add(public_id.name(), public_id.clone());
                  info!("CACHED RELOCATED {:?}", public_id.name());
                  // Reply with PutPublicIdResponse to the reply_to address
                  match message.orig_message.clone() {
                      Some(original_signed_msg) => {
                          ignore(self.send_reply(&message, our_authority,
                              MessageType::PutPublicIdResponse(public_id, original_signed_msg)));
                      },
                      None => {
                          error!("Name Request: there should always be an original request message
                              present at reply. Dropping reply.");
                      }
                  }
                }
                Ok(())
            },
            _ => Err(RoutingError::BadAuthority)
        }
    }

    fn handle_find_group(&mut self, original_message: RoutingMessage) -> RoutingResult {
        let group = self.routing_table.our_close_group().into_iter()
                    .map(|x|x.fob)
                    // add ourselves
                    .chain(Some(PublicId::new(&self.id)).into_iter())
                    .collect::<Vec<_>>();

        let message = RoutingMessage {
            destination  : original_message.reply_destination(),
            source       : SourceAddress::Direct(self.id.name().clone()),
            orig_message : None,
            message_type : MessageType::FindGroupResponse(group),
            message_id   : original_message.message_id,
            authority    : Authority::Unknown,
        };

        self.send_swarm_or_parallel(&message)
    }

    fn handle_find_group_response(&mut self,
                                  find_group_response: Vec<PublicId>,
                                  refresh_our_own_group: bool) -> RoutingResult {
        for peer in find_group_response {
            self.refresh_routing_table(&peer.name());
        }
        if refresh_our_own_group {
            let our_name = self.id.name().clone();
            if !self.connection_cache.contains_key(&our_name) {
                let find_group_msg = self.construct_find_group_msg();
                ignore(self.send_swarm_or_parallel(&find_group_msg));
                self.connection_cache.entry(our_name)
                    .or_insert(SteadyTime::now());
            }
        }
        Ok(())
    }

    fn handle_get_data(&mut self, orig_message: SignedMessage,
                                  message: RoutingMessage,
                                  data_request: DataRequest) -> RoutingResult {
        let our_authority  = our_authority(&message, &self.routing_table);
        let from_authority = message.from_authority();
        let from           = message.source_address();

        match self.mut_interface().handle_get(
                data_request.clone(), our_authority.clone(), from_authority, from) {
            Ok(method_calls) => {
                for method_call in method_calls {
                    match method_call {
                        MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                        MethodCall::Get { name: x, data_request: y, } => self.get(x, y),
                        MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
                        MethodCall::Post { destination: x, content: y, } => self.post(x, y),
                        MethodCall::Delete { name: x, data : y } => self.delete(x, y),
                        MethodCall::Forward { destination } =>
                            ignore(self.forward(&orig_message, &message, destination)),
                        MethodCall::Reply { data } => {

                            let group_pub_keys = if our_authority.is_group() {
                                self.group_pub_keys()
                            }
                            else {
                                BTreeMap::new()
                            };

                            let response = GetDataResponse {
                                data           : data,
                                orig_request   : orig_message.clone(),
                                group_pub_keys : group_pub_keys
                            };

                            ignore(self.send_reply(&message, our_authority.clone(), MessageType::GetDataResponse(response)))
                        },
                    }
                }
            },
            Err(..) => {;},
        }
        Ok(())
    }

    fn forward(&self, orig_message: &SignedMessage, routing_message: &RoutingMessage,
            destination: NameType) -> RoutingResult {
        let original_routing_message =
            try!(orig_message.get_routing_message());
        let our_authority = our_authority(&original_routing_message, &self.routing_table);
        let message = routing_message.create_forward(self.id.name().clone(),
                                                     our_authority,
                                                     destination,
                                                     orig_message.clone());
        ignore(self.send_swarm_or_parallel(&message));
        Ok(())
    }

    fn send_reply(&mut self,
                  routing_message : &RoutingMessage,
                  our_authority   : Authority,
                  msg             : MessageType) -> RoutingResult {
        let mut message = try!(routing_message.create_reply(&self.id.name(), &our_authority));

        message.message_type = msg;
        message.authority    = our_authority;

        self.send_swarm_or_parallel_or_relay(&message)
    }

    pub fn get_quorum(&self) -> usize {
        let mut quorum = types::QUORUM_SIZE;
        if self.routing_table.size() < types::QUORUM_SIZE {
            quorum = self.routing_table.size();
        }
        quorum
    }

    fn handle_node_get_data_response(&mut self, _signed_message : SignedMessage,
            message: RoutingMessage, response: GetDataResponse) -> RoutingResult {
        let our_authority = our_authority(&message, &self.routing_table);
        let from = message.source.non_relayed_source();

        let _ = self.get_quorum();

        let source = match message.source.actual_source() {
            Address::Node(name) => name,
            _ => return Err(RoutingError::BadAuthority),
        };

        let resolved = Event::GetDataResponse(message.orig_message.clone(), response.clone(),
                                              source,
                                              message.destination.non_relayed_destination(),
                                              message.authority.clone(), our_authority.clone(),
                                              message.message_id.clone());

        //let resolved = match self.get_data_response_sentinel.add_claim(
        //    SentinelGetDataResponse::new(message.clone(), response.clone(), our_authority.clone()),
        //    source, signed_message.signature().clone(),
        //    signed_message.encoded_body().clone(), quorum, quorum) {
        //        Some(result) =>  match  result {
        //            AddResult::RequestKeys(_) => {
        //                // Get Key Request
        //                return Ok(())
        //            },
        //            AddResult::Resolved(request, serialised_claim) => (request, serialised_claim)
        //        },
        //        None => return Ok(())
        //};
        let data_response = try!(resolved.get_data_response());
        for method_call in self.mut_interface().handle_get_response(from,
                                                                    data_response.data.clone()) {
            match method_call {
                MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                MethodCall::Get { name: x, data_request: y, } => self.get(x, y),
                MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
                MethodCall::Post { destination: x, content: y, } => self.post(x, y),
                MethodCall::Delete { name: x, data : y } => self.delete(x, y),
                MethodCall::Forward { destination } => {
                    let message_type = MessageType::GetDataResponse(data_response.clone());
                    let msg = try!(resolved.create_forward(message_type, self.id.name(), destination,
                                                           self.get_next_message_id()));
                    ignore(self.send_swarm_or_parallel(&msg));
                },
                MethodCall::Reply { data: _data } =>
                    info!("IGNORED: on handle_get_data_response MethodCall:Reply is not a Valid action")
            }
        }
        Ok(())
    }

    fn handle_client_get_data_response(&mut self, _orig_message : SignedMessage,
            message: RoutingMessage, response: GetDataResponse) -> RoutingResult {
        if !response.verify_request_came_from(&self.id.signing_public_key()) {
            return Err(RoutingError::FailedSignature);
        }

        let our_authority = our_authority(&message, &self.routing_table);
        let from = message.source.non_relayed_source();

        for method_call in self.mut_interface().handle_get_response(from, response.data.clone()) {
            match method_call {
                MethodCall::Put { destination: x, content: y, } => self.put(x, y),
                MethodCall::Get { name: x, data_request: y, } => self.get(x, y),
                MethodCall::Refresh { type_tag, from_group, payload } => self.refresh(type_tag, from_group, payload),
                MethodCall::Post { destination: x, content: y, } => self.post(x, y),
                MethodCall::Delete { name: x, data : y } => self.delete(x, y),
                MethodCall::Forward { destination } => {
                    let message_id = self.get_next_message_id();
                    let message = RoutingMessage {
                        destination  : DestinationAddress::Direct(destination),
                        source       : SourceAddress::Direct(self.id.name()),
                        orig_message : None,
                        message_type : MessageType::GetDataResponse(response.clone()),
                        message_id   : message_id,
                        authority    : our_authority.clone(),
                    };
                    ignore(self.forward(&try!(SignedMessage::new(&message, self.id.signing_private_key())) , &message, destination));
                },
                MethodCall::Reply { data: _data } =>
                    info!("IGNORED: on handle_get_data_response MethodCall:Reply is not a Valid action")
            }
        }
        Ok(())
    }

    fn group_pub_keys(&self) -> BTreeMap<NameType, sign::PublicKey> {
        let name_and_key_from_info = |node_info : NodeInfo| {
            (node_info.fob.name(), node_info.fob.signing_public_key())
        };

        let ourselves = (self.id.name(), self.id.signing_public_key());

        self.routing_table.our_close_group()
                          .into_iter()
                          .map(name_and_key_from_info)
                          .chain(Some(ourselves).into_iter())
                          .collect()
    }
}
