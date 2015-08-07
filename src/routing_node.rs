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
use routing_core::{RoutingCore, ConnectionName};
use id::Id;
use public_id::PublicId;
use who_are_you::IAm;
use types;
use types::{MessageId, Bytes, Address};
use utils::{encode, decode};
use data::{Data, DataRequest};
use authority::{Authority, our_authority};

use messages::{RoutingMessage,
               SignedMessage, SignedToken,
               ConnectRequest,
               ConnectResponse,
               ErrorReturn,
               GetDataResponse,
               Content,
               ExternalRequest, ExternalResponse,
               InternalRequest, InternalResponse };

use error::{RoutingError, ResponseError};
use refresh_accumulator::RefreshAccumulator;
use message_filter::MessageFilter;


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
    filter              : MessageFilter<types::FilterType>,
    core                : RoutingCore,
    // public_id_cache     : LruCache<NameType, PublicId>,
    connection_cache    : BTreeMap<NameType, SteadyTime>,
    // refresh_accumulator : RefreshAccumulator,
}

impl RoutingNode {
    pub fn new(action_sender   : mpsc::Sender<Action>,
               action_receiver : mpsc::Receiver<Action>,
               event_sender    : mpsc::Sender<Event> ) -> Result<RoutingNode, RoutingError> {

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
            filter              : MessageFilter::with_expiry_duration(Duration::minutes(20)),
            core                : RoutingCore::new(),
            connection_cache    : BTreeMap::new(),
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

    fn request_network_name(&mut self) -> Result<NameType, RoutingError>  {
        unimplemented!()
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

        let message = message_wrap.get_routing_message().clone();

        // filter check
        if self.filter.check(&message.get_filter()) {
            // should just return quietly
            debug!("FILTER BLOCKED message {:?} from {:?} to {:?}", message.content,
                message.source(), message.destination());
            return Err(RoutingError::FilterCheckFailed);
        }
        debug!("message {:?} from {:?} to {:?}", message.content,
            message.source(), message.destination());
        // add to filter
        self.filter.add(message.get_filter());

        // Forward
        ignore(self.send(message_wrap.clone()));

        let address_in_close_group_range =
            self.address_in_close_group_range(&message.destination());

        // Handle FindGroupResponse
        if let Content::InternalResponse(InternalResponse::FindGroup(ref vec_of_public_ids), _)
                = message.content {
            ignore(self.handle_find_group_response(
                        vec_of_public_ids.clone(),
                        address_in_close_group_range.clone()));
        }

        if !address_in_close_group_range {
            return Ok(());
        }

        // Drop message before Sentinel check if it is a direct message type (Connect, ConnectResponse)
        // and this node is in the group but the message destination is another group member node.
        match message.content {
            Content::InternalRequest(InternalRequest::Connect(_)) |
            Content::InternalResponse(InternalResponse::Connect(_), _) => {
                match message.destination() {
                    Authority::ClientManager(_)  => return Ok(()), // TODO: Should be error
                    Authority::NaeManager(_)     => return Ok(()), // TODO: Should be error
                    Authority::NodeManager(_)    => return Ok(()), // TODO: Should be error
                    Authority::ManagedNode(name) => if name != self.core.id().name() {
                        return Ok(())
                    },
                    Authority::Client(_, _)      => return Ok(()), // TODO: Should be error
                }
            }
            _ => (),
        }
        //
        // pre-sentinel message handling

        if self.our_authority(&message)
            .map(|our_auth| message.to_authority == our_auth).unwrap_or(false) {
            return Err(RoutingError::BadAuthority);
        }

        match message.content {
            //MessageType::GetKey => self.handle_get_key(header, body),
            //MessageType::GetGroupKey => self.handle_get_group_key(header, body),
            //Content::InternalRequest(InternalRequest::Connect(request)) =>
            //    self.handle_connect_request(request, message_wrap),
            //_ => {
            //    // Sentinel check

            //    // TODO:
            //    // switch message type
            //    //match message.message_type {
            //    //    MessageType::ConnectResponse(response) =>
            //    //        self.handle_connect_response(response),
            //    //    MessageType::FindGroup =>
            //    //         self.handle_find_group(message),
            //    //    MessageType::PutPublicId(ref id) =>
            //    //        self.handle_put_public_id(message_wrap, message.clone(), id.clone()),
            //    //    MessageType::Refresh(ref tag, ref data) =>
            //    //        self.handle_refresh(message.clone(), tag.clone(), data.clone()),
            //    //    _ => {
            //    //        Err(RoutingError::UnknownMessageType)
            //    //    }
            //    //}
            //    Ok(())
            //}
            Content::InternalRequest(request) => {
            }
            Content::InternalResponse(response, serialised_request) => {
            }
            Content::ExternalRequest(request) => {
                self.send_to_user(Event::Request {
                    request        : request,
                    our_authority  : message.to_authority,
                    from_authority : message.from_authority,
                    response_token : try!(message_wrap.as_token()),
                })
            }
            Content::ExternalResponse(response) => {
                try!(self.handle_external_response(response,
                                                   message.to_authority,
                                                   message.from_authority))
            }
        }
        Ok(())
    }

    fn handle_external_response(&self, response       : ExternalResponse,
                                       to_authority   : Authority,
                                       from_authority : Authority) -> RoutingResult {

        let orig_request_msg = try!(response.get_orig_request());

        // Have we sent the request?
        if *orig_request_msg.claimant() != *self.name() {
            return Err(RoutingError::UnknownMessageType)
        }

        if !orig_request_msg.verify_signature(self.public_sign_key()) {
            return Err(RoutingError::FailedSignature)
        }

        let orig_request = match orig_request_msg.get_routing_message().content {
            Content::ExternalRequest(ref request) => request.clone(),
            _ => return Err(RoutingError::UnknownMessageType)
        };

        self.send_to_user(Event::Response {
            response       : response,
            our_authority  : to_authority,
            from_authority : from_authority,
            orig_request   : orig_request,
        });

        Ok(())
    }

    /// Scan all passing messages for the existance of nodes in the address space.
    /// If a node is detected with a name that would improve our routing table,
    /// then try to connect.  During a delay of 5 seconds, we collapse
    /// all re-occurances of this name, and block a new connect request
    /// TODO: The behaviour of this function has been adapted to serve as a filter
    /// to cover for the lack of a filter on FindGroupResponse
    fn refresh_routing_table(&mut self, from_node : NameType) {
      // disable refresh when scanning on small routing_table size
      let time_now = SteadyTime::now();
      if !self.connection_cache.contains_key(&from_node) {
          if self.core.check_node(&ConnectionName::Routing(from_node)) {
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

    // ----- Send Functions -----------------------------------------------------------------------

    fn send_to_user(&self, _event: Event) {
        unimplemented!()
    }

    fn name(&self) -> &Address {
        unimplemented!()
    }

    fn our_authority(&self, message: &RoutingMessage) -> Option<Authority> {
        unimplemented!()
    }

    fn public_sign_key(&self) -> &sign::PublicKey {
        unimplemented!()
    }

    /// Send queries the core for a vector of endpoints over which the signed message
    /// needs to be sent out.
    fn send(&self, signed_message : SignedMessage) -> RoutingResult {
        unimplemented!()
    }

    fn send_connect_request_msg(&mut self, peer_id: &NameType) -> RoutingResult {
        unimplemented!()
        // // FIXME: We're sending all accepting connections as local since we don't differentiate
        // // between local and external yet.
        // let connect_request = ConnectRequest {
        //     local_endpoints: self.accepting_on.clone(),
        //     external_endpoints: vec![],
        //     requester_id: self.core.id().name(),
        //     receiver_id: peer_id.clone(),
        //     requester_fob: PublicId::new(&self.core.id()),
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
        unimplemented!()
        // TODO (ben 5/08/2015) needs to moved to core
        // match self.bootstrap {
        //     Some((ref endpoint, name)) => {
        //         if self.routing_table.size() > 0 {
        //             info!("Dropped bootstrap on {:?} {:?}", endpoint, name);
        //             self.connection_manager.drop_node(endpoint.clone());
        //         }
        //     },
        //     None => {}
        // };
        // self.bootstrap = None;
    }

    fn address_in_close_group_range(&self, destination_auth: &Authority) -> bool {
        unimplemented!()
        // TODO (ben 05/08/2015) again, this needs to rely on core
        // let address = match *destination_auth {
        //     Authority::ClientManager(name) => name,
        //     Authority::NaeManager(name)    => name,
        //     Authority::NodeManager(name)   => name,
        //     Authority::ManagedNode(_)      => return false,
        //     Authority::Client(_, _)        => return false,
        // };
        //
        // if self.routing_table.size() < types::QUORUM_SIZE  ||
        //    *address == self.core.id().name().clone()
        // {
        //     return true;
        // }
        //
        // match self.routing_table.our_close_group().last() {
        //     Some(furthest_close_node) => {
        //         closer_to_target_or_equal(&address, &furthest_close_node.id(), &self.core.id().name())
        //     },
        //     None => false  // ...should never reach here
        // }
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
