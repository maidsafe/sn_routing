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

use sodiumoxide;
use std::sync::mpsc;
use std::thread::spawn;

use id::Id;
use action::Action;
use event::Event;
use messages::SignedToken;
use routing_node::RoutingNode;
use NameType;
use data::{Data, DataRequest};
use types::{Bytes, CacheOptions};
use error::{RoutingError, ResponseError};
use authority::Authority;
use sodiumoxide::crypto;
use messages::{ExternalRequest, ExternalResponse, InternalRequest, Content};

type RoutingResult = Result<(), RoutingError>;

/// Routing provides an actionable interface to RoutingNode.
/// On constructing a new Routing object a RoutingNode will also be started.
/// Routing objects are clonable for multithreading, or a Routing object can be
/// cloned with a new set of keys while preserving a single RoutingNode.
#[derive(Clone)]
pub struct Routing {
    action_sender: mpsc::Sender<Action>,
}

impl Routing {
    /// Starts a new RoutingIdentity, which will also start a new RoutingNode.
    /// The RoutingNode will attempt to achieve full routing node status.
    /// The intial Routing object will have newly generated keys
    pub fn new(event_sender: mpsc::Sender<Event>) -> Routing {
        sodiumoxide::init();  // enable shared global (i.e. safe to multithread now)

        let (action_sender, action_receiver) = mpsc::channel::<Action>();

        // start the handler for routing without a restriction to become a full node
        let mut routing_node = RoutingNode::new(action_sender.clone(),
                                                action_receiver,
                                                event_sender,
                                                false,
                                                None);

        spawn(move || {
                       debug!("started routing run()");
                       routing_node.run();
                       debug!("Routing node terminated running.");
                   });

        Routing { action_sender: action_sender }
    }

    /// Send a Get message with a DataRequest to an Authority, signed with given keys.
    pub fn get_request(&self, our_authority: Authority, location: Authority,
        data_request: DataRequest) {
        let _ = self.action_sender.send(Action::SendContent(
                our_authority, location,
                Content::ExternalRequest(ExternalRequest::Get(data_request, 0u8))));
    }

    /// Add something to the network
    pub fn put_request(&self, our_authority: Authority, location: Authority, data: Data) {
        let _ = self.action_sender.send(Action::SendContent(
                our_authority, location,
                Content::ExternalRequest(ExternalRequest::Put(data))));
    }

    /// Change something already on the network
    pub fn post_request(&self, our_authority: Authority, location: Authority, data: Data) {
        let _ = self.action_sender.send(Action::SendContent(
                our_authority, location,
                Content::ExternalRequest(ExternalRequest::Post(data))));
    }

    /// Remove something from the network
    pub fn delete_request(&self, our_authority: Authority, location: Authority, data: Data) {
        let _ = self.action_sender.send(Action::SendContent(
                our_authority, location,
                Content::ExternalRequest(ExternalRequest::Delete(data))));
    }
    /// Respond to a get_request (no error can be sent)
    /// If we received the request from a group, we'll not get the signed_token.
    pub fn get_response(&self,
                        our_authority: Authority,
                        location: Authority,
                        data: Data,
                        data_request: DataRequest,
                        signed_token: Option<SignedToken>) {
        let _ = self.action_sender.send(Action::SendContent(
                our_authority, location,
                Content::ExternalResponse(
                    ExternalResponse::Get(data, data_request, signed_token))));
    }
    /// response error to a put request
    pub fn put_response(&self,
                        our_authority: Authority,
                        location: Authority,
                        response_error: ResponseError,
                        signed_token: Option<SignedToken>) {
        if response_error == ::error::ResponseError::Abort { return; };
        let _ = self.action_sender.send(Action::SendContent(
                our_authority, location,
                Content::ExternalResponse(
                    ExternalResponse::Put(response_error, signed_token))));
    }
    /// Response error to a post request
    pub fn post_response(&self,
                        our_authority: Authority,
                         location: Authority,
                         response_error: ResponseError,
                         signed_token: Option<SignedToken>) {
        if response_error == ::error::ResponseError::Abort { return; };
        let _ = self.action_sender.send(Action::SendContent(
                our_authority, location,
                Content::ExternalResponse(
                    ExternalResponse::Post(response_error, signed_token))));
    }
    /// response error to a delete respons
    pub fn delete_response(&self,
                           our_authority: Authority,
                           location: Authority,
                           response_error: ResponseError,
                           signed_token: Option<SignedToken>) {
        if response_error == ::error::ResponseError::Abort { return; };
        let _ = self.action_sender.send(Action::SendContent(
                our_authority, location,
                Content::ExternalResponse(ExternalResponse::Delete(response_error,
                    signed_token))));
    }

    /// Refresh the content in the close group nodes of group address content::name.
    /// This method needs to be called when churn is triggered.
    /// all the group members need to call this, otherwise it will not be resolved as a valid
    /// content. If the authority provided (our_authority) is not a group, the request for refresh will be dropped.
    pub fn refresh_request(&self, type_tag: u64, our_authority: Authority, content: Bytes) {
        if !our_authority.is_group() {
            error!("refresh request (type_tag {:?}) can only be made as a group authority: {:?}",
                type_tag, our_authority);
            return; };
        let _ = self.action_sender.send(Action::SendContent(our_authority.clone(), our_authority,
            Content::InternalRequest(InternalRequest::Refresh(type_tag, content))));
    }

    /// Dynamically enable/disable caching for Data types.
    pub fn set_cache_options(&self, cache_options: CacheOptions) {
        let _ = self.action_sender.send(Action::SetCacheOptions(cache_options));

    }

    /// Signal to RoutingNode that it needs to refuse new messages and handle all outstanding
    /// messages.  After handling all messages it will send an Event::Terminated to the user.
    pub fn stop(&mut self) {
        let _ = self.action_sender.send(Action::Terminate);
    }
}
