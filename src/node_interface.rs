// Copyright 2015 MaidSafe.net limited.
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

use sendable::Sendable;
use name_type::NameType;
use types::DestinationAddress;
use authority::Authority;
use types::MessageAction;
use error::{InterfaceError, ResponseError};

/// MethodCall denotes a specific request to be carried out by routing.
pub enum MethodCall {
    /// request for no action
    None,
    /// request to have `destination` to handle put for the `content`
    Put { destination: NameType, content: Box<Sendable>, },
    /// request to retreive data with specified type and name from network
    Get { type_id: u64, name: NameType, },
    /// request to post
    Post,
    /// request to refresh
    Refresh { content: Box<Sendable>, },
    RefreshNew { type_tag: u64, from_group: NameType, payload: Vec<u8>, },
    /// request to send on the request to destination for further handling
    SendOn { destination: NameType },
}

#[deny(missing_docs)]
/// The Interface trait introduces the methods expected to be implemented by the user
/// of RoutingNode
pub trait Interface : Sync + Send {
    /// depending on our_authority and from_authority, the public key or address of the node
    /// potentially storing public key with specified name is returned, on success.
    /// failure to provide public key or an address is indicated as an InterfaceError.
    fn handle_get_key(&mut self,
                      type_id: u64,
                      name: NameType,
                      our_authority: Authority,
                      from_authority: Authority,
                      from_address: NameType) -> Result<MessageAction, InterfaceError>;

    /// depending on our_authority and from_authority, data or address of the node
    /// potentially storing data with specified name and type_id is returned, on success.
    /// failure to provide data or an address is indicated as an InterfaceError.
    fn handle_get(&mut self,
                  type_id: u64,
                  name: NameType,
                  our_authority: Authority,
                  from_authority: Authority,
                  from_address: NameType) -> Result<MessageAction, InterfaceError>;

    /// depending on our_authority and from_authority, data is stored on current node or an address
    /// (with different authority) for further handling of the request is provided.
    /// failure is indicated as an InterfaceError.
    fn handle_put(&mut self,
                  our_authority: Authority,
                  from_authority: Authority,
                  from_address: NameType,
                  dest_address: DestinationAddress,
                  data: Vec<u8>) -> Result<MessageAction, InterfaceError>;

    /// depending on our_authority and from_authority, post request is handled by current node or
    /// an address for further handling of the request is provided. Failure is indicated as an
    /// InterfaceError.
    fn handle_post(&mut self,
                   our_authority: Authority,
                   from_authority: Authority,
                   from_address: NameType,
                   name : NameType,
                   data: Vec<u8>) -> Result<MessageAction, InterfaceError>;

    /// handles the response to a put request. Depending on ResponseError, performing an action of
    /// type MethodCall is requested.
    fn handle_get_response(&mut self,
                           from_address: NameType,
                           response: Result<Vec<u8>, ResponseError>) -> MethodCall;

    /// handles the response to a put request. Depending on ResponseError, performing an action of
    /// type MethodCall is requested.
    fn handle_put_response(&mut self,
                           from_authority: Authority,
                           from_address: NameType,
                           response: Result<Vec<u8>, ResponseError>) -> MethodCall;

    /// handles the response to a post request. Depending on ResponseError, performing an action of
    /// type MethodCall is requested.
    fn handle_post_response(&mut self,
                            from_authority: Authority,
                            from_address: NameType,
                            response: Result<Vec<u8>, ResponseError>);

    /// handles the actions to be carried out in the event of a churn. The function provides a list
    /// of actions (of type MethodCall) to be carried out in order to update relevant nodes.
    fn handle_churn(&mut self, close_group: Vec<NameType>) -> Vec<MethodCall>;

    /// attempts to potentially retrieve data from cache.
    fn handle_cache_get(&mut self,
                        type_id: u64,
                        name: NameType,
                        from_authority: Authority,
                        from_address: NameType) -> Result<MessageAction, InterfaceError>;

    /// attempts to store data in cache. The type of data and/or from_authority indicates
    /// if store in cache is required.
    fn handle_cache_put(&mut self,
                        from_authority: Authority,
                        from_address: NameType,
                        data: Vec<u8>) -> Result<MessageAction, InterfaceError>;
}

pub trait CreatePersonas<F : Interface> : Sync + Send  {
    fn create_personas(&mut self) -> F;

}
