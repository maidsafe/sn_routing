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
use std::sync::mpsc::{Sender, Receiver, channel};

use action::Action;
use event::Event;
use xor_name::XorName;
use routing_node::RoutingNode;
use error::{RoutingError, InterfaceError};
use authority::Authority;
use messages::{RoutingMessage, RequestMessage, ResponseMessage, RequestContent, ResponseContent};

type RoutingResult = Result<(), RoutingError>;

/// Routing provides an actionable interface to RoutingNode.
/// On constructing a new Routing object a RoutingNode will also be started.
/// Routing objects are clonable for multithreading, or a Routing object can be
/// cloned with a new set of keys while preserving a single RoutingNode.
pub struct Routing {
    interface_result_tx: Sender<Result<(), InterfaceError>>,
    interface_result_rx: Receiver<Result<(), InterfaceError>>,
    action_sender: ::types::RoutingActionSender,
    _raii_joiner: ::maidsafe_utilities::thread::RaiiThreadJoiner,
}

impl Routing {
    /// Starts a new RoutingIdentity, which will also start a new RoutingNode.
    /// The RoutingNode will attempt to achieve full routing node status.
    /// The intial Routing object will have newly generated keys
    pub fn new(event_sender: Sender<Event>) -> Result<Routing, RoutingError> {
        sodiumoxide::init();  // enable shared global (i.e. safe to multithread now)

        // start the handler for routing without a restriction to become a full node
        let (action_sender, raii_joiner) = try!(RoutingNode::new(event_sender, false, None));

        let (tx, rx) = channel();

        Ok(Routing {
            interface_result_tx: tx,
            interface_result_rx: rx,
            action_sender: action_sender,
            _raii_joiner: raii_joiner,
        })
    }

    /// Send a Get message with a DataRequest to an Authority, signed with given keys.
    pub fn send_get_request(&self,
                            src: Authority,
                            dst: Authority,
                            content: RequestContent)
                            -> Result<(), InterfaceError> {
        let routing_msg = RoutingMessage::Request(RequestMessage {
            src: src,
            dst: dst,
            content: content,
        });
        self.send_action(routing_msg)
    }

    /// Add something to the network
    pub fn send_put_request(&self,
                            src: Authority,
                            dst: Authority,
                            content: RequestContent)
                            -> Result<(), InterfaceError> {
        let routing_msg = RoutingMessage::Request(RequestMessage {
            src: src,
            dst: dst,
            content: content,
        });
        self.send_action(routing_msg)
    }

    /// Change something already on the network
    pub fn send_post_request(&self,
                             src: Authority,
                             dst: Authority,
                             content: RequestContent)
                             -> Result<(), InterfaceError> {
        let routing_msg = RoutingMessage::Request(RequestMessage {
            src: src,
            dst: dst,
            content: content,
        });
        self.send_action(routing_msg)
    }

    /// Remove something from the network
    pub fn send_delete_request(&self,
                               src: Authority,
                               dst: Authority,
                               content: RequestContent)
                               -> Result<(), InterfaceError> {
        let routing_msg = RoutingMessage::Request(RequestMessage {
            src: src,
            dst: dst,
            content: content,
        });
        self.send_action(routing_msg)
    }

    /// Respond to a get_request (no error can be sent)
    /// If we received the request from a group, we'll not get the signed_request.
    pub fn send_get_response(&self,
                             src: Authority,
                             dst: Authority,
                             content: ResponseContent)
                             -> Result<(), InterfaceError> {
        let routing_msg = RoutingMessage::Response(ResponseMessage {
            src: src,
            dst: dst,
            content: content,
        });
        self.send_action(routing_msg)
    }

    /// response error to a put request
    pub fn send_put_response(&self,
                             src: Authority,
                             dst: Authority,
                             content: ResponseContent)
                             -> Result<(), InterfaceError> {
        let routing_msg = RoutingMessage::Response(ResponseMessage {
            src: src,
            dst: dst,
            content: content,
        });
        self.send_action(routing_msg)
    }

    /// Response error to a post request
    pub fn send_post_response(&self,
                              src: Authority,
                              dst: Authority,
                              content: ResponseContent)
                              -> Result<(), InterfaceError> {
        let routing_msg = RoutingMessage::Response(ResponseMessage {
            src: src,
            dst: dst,
            content: content,
        });
        self.send_action(routing_msg)
    }

    /// response error to a delete respons
    pub fn send_delete_response(&self,
                                src: Authority,
                                dst: Authority,
                                content: ResponseContent)
                                -> Result<(), InterfaceError> {
        let routing_msg = RoutingMessage::Response(ResponseMessage {
            src: src,
            dst: dst,
            content: content,
        });
        self.send_action(routing_msg)
    }

    /// Refresh the content in the close group nodes of group address content::name.
    /// This method needs to be called when churn is triggered.
    /// all the group members need to call this, otherwise it will not be resolved as a valid
    /// content. If the authority provided (src) is not a group, the request for refresh will be dropped.
    pub fn send_refresh_request(&self,
                                _type_tag: u64,
                                _src: Authority,
                                _content: Vec<u8>,
                                _cause: XorName)
                                -> Result<(), InterfaceError> {
        unimplemented!()
        // if !src.is_group() {
        // error!("refresh request (type_tag {:?}) can only be made as a group authority: {:?}",
        // type_tag,
        // src);
        // return;
        // };
        // let _ =
        // self.action_sender
        // .send(Action::SendContent(src.clone(),
        // src,
        // Content::InternalRequest(InternalRequest::Refresh {
        // type_tag: type_tag,
        // message: content,
        // cause: cause,
        // })));
    }

    // TODO(Spandan) Ask vaults if this can be removed as Routing is now made to implement drop
    // trait and hence is RAII friendly
    /// Signal to RoutingNode that it needs to refuse new messages and handle all outstanding
    /// messages.  After handling all messages it will send an Event::Terminated to the user.
    pub fn stop(&self) {
        let _ = self.action_sender.send(Action::Terminate);
    }

    fn send_action(&self, routing_msg: RoutingMessage) -> Result<(), InterfaceError> {
        try!(self.action_sender.send(Action::NodeSendMessage {
            content: routing_msg,
            result_tx: self.interface_result_tx.clone(),
        }));

        try!(self.interface_result_rx.recv())
    }
}

impl Drop for Routing {
    fn drop(&mut self) {
        if let Err(err) = self.action_sender.send(Action::Terminate) {
            error!("Error {:?} sending event RoutingNode", err);
        }
    }
}

// #[cfg(test)]
// mod test {

// pub struct RoutingNetwork;

// impl RoutingNetwork {

//         fn new(size: u32) -> RoutingNetwork {
//             ::utils::initialise_logger(true);


//             let node = || { let _ =
//                 ::std::thread::spawn(move || ::test_utils::node::Node::new().run());
//             };
//             for i in 0..size { node(); ::std::thread::sleep_ms(1000 + i * 1000); }
//             ::std::thread::sleep_ms(size * 1000);

//             RoutingNetwork
//         }
//     }

//     fn calculate_key_name(key: &::std::string::String) -> XorName {
//         XorName::new(::sodiumoxide::crypto::hash::sha512::hash(key.as_bytes()).0)
//     }

//     #[test]
//     fn unit_client_put_get() {
//         // let _ = RoutingNetwork::new(10u32);
//         debug!("Starting client");
//         let mut client = ::test_utils::client::Client::new();
//         ::std::thread::sleep_ms(2000);

//         let key = ::std::string::String::from("key");
//         let value = ::std::string::String::from("value");
//         let name = calculate_key_name(&key.clone());
//         let data = unwrap_result!(::utils::encode(&(key, value)));
//         let data = ::data::Data::PlainData(::plain_data::PlainData::new(name.clone(), data));

//         debug!("Putting data {:?}", data);
//         client.put(data.clone());
//         ::std::thread::sleep_ms(5000);

//         let recovered_data = match client.get(::data::DataRequest::PlainData(name)) {
//             Some(data) => data,
//             None => panic!("Failed to recover stored data: {}.", name),
//         };

//         debug!("Recovered data {:?}", recovered_data);
//         assert_eq!(recovered_data, data);
//     }
// }
