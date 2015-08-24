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

#![allow(unsafe_code, unused)] // TODO Remove the unused attribute later

use std::io::{Read, Write};
use sodiumoxide::crypto;

use routing::authority::Authority;
use routing::data::{Data, DataRequest};
use routing::event::Event;
use routing::immutable_data::ImmutableDataType;
use routing::{ExternalRequest, ExternalResponse, NameType};
use routing::error::{RoutingError, InterfaceError, ResponseError};

#[derive(Clone)]
pub struct MockRouting {
    sender: ::std::sync::mpsc::Sender<Event>,
    client_sender: ::std::sync::mpsc::Sender<Data>,  // for testing only
    network_delay_ms: u32,  // for testing only
}

impl MockRouting {
    pub fn new(event_sender: ::std::sync::mpsc::Sender<(Event)>) -> MockRouting {
        let (client_sender, _) = ::std::sync::mpsc::channel();

        let mock_routing = MockRouting {
            sender: event_sender,
            client_sender: client_sender,
            network_delay_ms: 200,
        };

        mock_routing
    }

    #[allow(dead_code)]
    pub fn set_network_delay_for_delay_simulation(&mut self, delay_ms: u32) {
        self.network_delay_ms = delay_ms;
    }

    pub fn get_client_receiver(&mut self) -> ::std::sync::mpsc::Receiver<Data> {
        let (client_sender, client_receiver) = ::std::sync::mpsc::channel();
        self.client_sender = client_sender;
        client_receiver
    }

    // -----------  the following methods are for testing purpose only   ------------- //
    pub fn client_get(&mut self, client_address: NameType,
                      client_pub_key: crypto::sign::PublicKey, data_request: DataRequest) {
        let name = match data_request {
            DataRequest::ImmutableData(name, _) => name,
            DataRequest::StructuredData(name, _) => name,
            _ => panic!("unexpected")
        };
        let cloned_sender = self.sender.clone();
        let _ = ::std::thread::spawn(move || {
            let _ = cloned_sender.send(Event::Request{ request: ExternalRequest::Get(data_request),
                                                       our_authority: Authority::NaeManager(name),
                                                       from_authority: Authority::Client(client_address, client_pub_key),
                                                       response_token: None });
        });
    }

    pub fn client_put(&mut self, client_address: NameType,
                      client_pub_key: crypto::sign::PublicKey, data: Data) {
        let delay_ms = self.network_delay_ms;
        let cloned_sender = self.sender.clone();
        let _ = ::std::thread::spawn(move || {
            ::std::thread::sleep_ms(delay_ms);
            let _ = cloned_sender.send(Event::Request{ request: ExternalRequest::Put(data),
                                                       our_authority: Authority::ClientManager(client_address),
                                                       from_authority: Authority::Client(client_address, client_pub_key),
                                                       response_token: None });
        });
    }

    pub fn client_post(&mut self, client_address: NameType,
                       client_pub_key: crypto::sign::PublicKey, data: Data) {
        let delay_ms = self.network_delay_ms;
        let cloned_sender = self.sender.clone();
        let _ = ::std::thread::spawn(move || {
            ::std::thread::sleep_ms(delay_ms);
            let _ = cloned_sender.send(Event::Request{ request: ExternalRequest::Post(data.clone()),
                                                       our_authority: Authority::NaeManager(data.name()),
                                                       from_authority: Authority::Client(client_address, client_pub_key),
                                                       response_token: None });
        });
    }

    pub fn churn_event(&mut self, nodes: Vec<NameType>) {
        let cloned_sender = self.sender.clone();
        let _ = ::std::thread::spawn(move || {
            let _ = cloned_sender.send(Event::Churn(nodes));
        });
    }

    // -----------  the above methods are for testing purpose only   ------------- //

    // -----------  the following methods are expected to be API functions   ------------- //

    pub fn get_response(&self, location       : Authority,
                               data           : Data,
                               data_request   : DataRequest,
                               response_token : Option<::routing::SignedToken>) {
        let delay_ms = self.network_delay_ms;
        let cloned_sender = self.sender.clone();
        let cloned_client_sender = self.client_sender.clone();
        let _ = ::std::thread::spawn(move || {
            match location.clone() {
                Authority::NaeManager(_) => {
                    let _ = cloned_sender.send(Event::Response{ response: ExternalResponse::Get(data.clone(), data_request, response_token),
                                                                our_authority: location,
                                                                from_authority: Authority::ManagedNode(NameType::new([7u8; 64])) });
                },
                Authority::Client(_, _) => {
                    let _ = cloned_client_sender.send(data);
                },
                _ => {}
            }
        });
    }

    pub fn get_request(&self, location: Authority, request_for: DataRequest) {
        let name = match request_for.clone() {
            DataRequest::StructuredData(name, _) => name,
            DataRequest::ImmutableData(name, _) => name,
            DataRequest::PlainData(_) => panic!("Unexpected"),
        };
        let delay_ms = self.network_delay_ms;
        let cloned_sender = self.sender.clone();

        let _ = ::std::thread::spawn(move || {
            ::std::thread::sleep_ms(delay_ms);
            match location.clone() {
                Authority::ManagedNode(_) => {
                    let _ = cloned_sender.send(Event::Request{ request: ExternalRequest::Get(request_for),
                                                               our_authority: Authority::ManagedNode(NameType::new([7u8; 64])),
                                                               from_authority: Authority::NaeManager(name),
                                                               response_token: None });
                },
                _ => {}
            }
        });
    }

    pub fn put_request(&self, location: Authority, data: Data) {
        let destination = match location.clone() {
            Authority::ClientManager(dest) => dest,
            Authority::NaeManager(dest) => dest,
            Authority::NodeManager(dest) => dest,
            Authority::ManagedNode(dest) => dest,
            _ => panic!("Unexpected"),
        };
        let delay_ms = self.network_delay_ms;
        let cloned_sender = self.sender.clone();

        let _ = ::std::thread::spawn(move || {
            ::std::thread::sleep_ms(delay_ms);
            match location.clone() {
                Authority::NaeManager(_) => {
                    let _ = cloned_sender.send(Event::Request{ request: ExternalRequest::Put(data.clone()),
                                                               our_authority: location,
                                                               from_authority: Authority::ClientManager(NameType::new([7u8; 64])),
                                                               response_token: None });
                },
                Authority::NodeManager(_) => {
                    let _ = cloned_sender.send(Event::Request{ request: ExternalRequest::Put(data.clone()),
                                                               our_authority: location,
                                                               from_authority: Authority::NaeManager(data.name()),
                                                               response_token: None });
                },
                Authority::ManagedNode(_) => {
                    let _ = cloned_sender.send(Event::Request{ request: ExternalRequest::Put(data.clone()),
                                                               our_authority: location,
                                                               from_authority: Authority::NodeManager(NameType::new([6u8; 64])),
                                                               response_token: None });
                },
                _ => {}
            }
        });
    }

}
