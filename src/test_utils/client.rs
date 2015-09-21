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

extern crate time;

/// Network Client.
pub struct Client {
    routing_client: ::routing_client::RoutingClient,
    receiver: ::std::sync::mpsc::Receiver<::event::Event>,
    id: ::id::Id,
}

impl Client {

    /// Construct new Client.
    pub fn new() -> Client {
        let (sender, receiver) = ::std::sync::mpsc::channel::<::event::Event>();
        let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let encrypt_keys = ::sodiumoxide::crypto::box_::gen_keypair();
        let id = ::id::Id::with_keys(sign_keys.clone(), encrypt_keys.clone());
        let public_id = ::public_id::PublicId::new(&id);
        let routing_client = ::routing_client::RoutingClient::new(sender, Some(id));

        debug!("Client name {:?}", public_id.clone());

        Client {
            routing_client: routing_client,
            receiver: receiver,
            id: ::id::Id::with_keys(sign_keys, encrypt_keys),
        }
    }

    /// Get data from the network.
    pub fn get(&mut self, request: ::data::DataRequest) -> Option<::data::Data> {
        debug!("Get request from Client for {:?}", request);
        self.routing_client.get_request(
            ::authority::Authority::NaeManager(request.name()), request.clone());

        // Block until the data arrives.
        let timeout = ::time::Duration::milliseconds(10000);
        let time = ::time::SteadyTime::now();
        loop {
            while let Ok(event) = self.receiver.try_recv() {
                debug!("Client received routing event: {:?}", event);
                match event {
                    ::event::Event::Response{ response, our_authority: _, from_authority : _} => {
                        match response {
                            ::messages::ExternalResponse::Get(data, _, _) => {
                                debug!("Client received data {:?} for get request.", data);
                                debug!("Get took {:?} to arrive.",
                                        ::time::SteadyTime::now() - time);
                                return Some(data);
                            },
                            _ => debug!("Received unexpected external response {:?},", response),
                        };
                    },
                    _ => {},
                };

                break;
            }

            if time + timeout < ::time::SteadyTime::now() {
                debug!("Timed out waiting for data");
                return None;
            }
            ::std::thread::sleep_ms(10);
        }
    }

    /// Put data onto the network.
    pub fn put(&self, data: ::data::Data) {
        debug!("Put request from Client for {:?}", data);
        self.routing_client.put_request(::authority::Authority::ClientManager(self.name()), data);
    }

    // /// Post data onto the network.
    // pub fn post(&self, data: ::data::Data, location: Option<::authority::Authority>) {
    //     let location = match location {
    //         Some(authority) => authority,
    //         None => ::authority::Authority::NaeManager(data.name()),
    //     };

    //     self.routing.post_request(location, data)
    // }

    // /// Delete data from the network.
    // pub fn delete(&self, data: ::data::Data, location: Option<::authority::Authority>) {
    //     let location = match location {
    //         Some(authority) => authority,
    //         None => ::routing::authority::Authority::ClientManager(data.name()),
    //     };

    //     self.routing.delete_request(location, data)
    // }

    /// Return network name.
    pub fn name(&self) -> ::NameType {
        self.id.name()
    }
}
