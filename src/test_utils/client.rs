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

pub struct Client {
    routing_client: ::routing_client::RoutingClient,
    receiver: ::std::sync::mpsc::Receiver<::event::Event>,
    public_id: ::public_id::PublicId,
}

impl Client {
    pub fn new() -> Client {
        let (sender, receiver) = ::std::sync::mpsc::channel::<::event::Event>();

        let id = ::id::Id::new();
        let public_id = ::public_id::PublicId::new(&id);
        let routing_client = ::routing_client::RoutingClient::new(sender, Some(id));

        debug!("Client name {:?}", public_id.clone());

        Client {
            routing_client: routing_client,
            receiver: receiver,
            public_id: public_id,
        }
    }

    pub fn run(&mut self) {
    }

    /// Get data from the network.
    pub fn get(&mut self, request: ::data::DataRequest, location: Option<::authority::Authority>) {
        let authority = match location {
            Some(authority) => authority,
            None => ::authority::Authority::NaeManager(request.name()),
        };

        self.routing_client.get_request(authority, request.clone());
    }

    /// Put data onto the network.
    pub fn put(&self, data: ::data::Data, location: Option<::authority::Authority>) {
        let authority = match location {
            Some(authority) => authority,
            None => ::authority::Authority::ClientManager(data.name()),
        };

        self.routing_client.put_request(authority, data)
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

    /// Exit run loop.
    pub fn stop(&mut self) {
    }
}
