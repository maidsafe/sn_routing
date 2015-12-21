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
use sodiumoxide::crypto;
use time::{Duration, SteadyTime};
use std::thread;
use routing_client::RoutingClient;
use authority::Authority::{NaeManager, ClientManager};
use messages::ResponseContent;
use xor_name::XorName;
use id::FullId;
use event::Event;
use data::{Data, DataRequest};

/// Network Client.
pub struct Client {
    routing_client: RoutingClient,
    receiver: mpsc::Receiver<Event>,
    full_id: FullId,
}

impl Client {
    /// Client constructor.
    pub fn new() -> Client {
        let (sender, receiver) = mpsc::channel::<Event>();
        let sign_keys = crypto::sign::gen_keypair();
        let encrypt_keys = crypto::box_::gen_keypair();
        let full_id = FullId::with_keys(encrypt_keys.clone(), sign_keys.clone());
        let routing_client = unwrap_result!(RoutingClient::new(sender, Some(full_id)));

        Client {
            routing_client: routing_client,
            receiver: receiver,
            full_id: FullId::with_keys(encrypt_keys, sign_keys),
        }
    }

    /// Get from network.
    pub fn get(&mut self, request: DataRequest) -> Option<Data> {
        unwrap_result!(self.routing_client.send_get_request(NaeManager(request.name()), request.clone()));
        let timeout = Duration::milliseconds(10000);
        let time = SteadyTime::now();

        loop {
            while let Ok(event) = self.receiver.try_recv() {
                if let Event::Response(msg) = event {
                    match msg.content {
                        ResponseContent::GetSuccess(data) => return Some(data),
                        ResponseContent::GetFailure { .. } => return None,
                        _ => trace!("Received unexpected response {:?},", msg),
                    };
                }

                break;
            }

            if time + timeout < SteadyTime::now() {
                debug!("Timed out waiting for data");
                return None;
            }

            let interval = ::std::time::Duration::from_millis(10);
            thread::sleep(interval);
        }
    }

    /// Put to network.
    pub fn put(&self, data: Data) {
        unwrap_result!(self.routing_client.send_put_request(ClientManager(*self.name()), data));
    }

    /// Post data onto the network.
    pub fn post(&self) {
        unimplemented!()
    }

    /// Delete data from the network.
    pub fn delete(&self) {
        unimplemented!()
    }

    /// Return network name.
    pub fn name(&self) -> &XorName {
        self.full_id.public_id().name()
    }
}
