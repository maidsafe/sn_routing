// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use routing::{Authority, Client, ClientError, Event, FullId, ImmutableData, MessageId,
              MutableData, Response, Value, XorName};
use rust_sodium::crypto;
use std::collections::BTreeMap;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

const RESPONSE_TIMEOUT_SECS: u64 = 10;

macro_rules! recv_response {
    ($client:expr, $resp:ident, $data_id:expr, $req_msg_id:expr) => {
        loop {
            match $client.receiver.recv_timeout(Duration::from_secs(RESPONSE_TIMEOUT_SECS)) {
                Ok(Event::Response { response: Response::$resp { res, msg_id }, .. }) => {
                    if $req_msg_id != msg_id {
                        error!("{} response for {:?}, but with wrong message_id {:?} \
                                instead of {:?}.",
                               stringify!($resp),
                               $data_id,
                               msg_id,
                               $req_msg_id);
                        return Err(ClientError::from("Wrong message_id"));
                    }

                    if let Err(ref error) = res {
                        error!("{} for {:?} failed: {:?}", stringify!($resp), $data_id, error);
                    } else {
                        trace!("{} for {:?} successful", stringify!($resp), $data_id)
                    }

                    return res;
                }
                Ok(Event::Terminate) |
                Ok(Event::RestartRequired) => $client.disconnected(),
                Ok(_) => (),
                Err(_) => return Err(ClientError::from("No response")),
            }
        }
    }
}

/// A simple example client implementation for a network based on the Routing library.
pub struct ExampleClient {
    /// The client interface to the Routing library.
    client: Client,
    /// The receiver through which the Routing library will send events.
    receiver: Receiver<Event>,
    /// This client's ID.
    full_id: FullId,
}

impl ExampleClient {
    /// Creates a new client and attempts to establish a connection to the network.
    pub fn new() -> ExampleClient {
        let (sender, receiver) = mpsc::channel::<Event>();

        // Generate new key pairs. The client's name will be computed from them. This is a
        // requirement for clients: If the name does not match the keys, it will be rejected by the
        // network.
        let sign_keys = crypto::sign::gen_keypair();
        let encrypt_keys = crypto::box_::gen_keypair();
        let full_id = FullId::with_keys(encrypt_keys.clone(), sign_keys.clone());
        let mut client;

        // Try to connect the client to the network. If it fails, it probably means
        // the network isn't fully formed yet, so we restart and try again.
        'outer: loop {
            client = unwrap!(Client::new(
                sender.clone(),
                Some(full_id.clone()),
                None,
                Duration::from_secs(90),
            ));

            for event in receiver.iter() {
                match event {
                    Event::Connected => {
                        println!("Client Connected to the network");
                        break 'outer;
                    }
                    Event::Terminate => {
                        println!("Client failed to connect to the network. Restarting.");
                        thread::sleep(Duration::from_secs(5));
                        break;
                    }
                    _ => (),
                }
            }
        }

        ExampleClient {
            client: client,
            receiver: receiver,
            full_id: full_id,
        }
    }

    /// Send a `GetIData` request to the network and return the data received in
    /// the response.
    ///
    /// This is a blocking call and will wait indefinitely for the response.
    #[allow(unused)]
    pub fn get_idata(&mut self, name: XorName) -> Result<ImmutableData, ClientError> {
        let msg_id = MessageId::new();
        unwrap!(self.client.get_idata(
            Authority::NaeManager(name),
            name,
            msg_id,
        ));
        recv_response!(self, GetIData, name, msg_id)
    }

    /// Send a `PutIData` request to the network.
    ///
    /// This is a blocking call and will wait indefinitely for a response.
    #[allow(unused)]
    pub fn put_idata(&mut self, data: ImmutableData) -> Result<(), ClientError> {
        let dst = Authority::ClientManager(*self.name());
        let name = *data.name();
        let msg_id = MessageId::new();
        unwrap!(self.client.put_idata(dst, data, msg_id));
        recv_response!(self, PutMData, name, msg_id)
    }

    /// Send a `GetMDataShell` request to the network and return the data received in
    /// the response.
    ///
    /// This is a blocking call and will wait indefinitely for the response.
    #[allow(unused)]
    pub fn get_mdata_shell(&mut self, name: XorName, tag: u64) -> Result<MutableData, ClientError> {
        let msg_id = MessageId::new();
        unwrap!(self.client.get_mdata_shell(
            Authority::NaeManager(name),
            name,
            tag,
            msg_id,
        ));
        recv_response!(self, GetMDataShell, name, msg_id)
    }

    /// Send a `ListMDataEntries` request to the network and return the data received in
    /// the response.
    ///
    /// This is a blocking call and will wait indefinitely for the response.
    #[allow(unused)]
    pub fn list_mdata_entries(
        &mut self,
        name: XorName,
        tag: u64,
    ) -> Result<BTreeMap<Vec<u8>, Value>, ClientError> {
        let msg_id = MessageId::new();
        unwrap!(self.client.list_mdata_entries(
            Authority::NaeManager(name),
            name,
            tag,
            msg_id,
        ));
        recv_response!(self, ListMDataEntries, name, msg_id)
    }

    /// Send a `GetMDataValue` request to the network and return the data received in
    /// the response.
    ///
    /// This is a blocking call and will wait indefinitely for the response.
    #[allow(unused)]
    pub fn get_mdata_value(
        &mut self,
        name: XorName,
        tag: u64,
        key: Vec<u8>,
    ) -> Result<Value, ClientError> {
        let msg_id = MessageId::new();
        unwrap!(self.client.get_mdata_value(
            Authority::NaeManager(name),
            name,
            tag,
            key,
            msg_id,
        ));
        recv_response!(self, GetMDataValue, name, msg_id)
    }

    /// Send a `PutMData` request to the network.
    ///
    /// This is a blocking call and will wait indefinitely for a response.
    pub fn put_mdata(&mut self, data: MutableData) -> Result<(), ClientError> {
        let dst = Authority::ClientManager(*self.name());
        let name = *data.name();
        let tag = data.tag();
        let msg_id = MessageId::new();
        let requester = *self.signing_public_key();

        unwrap!(self.client.put_mdata(dst, data, msg_id, requester));
        recv_response!(self, PutMData, (name, tag), msg_id)
    }

    fn disconnected(&self) {
        panic!("Disconnected from the network.");
    }

    /// Returns network name.
    pub fn name(&self) -> &XorName {
        self.full_id.public_id().name()
    }

    /// Returns the signing public key of this client.
    pub fn signing_public_key(&self) -> &crypto::sign::PublicKey {
        self.full_id.public_id().signing_public_key()
    }
}

impl Default for ExampleClient {
    fn default() -> ExampleClient {
        ExampleClient::new()
    }
}
