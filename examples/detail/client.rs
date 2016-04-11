// Copyright 2016 MaidSafe.net limited.
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

use std::fmt::{self, Debug, Formatter};
use safe_core::core::client;
use safe_core::core::errors::CoreError;
use safe_network_common::client_errors::{GetError, MutationError};
use sodiumoxide::crypto;
use sodiumoxide::crypto::hash::sha512;
use rand::{thread_rng, Rng};
use rand::distributions::{IndependentSample, Range};
use routing::{Data, DataRequest};
use xor_name::XorName;

/// A simple example client implementation for a network based on the Routing library.
pub struct Client {
    /// The client interface to the safe_core.
    core_client: client::Client,
}

impl Client {
    /// Creates an unregistered client.
    pub fn create_unregistered_client() -> Client {
        Client { core_client: unwrap_result!(client::Client::create_unregistered_client()) }
    }

    /// Creates a registered client.
    pub fn create_account() -> Client {
        let mut rng = thread_rng();
        let keyword: String = rng.gen_ascii_chars().take(20).collect();
        let password: String = rng.gen_ascii_chars().take(20).collect();
        let pin_range = Range::new(0u16, 9999);
        let pin = pin_range.ind_sample(&mut rng).to_string();
        Client {
            core_client: unwrap_result!(client::Client::create_account(keyword, pin, password)),
        }
    }

    /// Send a `Get` request to the network and return the received response.
    pub fn get(&mut self, data_request: DataRequest) -> Result<Data, GetError> {
        let get_response_getter = unwrap_result!(self.core_client.get(data_request.clone(), None));
        match get_response_getter.get() {
            Ok(data) => Ok(data),
            Err(failure) => {
                match failure {
                    CoreError::GetFailure { ref request, ref reason } => {
                        assert_eq!(data_request, *request);
                        Err(reason.clone())
                    }
                    _ => panic!("Received unexpected failure {:?}", failure),
                }
            }
        }
    }

    /// Send a `Put` request to the network.
    pub fn put(&self, testing_data: Data) -> Result<(), MutationError> {
        let put_response_getter = unwrap_result!(self.core_client.put(testing_data.clone(), None));
        match put_response_getter.get() {
            Ok(_) => Ok(()),
            Err(failure) => {
                match failure {
                    CoreError::MutationFailure { ref data, ref reason } => {
                        assert_eq!(testing_data, *data);
                        Err(reason.clone())
                    }
                    _ => panic!("Received unexpected failure {:?}", failure),
                }
            }
        }
    }

    /// Post data onto the network.
    pub fn post(&self, testing_data: Data) -> Result<(), MutationError> {
        let post_response_getter = unwrap_result!(self.core_client
                                                      .post(testing_data.clone(), None));
        match post_response_getter.get() {
            Ok(_) => Ok(()),
            Err(failure) => {
                match failure {
                    CoreError::MutationFailure { ref data, ref reason } => {
                        assert_eq!(testing_data, *data);
                        Err(reason.clone())
                    }
                    _ => panic!("Received unexpected failure {:?}", failure),
                }
            }
        }
    }

    /// Delete data from the network.
    pub fn delete(&self, testing_data: Data) -> Result<(), MutationError> {
        let delete_response_getter = unwrap_result!(self.core_client
                                                        .delete(testing_data.clone(), None));
        match delete_response_getter.get() {
            Ok(_) => Ok(()),
            Err(failure) => {
                match failure {
                    CoreError::MutationFailure { ref data, ref reason } => {
                        assert_eq!(testing_data, *data);
                        Err(reason.clone())
                    }
                    _ => panic!("Received unexpected failure {:?}", failure),
                }
            }
        }
    }

    /// Return network name.
    pub fn name(&self) -> XorName {
        let hash_sign_key = sha512::hash(&(unwrap_result!(self.core_client
                                                              .get_public_signing_key()))
                                              .0);
        XorName::new(hash_sign_key.0)
    }

    /// Return public signing key.
    pub fn signing_public_key(&self) -> crypto::sign::PublicKey {
        *unwrap_result!(self.core_client.get_public_signing_key())
    }

    /// Return secret signing key.
    pub fn signing_private_key(&self) -> &crypto::sign::SecretKey {
        unwrap_result!(self.core_client.get_secret_signing_key())
    }
}

impl Debug for Client {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Client({:?})", self.name())
    }
}
