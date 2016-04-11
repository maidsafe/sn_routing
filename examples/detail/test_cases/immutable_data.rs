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

use super::*;
use rand;
use routing::{Data, DataRequest, ImmutableData, ImmutableDataType};
use safe_network_common::client_errors::GetError;
use xor_name::XorName;

pub fn test() {
    let mut test_group = TestGroup::new("ImmutableData test");
    let testing_data = Data::Immutable(ImmutableData::new(ImmutableDataType::Normal,
                                                          generate_random_vec_u8(1024)));

    // safe_core::client doesn't provide an API allows connecting to network without creating an
    // account. The unregistered client can only do get, not put.
    // test_group.start_case("Put with no account");
    // let mut client1 = Client::create_unregistered_client();
    // match client1.put(testing_data.clone()) {
    //     Ok(result) => panic!("Received unexpected response {:?}", result),
    //     Err(MutationError::NoSuchAccount) => {}
    //     Err(err) => panic!("Received unexpected err {:?}", err),
    // }

    test_group.start_case("Put");
    let mut client1 = Client::create_account();
    assert!(client1.put(testing_data.clone()).is_ok());

    test_group.start_case("Get");
    let mut data_request = DataRequest::Immutable(testing_data.name(), ImmutableDataType::Normal);
    assert_eq!(testing_data,
               unwrap_result!(client1.get(data_request.clone())));

    test_group.start_case("Get via different Client");
    let mut client2 = Client::create_unregistered_client();
    // Should succeed on first attempt if previous Client was able to Get already.
    assert_eq!(testing_data,
               unwrap_result!(client2.get(data_request.clone())));

    test_group.start_case("Get for non-existent data");
    data_request = DataRequest::Immutable(rand::random::<XorName>(), ImmutableDataType::Normal);
    match client1.get(data_request) {
        Ok(result) => panic!("Received unexpected response {:?}", result),
        Err(GetError::NoSuchData) => {}
        Err(err) => panic!("Received unexpected err {:?}", err),
    }

    test_group.release();
}
