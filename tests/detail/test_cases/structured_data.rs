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
use routing::{Data, DataRequest, StructuredData};
use safe_network_common::client_errors::{GetError, MutationError};
use xor_name::XorName;

struct Fixture {
    pub test_group: TestGroup,
    pub client1: Client,
    pub client2: Client,
    pub sd: StructuredData,
}

pub fn test() {
    let test_group = TestGroup::new("StructuredData test");
    // safe_core::client API requires create_account to having keys
    let client1 = Client::create_account();
    let client2 = Client::create_account();
    let sd = unwrap_result!(StructuredData::new(1,
                                                rand::random::<XorName>(),
                                                0,
                                                generate_random_vec_u8(10),
                                                vec![client1.signing_public_key()],
                                                vec![],
                                                Some(client1.signing_private_key())));
    let mut fixture = Fixture {
        test_group: test_group,
        client1: client1,
        client2: client2,
        sd: sd,
    };

    put(&mut fixture);
    get(&mut fixture);
    post(&mut fixture);
    delete(&mut fixture);

    fixture.test_group.release();
}

fn put(fixture: &mut Fixture) {
    let testing_data = Data::Structured(fixture.sd.clone());
    // safe_core::client doesn't provide an API allows connecting to network without creating an
    // account. The unregistered client can only do get, not put.
    // fixture.test_group.start_case("Put with no account");
    // match fixture.client1.put(testing_data.clone()) {
    //     Ok(result) => panic!("Received unexpected response {:?}", result),
    //     Err(MutationError::NoSuchAccount) => {}
    //     Err(err) => panic!("Received unexpected err {:?}", err),
    // }

    fixture.test_group.start_case("Put");
    assert!(fixture.client1.put(testing_data).is_ok());
}

fn get(fixture: &mut Fixture) {
    fixture.test_group.start_case("Get");
    let mut data_request = DataRequest::Structured(*fixture.sd.get_identifier(),
                                                   fixture.sd.get_type_tag());
    assert_eq!(Data::Structured(fixture.sd.clone()),
               unwrap_result!(fixture.client1.get(data_request.clone())));

    fixture.test_group.start_case("Get via different Client");
    // Should succeed on first attempt if previous Client was able to Get already.
    assert_eq!(Data::Structured(fixture.sd.clone()),
               unwrap_result!(fixture.client2.get(data_request.clone())));

    fixture.test_group.start_case("Get for non-existent data");
    data_request = DataRequest::Structured(rand::random::<XorName>(), 1);
    match fixture.client1.get(data_request) {
        Ok(result) => panic!("Received unexpected response {:?}", result),
        Err(GetError::NoSuchData) => {}
        Err(err) => panic!("Received unexpected err {:?}", err),
    }
}

fn post(fixture: &mut Fixture) {
    fixture.test_group.start_case("Post from non-authorised Client");
    let unauthorised_sd = unwrap_result!(StructuredData::new(fixture.sd.get_type_tag(),
                                                             *fixture.sd.get_identifier(),
                                                             fixture.sd.get_version() + 1,
                                                             generate_random_vec_u8(10),
                                                             fixture.sd.get_owner_keys().clone(),
                                                             vec![],
                                                             Some(fixture.client2
                                                                         .signing_private_key())));
    let mut data = Data::Structured(unauthorised_sd.clone());
    match fixture.client2.post(data) {
        Ok(result) => panic!("Received unexpected response {:?}", result),
        // structured_data_manager hasn't implemented a proper external_error_indicator
        Err(MutationError::Unknown) => {}
        Err(err) => panic!("Received unexpected err {:?}", err),
    }

    fixture.test_group.start_case("Post");
    fixture.sd = unwrap_result!(StructuredData::new(fixture.sd.get_type_tag(),
                                                    *fixture.sd.get_identifier(),
                                                    fixture.sd.get_version() + 1,
                                                    generate_random_vec_u8(10),
                                                    fixture.sd.get_owner_keys().clone(),
                                                    vec![],
                                                    Some(fixture.client1.signing_private_key())));
    data = Data::Structured(fixture.sd.clone());
    assert!(fixture.client1.post(data.clone()).is_ok());

    fixture.test_group.start_case("Get updated");
    let data_request = DataRequest::Structured(*fixture.sd.get_identifier(),
                                               fixture.sd.get_type_tag());
    // Should succeed on first attempt if previous Post message returned success.
    assert_eq!(data,
               unwrap_result!(fixture.client1.get(data_request.clone())));

    fixture.test_group.start_case("Post for non-existent data");
    let bad_sd = unwrap_result!(StructuredData::new(2,
                                                    rand::random::<XorName>(),
                                                    0,
                                                    generate_random_vec_u8(10),
                                                    vec![fixture.client1.signing_public_key()],
                                                    vec![],
                                                    Some(fixture.client1.signing_private_key())));
    data = Data::Structured(bad_sd);
    match fixture.client1.post(data) {
        Ok(result) => panic!("Received unexpected response {:?}", result),
        // structured_data_manager hasn't implemented a proper external_error_indicator
        Err(MutationError::Unknown) => {}
        Err(err) => panic!("Received unexpected err {:?}", err),
    }
}

fn delete(fixture: &mut Fixture) {
    fixture.test_group.start_case("Delete improperly");
    let invalid_sd = unwrap_result!(StructuredData::new(fixture.sd.get_type_tag(),
                                                        *fixture.sd.get_identifier(),
                                                        fixture.sd.get_version(),
                                                        generate_random_vec_u8(10),
                                                        fixture.sd.get_owner_keys().clone(),
                                                        vec![],
                                                        Some(fixture.client2
                                                                    .signing_private_key())));
    let mut data = Data::Structured(invalid_sd);
    match fixture.client1.delete(data) {
        Ok(result) => panic!("Received unexpected response {:?}", result),
        // structured_data_manager hasn't implemented a proper external_error_indicator
        Err(MutationError::Unknown) => {}
        Err(err) => panic!("Received unexpected err {:?}", err),
    }

    let mut data_request = DataRequest::Structured(*fixture.sd.get_identifier(),
                                                   fixture.sd.get_type_tag());
    assert_eq!(Data::Structured(fixture.sd.clone()),
               unwrap_result!(fixture.client1.get(data_request.clone())));

    fixture.test_group.start_case("Delete properly");
    fixture.sd = unwrap_result!(StructuredData::new(fixture.sd.get_type_tag(),
                                                    *fixture.sd.get_identifier(),
                                                    fixture.sd.get_version() + 1,
                                                    generate_random_vec_u8(10),
                                                    fixture.sd.get_owner_keys().clone(),
                                                    vec![],
                                                    Some(fixture.client1.signing_private_key())));
    data = Data::Structured(fixture.sd.clone());
    assert!(fixture.client1.delete(data).is_ok());

    data_request = DataRequest::Structured(*fixture.sd.get_identifier(), fixture.sd.get_type_tag());
    match fixture.client1.get(data_request) {
        Ok(result) => panic!("Received unexpected response {:?}", result),
        // structured_data_manager hasn't implemented a proper external_error_indicator
        Err(GetError::NoSuchData) => {}
        Err(err) => panic!("Received unexpected err {:?}", err),
    }

    fixture.test_group.start_case("Try to Put recently deleted");
    let deleted_sd = unwrap_result!(StructuredData::new(fixture.sd.get_type_tag(),
                                                        fixture.sd.get_identifier().clone(),
                                                        0,
                                                        generate_random_vec_u8(10),
                                                        vec![fixture.client1
                                                                    .signing_public_key()],
                                                        vec![],
                                                        Some(fixture.client1
                                                                    .signing_private_key())));
    data = Data::Structured(deleted_sd);
    match fixture.client1.put(data) {
        Ok(result) => panic!("Received unexpected response {:?}", result),
        // structured_data_manager hasn't implemented a proper external_error_indicator
        Err(MutationError::DataExists) => {}
        Err(err) => panic!("Received unexpected err {:?}", err),
    }
}
