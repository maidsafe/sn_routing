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
use maidsafe_utilities::serialisation::deserialise;
use rand;
use routing::{Data, DataRequest, ResponseContent, ResponseMessage, StructuredData};
use xor_name::XorName;

struct Fixture {
    pub test_group: TestGroup,
    pub client1: Client,
    pub client2: Client,
    pub sd: StructuredData,
    pub max_get_attempts: u32,
}

pub fn test(max_get_attempts: u32) {
    let test_group = TestGroup::new("StructuredData test");
    let client1 = Client::new();
    let client2 = Client::new();
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
        max_get_attempts: max_get_attempts,
    };

    put(&mut fixture);
    get(&mut fixture);
    post(&mut fixture);
    delete(&mut fixture);

    fixture.test_group.release();
}

fn put(fixture: &mut Fixture) {
    fixture.test_group.start_case("Put with no account");
    let data = Data::Structured(fixture.sd.clone());
    if let ResponseMessage {
           content: ResponseContent::PutFailure { ref external_error_indicator, .. }, .. } =
           unwrap_option!(fixture.client1.put(data.clone()), "") {
        if let ClientError::NoSuchAccount = unwrap_result!(deserialise(external_error_indicator)) {
        } else {
            panic!("Received unexpected external_error_indicator")
        }
    } else {
        panic!("Received unexpected response")
    }

    fixture.test_group.start_case("Put");
    fixture.client1.create_account();
    if let ResponseMessage { content: ResponseContent::PutSuccess(..), .. } =
           unwrap_option!(fixture.client1.put(data), "") {} else {
        panic!("Received unexpected response")
    }
}

fn get(fixture: &mut Fixture) {
    fixture.test_group.start_case("Get");
    let mut data_request = DataRequest::Structured(*fixture.sd.get_identifier(),
                                                   fixture.sd.get_type_tag());
    if let ResponseMessage { content: ResponseContent::GetSuccess(response_data, _), .. } =
           unwrap_option!(fixture.client1.get(data_request.clone()), "") {
        assert_eq!(Data::Structured(fixture.sd.clone()), response_data)
    } else {
        panic!("Received unexpected response")
    }

    fixture.test_group.start_case("Get via different Client");
    // Should succeed on first attempt if previous Client was able to Get already.
    if let ResponseMessage { content: ResponseContent::GetSuccess(response_data, _), .. } =
           unwrap_option!(fixture.client2.get(data_request), "") {
        assert_eq!(Data::Structured(fixture.sd.clone()), response_data)
    } else {
        panic!("Received unexpected response")
    }

    fixture.test_group.start_case("Get for non-existent data");
    data_request = DataRequest::Structured(rand::random::<XorName>(), 1);
    if let ResponseMessage {
           content: ResponseContent::GetFailure { ref external_error_indicator, .. }, .. } =
           unwrap_option!(fixture.client1.get(data_request), "") {
        let parsed_error = unwrap_result!(deserialise(external_error_indicator));
        if let ClientError::NoSuchData = parsed_error {} else {
            panic!("Received unexpected external_error_indicator")
        }
    } else {
        panic!("Received unexpected response")
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
    if let ResponseMessage {
           content: ResponseContent::PostFailure { ref external_error_indicator, .. }, .. } =
           unwrap_option!(fixture.client2.post(data), "") {
        // structured_data_manager hasn't implemented a proper external_error_indicator in
        // PostFailure
        assert_eq!(0, external_error_indicator.len())
    } else {
        panic!("Received unexpected response")
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
    if let ResponseMessage { content: ResponseContent::PostSuccess( .. ), .. } =
           unwrap_option!(fixture.client1.post(data.clone()), "") {} else {
        panic!("Received unexpected response")
    }

    fixture.test_group.start_case("Get updated");
    let data_request = DataRequest::Structured(*fixture.sd.get_identifier(),
                                               fixture.sd.get_type_tag());
    // Should succeed on first attempt if previous Post message returned success.
    if let ResponseMessage { content: ResponseContent::GetSuccess(response_data, _), .. } =
           unwrap_option!(fixture.client1.get(data_request), "") {
        assert_eq!(data, response_data)
    } else {
        panic!("Received unexpected response")
    }

    fixture.test_group.start_case("Post for non-existent data");
    let bad_sd = unwrap_result!(StructuredData::new(2,
                                                    rand::random::<XorName>(),
                                                    0,
                                                    generate_random_vec_u8(10),
                                                    vec![fixture.client1.signing_public_key()],
                                                    vec![],
                                                    Some(fixture.client1.signing_private_key())));
    data = Data::Structured(bad_sd);
    if let ResponseMessage {
           content: ResponseContent::PostFailure { ref external_error_indicator, .. }, .. } =
           unwrap_option!(fixture.client1.post(data), "") {
        // structured_data_manager hasn't implemented a proper external_error_indicator in
        // PostFailure
        assert_eq!(0, external_error_indicator.len())
    } else {
        panic!("Received unexpected response")
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
    if let ResponseMessage {
           content: ResponseContent::DeleteFailure { ref external_error_indicator, .. }, .. } =
           unwrap_option!(fixture.client1.delete(data), "") {
        // structured_data_manager hasn't implemented a proper external_error_indicator in
        // DeleteFailure
        assert_eq!(0, external_error_indicator.len())
    } else {
        panic!("Received unexpected response")
    }

    let mut data_request = DataRequest::Structured(*fixture.sd.get_identifier(),
                                                   fixture.sd.get_type_tag());
    if let ResponseMessage { content: ResponseContent::GetSuccess(response_data, _), .. } =
           unwrap_option!(fixture.client1.get(data_request.clone()), "") {
        assert_eq!(Data::Structured(fixture.sd.clone()), response_data);
    } else {
        panic!("Received unexpected response")
    }

    fixture.test_group.start_case("Delete properly");
    fixture.sd = unwrap_result!(StructuredData::new(fixture.sd.get_type_tag(),
                                                    *fixture.sd.get_identifier(),
                                                    fixture.sd.get_version() + 1,
                                                    generate_random_vec_u8(10),
                                                    fixture.sd.get_owner_keys().clone(),
                                                    vec![],
                                                    Some(fixture.client1.signing_private_key())));
    data = Data::Structured(fixture.sd.clone());
    if let ResponseMessage { content: ResponseContent::DeleteSuccess( .. ), .. } =
           unwrap_option!(fixture.client1.delete(data), "") {} else {
        panic!("Received unexpected response")
    }
    data_request = DataRequest::Structured(*fixture.sd.get_identifier(), fixture.sd.get_type_tag());
    if let ResponseMessage {
           content: ResponseContent::GetFailure { ref external_error_indicator, .. }, .. } =
           unwrap_option!(fixture.client1.get(data_request), "") {
        let parsed_error = unwrap_result!(deserialise(external_error_indicator));
        if let ClientError::NoSuchData = parsed_error {} else {
            panic!("Received unexpected external_error_indicator")
        }
    } else {
        panic!("Received unexpected response")
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
    if let ResponseMessage {
           content: ResponseContent::PutFailure { ref external_error_indicator, .. }, .. } =
           unwrap_option!(fixture.client1.put(data.clone()), "") {
        let parsed_error = unwrap_result!(deserialise(external_error_indicator));
        if let ClientError::DataExists = parsed_error {} else {
            panic!("Received unexpected external_error_indicator")
        }
    } else {
        panic!("Received unexpected response")
    }
}
