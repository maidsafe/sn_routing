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

pub fn test() {
    let mut test_group = TestGroup::new("StructuredData test");

    test_group.start_case("Put with no account");
    let mut client1 = Client::new();
    let data = Data::StructuredData(unwrap_result!(
            StructuredData::new(1,
                                rand::random::<XorName>(),
                                0,
                                generate_random_vec_u8(10),
                                vec![client1.signing_public_key()],
                                vec![],
                                Some(client1.signing_private_key()))));

    match unwrap_option!(client1.put(data.clone()), "") {
        ResponseMessage { content: ResponseContent::PutFailure { ref external_error_indicator, .. }, .. } => {
            match unwrap_result!(deserialise::<ClientError>(external_error_indicator)) {
                ClientError::NoSuchAccount => {}
                _ => panic!("Received unexpected external_error_indicator"),
            }
        }
        _ => panic!("Received unexpected response"),
    }

    test_group.start_case("Put");
    client1.create_account();
    let sd = unwrap_result!(StructuredData::new(1,
                                                rand::random::<XorName>(),
                                                0,
                                                generate_random_vec_u8(10),
                                                vec![client1.signing_public_key()],
                                                vec![],
                                                Some(client1.signing_private_key())));
    let data = Data::StructuredData(sd.clone());
    match unwrap_option!(client1.put(data.clone()), "") {
        ResponseMessage { content: ResponseContent::PutSuccess(..), .. } => {}
        _ => panic!("Received unexpected response"),
    }

    test_group.start_case("Get");
    let data_request = DataRequest::StructuredData(*sd.get_identifier(), sd.get_type_tag());
    match unwrap_option!(client1.get(data_request.clone()), "") {
        ResponseMessage { content: ResponseContent::GetSuccess(response_data, _), .. } => {
            assert_eq!(data, response_data);
        }
        _ => panic!("Received unexpected response"),
    }

    test_group.start_case("Get via different Client");
    let mut client2 = Client::new();
    match unwrap_option!(client2.get(data_request), "") {
        ResponseMessage { content: ResponseContent::GetSuccess(response_data, _), .. } => {
            assert_eq!(data, response_data);
        }
        _ => panic!("Received unexpected response"),
    }

    test_group.start_case("Get for non-existent data");
    let data_request = DataRequest::StructuredData(rand::random::<XorName>(), 1);
    match unwrap_option!(client1.get(data_request), "") {
        ResponseMessage { content: ResponseContent::GetFailure { ref external_error_indicator, .. }, .. } => {
            match unwrap_result!(deserialise::<ClientError>(external_error_indicator)) {
                ClientError::NoSuchData => {}
                _ => panic!("Received unexpected external_error_indicator"),
            }
        }
        _ => panic!("Received unexpected response"),
    }

    test_group.start_case("Post from non-authorised Client");
    let sd = unwrap_result!(StructuredData::new(sd.get_type_tag(),
                                                *sd.get_identifier(),
                                                sd.get_version() + 1,
                                                generate_random_vec_u8(10),
                                                sd.get_owner_keys().clone(),
                                                vec![],
                                                Some(client2.signing_private_key())));
    let data = Data::StructuredData(sd.clone());
    match client2.post(data) {
        None => {}
        _ => panic!("Received unexpected response"),
    }

    test_group.start_case("Post");
    let sd_posted = unwrap_result!(StructuredData::new(sd.get_type_tag(),
                                                *sd.get_identifier(),
                                                sd.get_version(),
                                                generate_random_vec_u8(10),
                                                sd.get_owner_keys().clone(),
                                                vec![],
                                                Some(client1.signing_private_key())));
    let data_posted = Data::StructuredData(sd_posted.clone());
    match unwrap_option!(client1.post(data_posted.clone()), "") {
        ResponseMessage { content: ResponseContent::PostSuccess( .. ), .. } => {}
        _ => panic!("Received unexpected response"),
    }


    test_group.start_case("Get updated");
    let data_request = DataRequest::StructuredData(*sd.get_identifier(), sd.get_type_tag());
    match unwrap_option!(client1.get(data_request), "") {
        ResponseMessage { content: ResponseContent::GetSuccess(response_data, _), .. } => {
            assert_eq!(data_posted, response_data);
        }
        _ => panic!("Received unexpected response"),
    }

    test_group.start_case("Post for non-existent data");
    let sd = unwrap_result!(StructuredData::new(2,
                                                rand::random::<XorName>(),
                                                0,
                                                generate_random_vec_u8(10),
                                                vec![client1.signing_public_key()],
                                                vec![],
                                                Some(client1.signing_private_key())));
    let data = Data::StructuredData(sd);
    match unwrap_option!(client1.post(data), "") {
        ResponseMessage { content: ResponseContent::PostFailure { ref external_error_indicator, .. }, .. } => {
            // structured_data_manager hasn't implemented a proper external_error_indicator in PostFailure
            assert_eq!(0, external_error_indicator.len());
        }
        _ => panic!("Received unexpected response"),
    }

    test_group.start_case("Delete improperly");
    let sd = unwrap_result!(StructuredData::new(sd_posted.get_type_tag(),
                                                *sd_posted.get_identifier(),
                                                sd_posted.get_version(),
                                                generate_random_vec_u8(10),
                                                sd_posted.get_owner_keys().clone(),
                                                vec![],
                                                Some(client2.signing_private_key())));
    let data = Data::StructuredData(sd);
    match unwrap_option!(client1.delete(data), "") {
        ResponseMessage { content: ResponseContent::DeleteFailure { ref external_error_indicator, .. }, .. } => {
            // structured_data_manager hasn't implemented a proper external_error_indicator in DeleteFailure
            assert_eq!(0, external_error_indicator.len());
        }
        _ => panic!("Received unexpected response"),
    }
    let data_request = DataRequest::StructuredData(*sd_posted.get_identifier(), sd_posted.get_type_tag());
    match unwrap_option!(client1.get(data_request), "") {
        ResponseMessage { content: ResponseContent::GetSuccess(response_data, _), .. } => {
            assert_eq!(data_posted, response_data);
        }
        _ => panic!("Received unexpected response"),
    }

    test_group.start_case("Delete properly");
    let sd = unwrap_result!(StructuredData::new(sd_posted.get_type_tag(),
                                                *sd_posted.get_identifier(),
                                                sd_posted.get_version() + 1,
                                                generate_random_vec_u8(10),
                                                sd_posted.get_owner_keys().clone(),
                                                vec![],
                                                Some(client1.signing_private_key())));
    let data = Data::StructuredData(sd);
    match unwrap_option!(client1.delete(data), "") {
        ResponseMessage { content: ResponseContent::DeleteSuccess( .. ), .. } => {}
        _ => panic!("Received unexpected response"),
    }
    let data_request = DataRequest::StructuredData(*sd_posted.get_identifier(), sd_posted.get_type_tag());
    match unwrap_option!(client1.get(data_request), "") {
        ResponseMessage { content: ResponseContent::GetFailure { ref external_error_indicator, .. }, .. } => {
            match unwrap_result!(deserialise::<ClientError>(external_error_indicator)) {
                ClientError::NoSuchData => {}
                _ => panic!("Received unexpected external_error_indicator"),
            }
        }
        _ => panic!("Received unexpected response"),
    }

    test_group.release();
}
