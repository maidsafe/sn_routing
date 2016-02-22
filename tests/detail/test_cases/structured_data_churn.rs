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

pub fn test(request_count: u32) {
    let mut test_group = TestGroup::new("StructuredData churn test");

    let mut client = Client::new();
    client.create_account();
    let mut stored_data = Vec::with_capacity(request_count as usize);
    for i in 0..request_count {
        test_group.start_case(&format!("Put StructuredData {}", i));
        let sd = unwrap_result!(StructuredData::new(1,
                                                    rand::random::<XorName>(),
                                                    0,
                                                    generate_random_vec_u8(10),
                                                    vec![client.signing_public_key()],
                                                    vec![],
                                                    Some(client.signing_private_key())));
        let data = Data::StructuredData(sd.clone());
        match unwrap_option!(client.put(data), "") {
            ResponseMessage { content: ResponseContent::PutSuccess(..), .. } => {}
            _ => panic!("Received unexpected response"),
        }
        stored_data.push(sd);
    }

    for i in 0..request_count as usize {
        test_group.start_case(&format!("Get StructuredData {}", i));
        let data_request = DataRequest::StructuredData(*stored_data[i].get_identifier(),
                                                       stored_data[i].get_type_tag());
        match unwrap_option!(client.get(data_request.clone()), "") {
            ResponseMessage { content: ResponseContent::GetSuccess(Data::StructuredData(sd), _), .. } => {
                assert_eq!(stored_data[i], sd);
            }
            _ => panic!("Received unexpected response"),
        }
    }

    for i in 0..request_count as usize {
        test_group.start_case(&format!("Post StructuredData {}", i));
        let sd = unwrap_result!(StructuredData::new(stored_data[i].get_type_tag(),
                                                    *stored_data[i].get_identifier(),
                                                    stored_data[i].get_version() + 1,
                                                    generate_random_vec_u8(10),
                                                    stored_data[i].get_owner_keys().clone(),
                                                    vec![],
                                                    Some(client.signing_private_key())));
        let data = Data::StructuredData(sd.clone());
        match unwrap_option!(client.post(data), "") {
            ResponseMessage { content: ResponseContent::PostSuccess( .. ), .. } => {}
            _ => panic!("Received unexpected response"),
        }
        stored_data[i] = sd;
    }

    for i in 0..request_count as usize {
        test_group.start_case(&format!("Get updated StructuredData {}", i));
        let data_request = DataRequest::StructuredData(*stored_data[i].get_identifier(),
                                                       stored_data[i].get_type_tag());
        match unwrap_option!(client.get(data_request.clone()), "") {
            ResponseMessage { content: ResponseContent::GetSuccess(Data::StructuredData(sd), _), .. } => {
                assert_eq!(stored_data[i], sd);
            }
            _ => panic!("Received unexpected response"),
        }
    }

    for i in 0..request_count as usize {
        test_group.start_case(&format!("Delete StructuredData {}", i));
        let sd = unwrap_result!(StructuredData::new(stored_data[i].get_type_tag(),
                                                    *stored_data[i].get_identifier(),
                                                    stored_data[i].get_version() + 2,
                                                    generate_random_vec_u8(10),
                                                    stored_data[i].get_owner_keys().clone(),
                                                    vec![],
                                                    Some(client.signing_private_key())));
        let data = Data::StructuredData(sd);
        match unwrap_option!(client.delete(data), "") {
            ResponseMessage { content: ResponseContent::DeleteSuccess( .. ), .. } => {}
            _ => panic!("Received unexpected response"),
        }
        let data_request = DataRequest::StructuredData(*stored_data[i].get_identifier(), stored_data[i].get_type_tag());
        match unwrap_option!(client.get(data_request), "") {
            ResponseMessage { content: ResponseContent::GetFailure { ref external_error_indicator, .. }, .. } => {
                match unwrap_result!(deserialise::<ClientError>(external_error_indicator)) {
                    ClientError::NoSuchData => {}
                    _ => panic!("Received unexpected external_error_indicator"),
                }
            }
            _ => panic!("Received unexpected response"),
        }
    }

    test_group.release();
}
