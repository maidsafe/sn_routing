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
use routing::{Data, DataRequest, ImmutableData, ImmutableDataType, ResponseContent,
              ResponseMessage};
use xor_name::XorName;

pub fn test(max_get_attempts: u32) {
    let mut test_group = TestGroup::new("ImmutableData test");

    test_group.start_case("Put with no account");
    let mut client1 = Client::new();
    let data = Data::Immutable(ImmutableData::new(ImmutableDataType::Normal,
                                                  generate_random_vec_u8(1024)));
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
    match unwrap_option!(client1.put(data.clone()), "") {
        ResponseMessage { content: ResponseContent::PutSuccess(..), .. } => {}
        _ => panic!("Received unexpected response"),
    }

    test_group.start_case("Get");
    let mut data_request = DataRequest::Immutable(data.name(), ImmutableDataType::Normal);
    match unwrap_option!(get_with_retry(&mut client1, data_request.clone(), max_get_attempts),
                         "") {
        ResponseMessage { content: ResponseContent::GetSuccess(response_data, _), .. } => {
            assert_eq!(data, response_data);
        }
        _ => panic!("Received unexpected response"),
    }

    test_group.start_case("Get via different Client");
    let mut client2 = Client::new();
    // Should succeed on first attempt if previous Client was able to Get already.
    match unwrap_option!(client2.get(data_request), "") {
        ResponseMessage { content: ResponseContent::GetSuccess(response_data, _), .. } => {
            assert_eq!(data, response_data);
        }
        _ => panic!("Received unexpected response"),
    }

    test_group.start_case("Get for non-existent data");
    data_request = DataRequest::Immutable(rand::random::<XorName>(), ImmutableDataType::Normal);
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
