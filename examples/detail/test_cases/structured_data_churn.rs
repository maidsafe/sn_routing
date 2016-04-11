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
use safe_network_common::client_errors::GetError;
use xor_name::XorName;

pub fn test(request_count: u32) {
    let mut test_group = TestGroup::new("StructuredData churn test");

    let mut client = Client::create_account();
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
        trace!("Putting StructuredData {} - {}", i, sd.name());
        let data = Data::Structured(sd.clone());
        assert!(client.put(data).is_ok());
        stored_data.push(sd);
    }

    for (i, stored_item) in stored_data.iter().enumerate() {
        test_group.start_case(&format!("Get StructuredData {}", i));
        let data_request = DataRequest::Structured(*stored_item.get_identifier(),
                                                   stored_item.get_type_tag());
        trace!("Getting StructuredData {} - {}", i, stored_item.name());
        assert_eq!(Data::Structured(stored_item.clone()),
                   unwrap_result!(client.get(data_request)));
    }

    for (i, stored_item) in stored_data.iter_mut().enumerate() {
        test_group.start_case(&format!("Post StructuredData {}", i));
        let sd = unwrap_result!(StructuredData::new(stored_item.get_type_tag(),
                                                    *stored_item.get_identifier(),
                                                    stored_item.get_version() + 1,
                                                    generate_random_vec_u8(10),
                                                    stored_item.get_owner_keys().clone(),
                                                    vec![],
                                                    Some(client.signing_private_key())));
        trace!("Posting StructuredData {} - {}", i, stored_item.name());
        let data = Data::Structured(sd.clone());
        assert!(client.post(data).is_ok());
        *stored_item = sd;
    }

    for (i, stored_item) in stored_data.iter().enumerate() {
        test_group.start_case(&format!("Get updated StructuredData {}", i));
        let data_request = DataRequest::Structured(*stored_item.get_identifier(),
                                                   stored_item.get_type_tag());
        trace!("Getting updated StructuredData {} - {}",
               i,
               stored_item.name());
        assert_eq!(Data::Structured(stored_item.clone()),
                   unwrap_result!(client.get(data_request)));
    }

    for (i, stored_item) in stored_data.iter().enumerate() {
        test_group.start_case(&format!("Delete StructuredData {}", i));
        trace!("Deleting StructuredData {} - {}", i, stored_item.name());
        let sd = unwrap_result!(StructuredData::new(stored_item.get_type_tag(),
                                                    *stored_item.get_identifier(),
                                                    stored_item.get_version() + 1,
                                                    generate_random_vec_u8(10),
                                                    stored_item.get_owner_keys().clone(),
                                                    vec![],
                                                    Some(client.signing_private_key())));
        let data = Data::Structured(sd);
        assert!(client.delete(data).is_ok());

        let data_request = DataRequest::Structured(*stored_item.get_identifier(),
                                                   stored_item.get_type_tag());
        match client.get(data_request) {
            Ok(result) => panic!("Received unexpected response {:?}", result),
            // structured_data_manager hasn't implemented a proper external_error_indicator
            Err(GetError::NoSuchData) => {}
            Err(err) => panic!("Received unexpected err {:?}", err),
        }
    }

    test_group.release();
}
