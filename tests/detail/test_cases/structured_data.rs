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
use routing::{Data, DataRequest, ResponseContent, ResponseMessage, StructuredData};
use xor_name::XorName;

pub fn test() {
    println!("Running StructuredData test");

    let mut client1 = Client::new();
    let mut client2 = Client::new();

    let data = Data::StructuredData(unwrap_result!(
            StructuredData::new(1,
                                rand::random::<XorName>(),
                                0,
                                generate_random_vec_u8(10),
                                vec![client1.signing_public_key()],
                                vec![],
                                Some(client1.signing_private_key()))));

    match unwrap_option!(client1.put(data.clone()), "") {
        ResponseMessage { content: ResponseContent::PutFailure { .. }, .. } => {
            println!("Received expected response.");
        }
        _ => panic!("Received unexpected response."),
    }

    create_account(&mut client1);

    let sd = unwrap_result!(StructuredData::new(1,
                                                rand::random::<XorName>(),
                                                0,
                                                generate_random_vec_u8(10),
                                                vec![client1.signing_public_key()],
                                                vec![],
                                                Some(client1.signing_private_key())));
    let data = Data::StructuredData(sd.clone());

    match unwrap_option!(client1.put(data.clone()), "") {
        ResponseMessage { content: ResponseContent::PutSuccess(..), .. } => {
            println!("Received expected response.");
        }
        _ => panic!("Received unexpected response."),
    }

    let data_request = DataRequest::StructuredData(sd.get_identifier().clone(), sd.get_type_tag());

    match unwrap_option!(client1.get(data_request.clone()), "") {
        ResponseMessage { content: ResponseContent::GetSuccess(response_data, _), .. } => {
            assert_eq!(data, response_data);
            println!("Received expected response.");
        }
        _ => panic!("Received unexpected response."),
    }

    match unwrap_option!(client2.get(data_request), "") {
        ResponseMessage { content: ResponseContent::GetSuccess(response_data, _), .. } => {
            assert_eq!(data, response_data);
            println!("Received expected response.");
        }
        _ => panic!("Received unexpected response."),
    }

    let data_request = DataRequest::StructuredData(rand::random::<XorName>(), 1);

    match unwrap_option!(client1.get(data_request), "") {
        ResponseMessage { content: ResponseContent::GetFailure { .. }, .. } => {
            println!("Received expected response.");
        }
        _ => panic!("Received unexpected response."),
    }

    let sd = unwrap_result!(StructuredData::new(sd.get_type_tag(),
                                                sd.get_identifier().clone(),
                                                sd.get_version() + 1,
                                                generate_random_vec_u8(10),
                                                sd.get_owner_keys().clone(),
                                                vec![],
                                                Some(client2.signing_private_key())));
    let data = Data::StructuredData(sd.clone());

    match client2.post(data.clone()) {
        None => println!("Received expected response."),
        _ => panic!("Received unexpected response."),
    }

    let sd = unwrap_result!(StructuredData::new(sd.get_type_tag(),
                                                sd.get_identifier().clone(),
                                                sd.get_version(),
                                                generate_random_vec_u8(10),
                                                sd.get_owner_keys().clone(),
                                                vec![],
                                                Some(client1.signing_private_key())));
    let data = Data::StructuredData(sd.clone());

    match unwrap_option!(client1.post(data.clone()), "") {
        ResponseMessage { content: ResponseContent::PostSuccess( .. ), .. } => {
            println!("Received expected response.");
        }
        _ => panic!("Received unexpected response."),
    }

    let data_request = DataRequest::StructuredData(sd.get_identifier().clone(), sd.get_type_tag());

    match unwrap_option!(client1.get(data_request.clone()), "") {
        ResponseMessage { content: ResponseContent::GetSuccess(response_data, _), .. } => {
            assert_eq!(data, response_data);
            println!("Received expected response.");
        }
        _ => panic!("Received unexpected response."),
    }

    let sd = unwrap_result!(StructuredData::new(2,
                                                rand::random::<XorName>(),
                                                0,
                                                generate_random_vec_u8(10),
                                                vec![client1.signing_public_key()],
                                                vec![],
                                                Some(client1.signing_private_key())));
    let data = Data::StructuredData(sd.clone());

    match unwrap_option!(client1.post(data.clone()), "") {
        ResponseMessage { content: ResponseContent::PostFailure { .. }, .. } => {
            println!("Received expected response.");
        }
        _ => panic!("Received unexpected response."),
    }
}
