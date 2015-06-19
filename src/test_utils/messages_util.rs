// Copyright 2015 MaidSafe.net limited.
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

use rand::{random, thread_rng};
use rand::distributions::{IndependentSample, Range};

use crust::Endpoint;
use error::ResponseError;
use messages;
use NameType;
use super::random_trait::Random;
use types::*;

// TODO: Use IPv6 and non-TCP
pub fn random_endpoint() -> Endpoint {
    use std::net::{Ipv4Addr, SocketAddrV4, SocketAddr};
    Endpoint::Tcp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(random::<u8>(),
        random::<u8>(), random::<u8>(),random::<u8>()), random::<u16>())))
}

pub fn random_endpoints() -> Vec<Endpoint> {
    let range = Range::new(1, 10);
    let mut rng = thread_rng();
    let count = range.ind_sample(&mut rng);
    let mut endpoints = vec![];
    for _ in 0..count {
        endpoints.push(random_endpoint());
    }
    endpoints
}

impl Random for messages::connect_request::ConnectRequest {
    fn generate_random() -> messages::connect_request::ConnectRequest {
        messages::connect_request::ConnectRequest {
            local_endpoints: random_endpoints(),
            external_endpoints: random_endpoints(),
            requester_id: Random::generate_random(),
            receiver_id: Random::generate_random(),
            requester_fob: Random::generate_random(),
        }
    }
}


impl Random for messages::connect_response::ConnectResponse {
    fn generate_random() -> messages::connect_response::ConnectResponse {
        use std::net::{Ipv4Addr, SocketAddrV4, SocketAddr};

        // TODO: IPv6 and non-TCP
        let random_endpoint = || -> Endpoint {
            Endpoint::Tcp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(random::<u8>(),
                                                           random::<u8>(),
                                                           random::<u8>(),
                                                           random::<u8>()),
                                             random::<u16>())))
        };

        messages::connect_response::ConnectResponse {
            requester_local_endpoints: random_endpoints(),
            requester_external_endpoints: random_endpoints(),
            receiver_local_endpoints: random_endpoints(),
            receiver_external_endpoints: random_endpoints(),
            requester_id: Random::generate_random(),
            receiver_id: Random::generate_random(),
            receiver_fob: Random::generate_random(),
            serialised_connect_request: generate_random_vec_u8(64),
            connect_request_signature: Random::generate_random()
        }
    }
}

impl Random for messages::connect_success::ConnectSuccess {
    fn generate_random() -> messages::connect_success::ConnectSuccess {
        messages::connect_success::ConnectSuccess {
            peer_id: Random::generate_random(),
            peer_fob: Random::generate_random(),
        }
    }
}

impl Random for messages::find_group::FindGroup {
    fn generate_random() -> messages::find_group::FindGroup {
        messages::find_group::FindGroup {
            requester_id: Random::generate_random(),
            target_id: Random::generate_random(),
        }
    }
}

impl Random for messages::find_group_response::FindGroupResponse {
    fn generate_random() -> messages::find_group_response::FindGroupResponse {
        let total = GROUP_SIZE as usize + 20;
        let mut vec = Vec::<PublicId>::with_capacity(total);
        for i in 0..total {
            let public_id : PublicId = Random::generate_random();
            vec.push(public_id);
        }

        messages::find_group_response::FindGroupResponse { group: vec }
    }
}

impl Random for messages::get_client_key::GetKey {
    fn generate_random() -> messages::get_client_key::GetKey {
        messages::get_client_key::GetKey {
            requester_id: Random::generate_random(),
            target_id: Random::generate_random(),
        }
    }
}

impl Random for messages::get_client_key_response::GetKeyResponse {
    fn generate_random() -> messages::get_client_key_response::GetKeyResponse {
        messages::get_client_key_response::GetKeyResponse {
            address: Random::generate_random(),
            public_sign_key: Random::generate_random(),
        }
    }
}

impl Random for messages::get_data::GetData {
    fn generate_random() -> messages::get_data::GetData {
        messages::get_data::GetData {
            requester: Random::generate_random(),
            name_and_type_id: Random::generate_random(),
        }
    }
}

impl Random for messages::get_data_response::GetDataResponse {
    fn generate_random() -> messages::get_data_response::GetDataResponse {
        messages::get_data_response::GetDataResponse {
            name_and_type_id: Random::generate_random(),
            data: Ok(generate_random_vec_u8(99)),
        }
    }
}


impl Random for messages::get_group_key::GetGroupKey {
    fn generate_random() -> messages::get_group_key::GetGroupKey {
        messages::get_group_key::GetGroupKey {
            target_id: Random::generate_random(),
        }
    }
}

impl Random for messages::get_group_key_response::GetGroupKeyResponse {
    fn generate_random() -> messages::get_group_key_response::GetGroupKeyResponse {
        let total: usize = GROUP_SIZE as usize + 7;
        let mut vec = Vec::<(NameType, PublicSignKey)>::with_capacity(total);
        for i in 0..total {
            vec.push((Random::generate_random(), Random::generate_random()));
        }
        messages::get_group_key_response::GetGroupKeyResponse {
            public_sign_keys: vec,
        }
    }
}

impl Random for messages::post::Post {
    fn generate_random() -> messages::post::Post {
        messages::post::Post {
            name: Random::generate_random(),
            data: generate_random_vec_u8(99),
        }
    }
}

impl Random for messages::put_data::PutData {
    fn generate_random() -> messages::put_data::PutData {
        messages::put_data::PutData {
            name: Random::generate_random(),
            data: generate_random_vec_u8(99),
        }
    }
}

impl Random for messages::refresh::Refresh {
    fn generate_random() -> messages::refresh::Refresh {
        messages::refresh::Refresh {
            type_tag: random(),
            from_group: Random::generate_random(),
            payload: generate_random_vec_u8(random::<usize>() % 512 + 512),
        }
    }
}

impl Random for messages::put_data_response::PutDataResponse {
     fn generate_random() -> messages::put_data_response::PutDataResponse {
         let data = if random::<bool>() {
             Ok(generate_random_vec_u8(99))
         } else {
             Err(ResponseError::NoData)
         };

         messages::put_data_response::PutDataResponse {
             name: Random::generate_random(),
             data: data,
         }
    }
}

impl Random for messages::put_public_id::PutPublicId {
    fn generate_random() -> messages::put_public_id::PutPublicId {
        let public_id : PublicId = Random::generate_random();
        messages::put_public_id::PutPublicId {
            public_id: public_id,
        }
    }
}

impl Random for messages::put_public_id_response::PutPublicIdResponse {
    fn generate_random() -> messages::put_public_id_response::PutPublicIdResponse {
        let public_id : PublicId = Random::generate_random();
        messages::put_public_id_response::PutPublicIdResponse {
            public_id: public_id,
        }
    }
}
