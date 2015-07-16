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


#[cfg(test)]
mod test {
    use messages;
    use crust::Endpoint;
    use sodiumoxide::crypto;
    use rand::distributions::Range;
    use rand::{random, thread_rng};
    use data::*;

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

impl Random for messages::ConnectRequest {
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


impl Random for messages::ConnectResponse {
    fn generate_random() -> messages::connect_response::ConnectResponse {

        messages::connect_response::ConnectResponse {
            requester_local_endpoints: random_endpoints(),
            requester_external_endpoints: random_endpoints(),
            receiver_local_endpoints: random_endpoints(),
            receiver_external_endpoints: random_endpoints(),
            requester_id: Random::generate_random(),
            receiver_id: Random::generate_random(),
            receiver_fob: Random::generate_random(),
            serialised_connect_request: generate_random_vec_u8(64),
            connect_request_signature: crypto::sign::Signature([0; 64]),
        }
    }
}

}
