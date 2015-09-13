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
pub mod test {

    // TODO: Use IPv6 and non-TCP
    pub fn random_endpoint() -> ::crust::Endpoint {
        ::crust::Endpoint::Tcp(::std::net::SocketAddr::V4(::std::net::SocketAddrV4::new(
            ::std::net::Ipv4Addr::new(::rand::random::<u8>(),
                                      ::rand::random::<u8>(),
                                      ::rand::random::<u8>(),
                                      ::rand::random::<u8>()),
            ::rand::random::<u16>())))
    }

    pub fn random_endpoints() -> Vec<::crust::Endpoint> {
        use rand::distributions::IndependentSample;
        let range = ::rand::distributions::Range::new(1, 10);
        let mut rng = ::rand::thread_rng();
        let count = range.ind_sample(&mut rng);
        let mut endpoints = vec![];
        for _ in 0..count {
            endpoints.push(random_endpoint());
        }
        endpoints
    }

    impl super::super::random_trait::Random for ::messages::ConnectRequest {
            fn generate_random() -> ::messages::ConnectRequest {
                ::messages::ConnectRequest {
                    local_endpoints: random_endpoints(),
                    external_endpoints: random_endpoints(),
                    requester_fob: super::super::random_trait::Random::generate_random(),
                }
            }
    }

    impl super::super::random_trait::Random for ::messages::ConnectResponse {
            fn generate_random() -> ::messages::ConnectResponse {
                ::messages::ConnectResponse {
                    local_endpoints: random_endpoints(),
                    external_endpoints: random_endpoints(),
                    receiver_fob: super::super::random_trait::Random::generate_random(),
                }
            }
    }
}
