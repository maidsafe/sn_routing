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

use rand;

fn generate_random_authority(name: ::NameType, key: &::sodiumoxide::crypto::sign::PublicKey)
        -> ::authority::Authority {
    use rand::distributions::IndependentSample;

    let mut rng = ::rand::thread_rng();
    let range = ::rand::distributions::Range::new(0, 5);
    let index = range.ind_sample(&mut rng);

    match index {
        0 => return ::authority::Authority::ClientManager(name),
        1 => return ::authority::Authority::NaeManager(name),
        2 => return ::authority::Authority::NodeManager(name),
        3 => return ::authority::Authority::ManagedNode(name),
        4 => return ::authority::Authority::Client(name, key.clone()),
        _ => panic!("Unexpected index.")
    }
}

fn generate_random_data(public_sign_key: &::sodiumoxide::crypto::sign::PublicKey,
                        secret_sign_key: &::sodiumoxide::crypto::sign::SecretKey)
        -> ::data::Data {
    use rand::distributions::IndependentSample;

    let mut rng = ::rand::thread_rng();
    let range = ::rand::distributions::Range::new(0, 3);
    let index = range.ind_sample(&mut rng);

    match index {
        0 => {
            let structured_data =
                match ::structured_data::StructuredData::new(0, ::rand::random(), 0,
                        vec![], vec![public_sign_key.clone()], vec![], Some(&secret_sign_key)) {
                    Ok(structured_data) => structured_data,
                    Err(error) => panic!("StructuredData error: {:?}", error),
            };
            return ::data::Data::StructuredData(structured_data)
        },
        1 => {
            let type_tag = ::immutable_data::ImmutableDataType::Normal;
            let immutable_data = ::immutable_data::ImmutableData::new(
                    type_tag, ::types::generate_random_vec_u8(1025));
            return ::data::Data::ImmutableData(immutable_data)
        },
        2 => {
            let plain_data = ::plain_data::PlainData::new(
                rand::random(), ::types::generate_random_vec_u8(1025));
            return ::data::Data::PlainData(plain_data)
        },
        _ => panic!("Unexpected index.")
    }
}

/// Semi-random routing message.
// TODO Brian: Randomize Content and rename to random_routing_message.
pub fn arbitrary_routing_message(public_key: &::sodiumoxide::crypto::sign::PublicKey,
                          secret_key: &::sodiumoxide::crypto::sign::SecretKey)
        -> ::messages::RoutingMessage {
    let from_authority = generate_random_authority(rand::random(), public_key);
    let to_authority = generate_random_authority(rand::random(), public_key);
    let data = generate_random_data(public_key, secret_key);
    let content = ::messages::Content::ExternalRequest(::messages::ExternalRequest::Put(data));

    ::messages::RoutingMessage {
        from_authority: from_authority,
        to_authority: to_authority,
        content: content,
    }
}

#[cfg(test)]
pub mod test {
    use rand;

    // TODO: Use IPv6 and non-TCP
    pub fn random_socket_addr() -> ::std::net::SocketAddr {
        ::std::net::SocketAddr::V4(::std::net::SocketAddrV4::new(
            ::std::net::Ipv4Addr::new(::rand::random::<u8>(),
                                      ::rand::random::<u8>(),
                                      ::rand::random::<u8>(),
                                      ::rand::random::<u8>()),
            ::rand::random::<u16>()))
    }

    pub fn random_endpoint() -> ::crust::Endpoint {
        // TODO: Udt
        ::crust::Endpoint::Tcp(random_socket_addr())
    }

    pub fn random_connection() -> ::crust::Connection {
        let local = random_socket_addr();
        let remote = random_socket_addr();
        // TODO: Udt
        ::crust::Connection::new(::crust::Protocol::Tcp, local, remote)
    }

    pub fn random_endpoints<R: rand::Rng>(rng: &mut R) -> Vec<::crust::Endpoint> {
        use rand::distributions::IndependentSample;
        let range = ::rand::distributions::Range::new(1, 10);
        let count = range.ind_sample(rng);
        let mut endpoints = vec![];
        for _ in 0..count {
            endpoints.push(random_endpoint());
        }
        endpoints
    }

    impl rand::Rand for ::messages::ConnectRequest {
        fn rand<R: rand::Rng>(rng: &mut R) -> ::messages::ConnectRequest {
            ::messages::ConnectRequest {
                local_endpoints: random_endpoints(rng),
                external_endpoints: random_endpoints(rng),
                requester_fob: rand::random(),
            }
        }
    }

    impl rand::Rand for ::messages::ConnectResponse {
        fn rand<R: rand::Rng>(rng: &mut R) -> ::messages::ConnectResponse {
            ::messages::ConnectResponse {
                local_endpoints: random_endpoints(rng),
                external_endpoints: random_endpoints(rng),
                receiver_fob: rand::random(),
            }
        }
    }
}

