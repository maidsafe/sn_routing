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

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};

use crust::Endpoint;
use NameType;
use types;

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ConnectResponse {
    pub requester_local_endpoints: Vec<Endpoint>,
    pub requester_external_endpoints: Vec<Endpoint>,
    pub receiver_local_endpoints: Vec<Endpoint>,
    pub receiver_external_endpoints: Vec<Endpoint>,
    pub requester_id: NameType,
    pub receiver_id: NameType,
    pub receiver_fob: types::PublicId
}

impl Encodable for ConnectResponse {
    fn encode<E: Encoder>(&self, encoder: &mut E)->Result<(), E::Error> {
        CborTagEncode::new(5483_001, &(&self.requester_local_endpoints,
                                       &self.requester_external_endpoints,
                                       &self.receiver_local_endpoints,
                                       &self.receiver_external_endpoints,
                                       &self.requester_id,
                                       &self.receiver_id,
                                       &self.receiver_fob)).encode(encoder)
    }
}

impl Decodable for ConnectResponse {
    fn decode<D: Decoder>(decoder: &mut D)->Result<ConnectResponse, D::Error> {
        let _ = try!(decoder.read_u64());
        let (requester_local,
             requester_external,
             receiver_local,
             receiver_external,
             requester_id,
             receiver_id,
             receiver_fob):
                 (Vec<Endpoint>,
                  Vec<Endpoint>,
                  Vec<Endpoint>,
                  Vec<Endpoint>,
                  NameType,
                  NameType,
                  types::PublicId) = try!(Decodable::decode(decoder));
        Ok(ConnectResponse { requester_local_endpoints: requester_local,
                             requester_external_endpoints: requester_external,
                             receiver_local_endpoints: receiver_local,
                             receiver_external_endpoints: receiver_external,
                             requester_id: requester_id,
                             receiver_id: receiver_id,
                             receiver_fob: receiver_fob
                           })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use cbor;
    use test_utils::Random;

    #[test]
    fn connect_response_serialisation() {
        let obj_before: ConnectResponse = Random::generate_random();

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: ConnectResponse = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }
}
