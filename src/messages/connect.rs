// Copyright 2015 MaidSafe.net limited
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe
// Software.

#![allow(unused_assignments)]

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};

use types;

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ConnectRequest {
  pub local : types::EndPoint,
  pub external : types::EndPoint,
  pub request_id : types::DhtId,
  pub receiver_id : types::DhtId,
  pub requester_fob : types::PublicPmid
}

impl ConnectRequest {
    pub fn generate_random() -> ConnectRequest {
        ConnectRequest {
            local: types::EndPoint::generate_random(),
            external: types::EndPoint::generate_random(),
            request_id: types::DhtId::generate_random(),
            receiver_id: types::DhtId::generate_random(),
            requester_fob: types::PublicPmid::generate_random(),
        }
    }
}

impl Encodable for ConnectRequest {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_001, &(&self.local, &self.external, &self.request_id,
                                   &self.receiver_id, &self.requester_fob)).encode(e)
  }
}

impl Decodable for ConnectRequest {
  fn decode<D: Decoder>(d: &mut D)->Result<ConnectRequest, D::Error> {
    try!(d.read_u64());
    let (local, external, request_id, receiver_id, requester_fob) = try!(Decodable::decode(d));
    Ok(ConnectRequest { local: local, external: external, request_id: request_id,
                        receiver_id: receiver_id, requester_fob: requester_fob})
  }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn connect_request_serialisation() {
        let obj_before = ConnectRequest::generate_random();

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: ConnectRequest = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }
}
