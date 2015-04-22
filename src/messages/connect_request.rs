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

extern crate rand;
use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use std::net::{SocketAddr};

use types;

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ConnectRequest {
  pub local         : SocketAddr,
  pub external      : SocketAddr,
  pub requester_id  : types::DhtId,
  pub receiver_id   : types::DhtId,
  pub requester_fob : types::PublicPmid
}

impl Encodable for ConnectRequest {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
      // FIXME: Implement Encodable/Decodable for SocketAddr
      let local_str    = format!("{}", self.local);
      let external_str = format!("{}", self.external);
      CborTagEncode::new(5483_001, &(&local_str,
                                     &external_str,
                                     &self.requester_id,
                                     &self.receiver_id,
                                     &self.requester_fob)).encode(e)
  }
}

impl Decodable for ConnectRequest {
  fn decode<D: Decoder>(d: &mut D)->Result<ConnectRequest, D::Error> {
      use types::DhtId;

    try!(d.read_u64());

    let (local_str, external_str, requester_id, receiver_id, requester_fob):
        (String, String, DhtId, DhtId, types::PublicPmid) = try!(Decodable::decode(d));

    let local    = try!(local_str   .parse().or(Err(d.error("can't parse local addr"))));
    let external = try!(external_str.parse().or(Err(d.error("can't parse external addr"))));

    Ok(ConnectRequest { local: local,
                        external: external,
                        requester_id: requester_id,
                        receiver_id: receiver_id,
                        requester_fob: requester_fob})
  }
}

#[cfg(test)]
mod test {
    use super::*;
    use cbor;
    use test_utils::Random;

    #[test]
    fn connect_request_serialisation() {
        let obj_before : ConnectRequest = Random::generate_random();

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: ConnectRequest = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }
}
