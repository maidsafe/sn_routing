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
use std::net::{SocketAddr};
use NameType;

use types;

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ConnectResponse {
  pub requester_local    : SocketAddr,
  pub requester_external : SocketAddr,
  pub receiver_local     : SocketAddr,
  pub receiver_external  : SocketAddr,
  pub requester_id       : NameType,
  pub receiver_id        : NameType,
  pub receiver_fob       : types::PublicPmid
}

impl Encodable for ConnectResponse {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    // FIXME: Implement Encodable/Decodable for SocketAddr
    let requester_local    = format!("{}", self.requester_local);
    let requester_external = format!("{}", self.requester_external);
    let receiver_local     = format!("{}", self.receiver_local);
    let receiver_external  = format!("{}", self.receiver_external);

    CborTagEncode::new(5483_001, &(&requester_local, &requester_external,
                                   &receiver_local, &receiver_external,
                                   &self.requester_id, &self.receiver_id,
                                   &self.receiver_fob)).encode(e)
  }
}

impl Decodable for ConnectResponse {
  fn decode<D: Decoder>(d: &mut D)->Result<ConnectResponse, D::Error> {
    try!(d.read_u64());
    let (requester_local, requester_external, receiver_local, receiver_external,
         requester_id, receiver_id, receiver_fob):
        (String, String, String, String, NameType, NameType, types::PublicPmid)
        = try!(Decodable::decode(d));

    let req_local    = try!(requester_local   .parse().or(Err(d.error("can't parse req_local addr"))));
    let req_external = try!(requester_external.parse().or(Err(d.error("can't parse req_external addr"))));
    let rec_local    = try!(receiver_local    .parse().or(Err(d.error("can't parse rec_local addr"))));
    let rec_external = try!(receiver_external .parse().or(Err(d.error("can't parse rec_external addr"))));

    Ok(ConnectResponse { requester_local: req_local, requester_external: req_external,
                         receiver_local: rec_local, receiver_external: rec_external,
                         requester_id: requester_id, receiver_id: receiver_id, receiver_fob: receiver_fob})
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
