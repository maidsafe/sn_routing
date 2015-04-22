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

use types;

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ConnectSuccess {
  pub peer_id   : types::DhtId,
  pub peer_fob : types::PublicPmid
}

impl Encodable for ConnectSuccess {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
      CborTagEncode::new(5483_001, &(&self.peer_id,
                                     &self.peer_fob)).encode(e)
  }
}

impl Decodable for ConnectSuccess {
  fn decode<D: Decoder>(d: &mut D)->Result<ConnectSuccess, D::Error> {
      use types::DhtId;

    try!(d.read_u64());

    let (peer_id, peer_fob): (DhtId, types::PublicPmid) = try!(Decodable::decode(d));

    Ok(ConnectSuccess { peer_id: peer_id,
                        peer_fob: peer_fob})
  }
}

#[cfg(test)]
mod test {
    extern crate cbor;

    use super::*;
    use test_utils::Random;

    #[test]
    fn connect_success_serialisation() {
        let obj_before : ConnectSuccess = Random::generate_random();

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: ConnectSuccess = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }
}
