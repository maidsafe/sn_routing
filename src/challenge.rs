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
use NameType;

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Challenge {
  pub challenge: Vec<u8>,  // can be my id + peer endpoint ?
}

impl Encodable for Challenge {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_001, &(&self.challenge)).encode(e)
  }
}

impl Decodable for Challenge {
  fn decode<D: Decoder>(d: &mut D)->Result<Challenge, D::Error> {
    try!(d.read_u64());
    let challenge = try!(Decodable::decode(d));
    Ok(Challenge { challenge: challenge })
  }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ChallengeResponse {
  pub name : NameType,
  pub challenge_response: Vec<u8>,
}

pub fn validate(challenge: &Challenge, challenge_response: &ChallengeResponse) -> bool {
    true  // FIXME validation
}


impl Encodable for ChallengeResponse {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_001, &(&self.name, &self.challenge_response)).encode(e)
  }
}

impl Decodable for ChallengeResponse {
  fn decode<D: Decoder>(d: &mut D)->Result<ChallengeResponse, D::Error> {
    try!(d.read_u64());
    let (name, challenge_response) = try!(Decodable::decode(d));
    Ok(ChallengeResponse { name: name,  challenge_response: challenge_response})
  }
}

#[cfg(test)]
mod test {
    use super::*;
    use cbor;
    use test_utils::Random;

    #[test]
    fn challenge_validation() {
        let challenge : Challenge = Random::generate_random();

        // let mut e = cbor::Encoder::from_memory();
        // e.encode(&[&obj_before]).unwrap();

        // let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        // let obj_after: ConnectRequest = d.decode().next().unwrap().unwrap();

        // assert_eq!(obj_before, obj_after);
    }
}