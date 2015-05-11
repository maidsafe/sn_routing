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
use sodiumoxide::crypto;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use NameType;
use types::PublicSignKey;

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ChallengeRequest {
    pub name: NameType,  // can be my id + peer endpoint or a timestamp?
}

impl Encodable for ChallengeRequest {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        CborTagEncode::new(5483_001, &(&self.name)).encode(e)
    }
}

impl Decodable for ChallengeRequest {
    fn decode<D: Decoder>(d: &mut D)->Result<ChallengeRequest, D::Error> {
        try!(d.read_u64());
        let name = try!(Decodable::decode(d));
        Ok(ChallengeRequest { name: name })
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ChallengeResponse {
    pub name: NameType,
    pub signature: PublicSignKey,
    pub request: ChallengeRequest,
}

pub fn validate(public_sign_key: &crypto::sign::PublicKey,
                challenge_response: &ChallengeResponse) -> bool {
    true  // FIXME validation
}

impl Encodable for ChallengeResponse {
    fn encode<E: Encoder>(&self, encoder: &mut E)->Result<(), E::Error> {
        CborTagEncode::new(5483_001, &(&self.name,
                                       &self.signature,
                                       &self.request,)).encode(encoder)
    }
}

impl Decodable for ChallengeResponse {
    fn decode<D: Decoder>(d: &mut D)->Result<ChallengeResponse, D::Error> {
        try!(d.read_u64());
        let (name, signature, request) = try!(Decodable::decode(d));
        Ok(ChallengeResponse { name: name,  signature: signature, request: request })
    }
}

#[cfg(test)]
mod test {
    use cbor;
    use super::*;
    use NameType;
    use test_utils::Random;

    #[test]
    fn challenge_validation() {
        let orginal_request = ChallengeRequest{ name: Random::generate_random() };

        // serialise
        let mut encoded_request = cbor::Encoder::from_memory();
        encoded_request.encode(&[&orginal_request]).unwrap();

        // parse
         let mut decoded_request = cbor::Decoder::from_bytes(encoded_request.as_bytes());
         let request: ChallengeRequest = decoded_request.decode().next().unwrap().unwrap();
         assert_eq!(orginal_request, request);

         // response
        let orginal_response = ChallengeResponse{ name: Random::generate_random(),
                                                  signature: Random::generate_random(),
                                                  request: request };
        // serialise response
        let mut encoded_response = cbor::Encoder::from_memory();
        encoded_response.encode(&[&orginal_response]).unwrap();

        // parse
         let mut decoded_response = cbor::Decoder::from_bytes(encoded_request.as_bytes());
         let response: ChallengeResponse = decoded_response.decode().next().unwrap().unwrap();
         assert_eq!(orginal_response, response);

        // let mut e = cbor::Encoder::from_memory();
        // e.encode(&[&obj_before]).unwrap();

        // let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        // let obj_after: ConnectRequest = d.decode().next().unwrap().unwrap();

        // assert_eq!(obj_before, obj_after);
    }
}
