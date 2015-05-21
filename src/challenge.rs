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
use sodiumoxide::crypto;
use NameType;
use utils::decode;

#[derive(Debug, Eq, PartialEq)]
pub struct ChallengeRequest {
    pub name: NameType,  // can be my id + peer endpoint or a timestamp?
}

impl Encodable for ChallengeRequest {
    fn encode<E: Encoder>(&self, encoder: &mut E)->Result<(), E::Error> {
        CborTagEncode::new(5483_001, &(&self.name)).encode(encoder)
    }
}

impl Decodable for ChallengeRequest {
    fn decode<D: Decoder>(decoder: &mut D)->Result<ChallengeRequest, D::Error> {
        try!(decoder.read_u64());
        let name = try!(Decodable::decode(decoder));
        Ok(ChallengeRequest { name: name })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ChallengeResponse {
    pub name: NameType,
    pub signature: Vec<u8>,
    pub request: ChallengeRequest,
}

pub fn validate(public_sign_key: &crypto::sign::PublicKey,
                challenge_response: &ChallengeResponse) -> bool {
    match crypto::sign::verify(&challenge_response.signature, &public_sign_key) {
        Some(x) => {
            match decode::<ChallengeRequest>(&x) {
                Err(_) => false,
                Ok(request) => challenge_response.request == request,
            }
        },
        None => false
    }
}

impl Encodable for ChallengeResponse {
    fn encode<E: Encoder>(&self, encoder: &mut E)->Result<(), E::Error> {
        CborTagEncode::new(5483_001, &(&self.name,
                                       &self.signature,
                                       &self.request,)).encode(encoder)
    }
}

impl Decodable for ChallengeResponse {
    fn decode<D: Decoder>(decoder: &mut D)->Result<ChallengeResponse, D::Error> {
        try!(decoder.read_u64());
        let (name, signature, request) = try!(Decodable::decode(decoder));
        Ok(ChallengeResponse { name: name, signature: signature, request: request })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sodiumoxide::crypto;
    use test_utils::Random;
    use utils::{decode, encode};

    #[test]
    fn challenge_validation() {
        let orginal_request = ChallengeRequest{ name: Random::generate_random() };

        // serialise
        let encoded_request = encode(&orginal_request).unwrap();

        // parse
        let request = decode::<ChallengeRequest>(&encoded_request).unwrap();
        assert_eq!(orginal_request, request);

        // response
        let (pub_sign_key, sec_sign_key) = crypto::sign::gen_keypair();
        let signature: Vec<u8> = crypto::sign::sign(&encoded_request, &sec_sign_key);
        let orginal_response = ChallengeResponse{ name: Random::generate_random(),
                                                  signature: signature,
                                                  request: request };

        // serialise response
        let encoded_response = encode(&orginal_response).unwrap();

        // parse
        let response = decode::<ChallengeResponse>(&encoded_response).unwrap();
        assert_eq!(orginal_response, response);

        // validate
        assert!(validate(&pub_sign_key, &response));

        // invalid response using different sign key
        let (other_pub_sign_key, other_sec_sign_key) = crypto::sign::gen_keypair();
        let other_signature = crypto::sign::sign(&encoded_request, &other_sec_sign_key);
        let invalid_response = ChallengeResponse{ name: Random::generate_random(),
                                                  signature: other_signature,
                                                  request: orginal_request };

        // validate invalid_response
        assert!(!validate(&pub_sign_key, &invalid_response));
    }
}
