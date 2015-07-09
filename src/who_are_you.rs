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
use public_id::PublicId;

#[derive(RustcEncodable, RustcDecodable, Debug, Eq, PartialEq)]
pub struct WhoAreYou {
    pub nonce: u8  // FIXME: a placeholder for nonce
}
// TODO: add nonce to be signed for added security later


#[derive(Debug, Eq, PartialEq)]
pub struct IAm {
    pub public_id: PublicId,
    // FIXME: return signed nonce
}

impl Encodable for IAm {
    fn encode<E: Encoder>(&self, encoder: &mut E)->Result<(), E::Error> {
        CborTagEncode::new(5483_001, &(&self.public_id)).encode(encoder)
    }
}

impl Decodable for IAm {
    fn decode<D: Decoder>(decoder: &mut D)->Result<IAm, D::Error> {
        try!(decoder.read_u64());
        let public_id = try!(Decodable::decode(decoder));
        Ok(IAm { public_id: public_id })
    }
}

#[cfg(test)]
mod test {
    // TODO: add encode / decode test
    // TODO: add validation test
}
