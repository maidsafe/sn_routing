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
pub struct Refresh {
    pub type_tag: u64,
    // This is a redundant information as the header contains it too, but
    // we can't trust the header as it is not signed. TODO: Would be nice
    // if we sent the information only once.
    pub from_group: NameType,
    pub payload: Vec<u8>,
}

impl Encodable for Refresh {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        // For some strange reason we can't put the `type_tag` at
        // the beginning of the tripple because it confuses the CBOR
        // parser.
        CborTagEncode::new(5483_001,
                           &(&self.from_group, &self.type_tag, &self.payload)).encode(e)
    }
}

impl Decodable for Refresh {
    fn decode<D: Decoder>(d: &mut D)->Result<Refresh, D::Error> {
        try!(d.read_u64());
        let (from_group, type_tag, payload) = try!(Decodable::decode(d));
        Ok(Refresh { type_tag: type_tag, from_group: from_group, payload: payload })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use cbor;
    use test_utils::Random;

    #[test]
    fn refresh_message() {
        let obj_before: Refresh = Random::generate_random();

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: Refresh = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }
}
