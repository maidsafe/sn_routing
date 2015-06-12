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

#![allow(unused_assignments)]

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use sendable::Sendable;

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Refresh<T> where T: Sendable + Encodable + Decodable {
    payload: T,
}

impl<T> Encodable for Refresh<T> where T: Sendable + Encodable + Decodable {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        CborTagEncode::new(5483_001, &(self.payload)).encode(e)
    }
}

impl<T> Decodable for Refresh<T> where T: Sendable + Encodable + Decodable {
    fn decode<D: Decoder>(d: &mut D)->Result<Refresh<T>, D::Error> {
        try!(d.read_u64());
        let payload = try!(Decodable::decode(d));
        Ok(Refresh { payload: payload })
    }
}

