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
pub struct ConnectResponse {
  pub requester_local : types::EndPoint,
  pub requester_external : types::EndPoint,
  pub receiver_local : types::EndPoint,
  pub receiver_external : types::EndPoint,
  pub requester_id : types::Address,
  pub receiver_id : types::Address,
  pub receiver_fob : types::PublicPmid
}

impl Encodable for ConnectResponse {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_001, &(&self.requester_local, &self.requester_external,
                                   &self.receiver_local, &self.receiver_external,
                                   &self.requester_id, &self.receiver_id, &self.receiver_fob)).encode(e)
  }
}

impl Decodable for ConnectResponse {
  fn decode<D: Decoder>(d: &mut D)->Result<ConnectResponse, D::Error> {
    try!(d.read_u64());
    let (requester_local, requester_external, receiver_local, receiver_external,
         requester_id, receiver_id, receiver_fob) = try!(Decodable::decode(d));
    Ok(ConnectResponse { requester_local: requester_local, requester_external: requester_external,
                         receiver_local: receiver_local, receiver_external: receiver_external,
                         requester_id: requester_id, receiver_id: receiver_id, receiver_fob: receiver_fob})
  }
}
