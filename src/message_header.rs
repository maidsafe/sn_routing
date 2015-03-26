// Copyright 2015 MaidSafe.net limited
//
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
//
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
//
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe Software.

extern crate sodiumoxide;

use sodiumoxide::crypto;
use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};

use types;

/// Header of various message types used on routing level
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct MessageHeader {
  message_id : types::MessageId,
  destination : types::DestinationAddress,
  source : types::SourceAddress,
  authority : types::Authority,
  signature : types::Signature
}

impl Encodable for MessageHeader {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_004,
                    &(&self.message_id, &self.destination, &self.source,
                             &self.authority, &self.signature)).encode(e)
  }
}

impl Decodable for MessageHeader {
  fn decode<D: Decoder>(d: &mut D)->Result<MessageHeader, D::Error> {
    try!(d.read_u64());
    let (message_id, destination, source, authority, signature) = try!(Decodable::decode(d));
    Ok(MessageHeader{ message_id : message_id, destination : destination,
                      source : source, authority : authority, signature : signature })
  }
}

impl MessageHeader {
  pub fn new(message_id : types::MessageId,
             destination : types::DestinationAddress,
             source : types::SourceAddress,
             authority : types::Authority,
             signature : types::Signature) -> MessageHeader {
    if source.from_node.len() == 64 {
      MessageHeader {
        message_id : message_id, destination : destination,
        source : source, authority : authority, signature : signature
      }
    } else {
      panic!("incorrect input for MessageHeader")
    }
  }

  pub fn message_id(&self) -> types::MessageId {
    self.message_id
  }

  pub fn from_node(&self) -> types::Address {
    self.source.from_node.clone()
  }

  pub fn from_group(&self) -> Option<types::Address> {
    if self.source.from_group.len() == 64 {
      Some(self.source.from_group.clone())
    } else {
      None
    }
  }

  pub fn is_from_group(&self) -> bool {
    if self.source.from_group.len() == 64 {
      true
    } else {
      false
    }
  }

  pub fn is_relayed(&self) -> bool {
    if self.source.reply_to.len() != 64 {
      true
    } else {
      false
    }
  }

  pub fn reply_to(&self) -> Option<types::Address> {
    if self.source.reply_to.len() == 64 {
      Some(self.source.reply_to.clone())
    } else {
      None
    }
  }

  pub fn from(&self) -> types::Address {
    match self.from_group() {
      Some(address) => address,
      None => self.from_node()
    }
  }

  pub fn send_to(&self) -> types::DestinationAddress {
    if self.is_relayed() {
      types::DestinationAddress{
        dest : self.source.from_node.clone(),
        reply_to : self.source.reply_to.clone()
      }
    } else {
      types::DestinationAddress{
        dest : self.source.from_node.clone(),
        reply_to : types::Address::new()
      }
    }
  }

  pub fn get_filter(&self) -> (types::Address, types::MessageId) {
    (self.source.from_node.clone(), self.message_id)
  }

  pub fn get_signature(&self) -> crypto::sign::Signature {
    self.signature.get_signature()
  }
}

#[cfg(test)]
#[allow(deprecated)]
mod test {
  extern crate cbor;
  use super::*;
  use std::rand;
  use rustc_serialize::{Decodable, Encodable};
  use types;

  pub fn generate_u8_64() -> Vec<u8> {
    let mut u8_64: Vec<u8> = vec![];
    for _ in (0..64) {
      u8_64.push(rand::random::<u8>());
    }
    u8_64
  }

  fn test_object<T>(obj_before : T) where T: for<'a> Encodable + Decodable + Eq {
    let mut e = cbor::Encoder::from_memory();
    e.encode(&[&obj_before]).unwrap();
    let mut d = cbor::Decoder::from_bytes(e.as_bytes());
    let obj_after: T = d.decode().next().unwrap().unwrap();
    assert_eq!(obj_after == obj_before, true)
  }

  #[test]
  fn test_message_header() {
    test_object(MessageHeader {
      message_id : rand::random::<u32>(),
      destination : types::DestinationAddress{dest: generate_u8_64(), reply_to: generate_u8_64()},
      source : types::SourceAddress { from_node : generate_u8_64(),
                                      from_group : generate_u8_64(),
                                      reply_to: generate_u8_64() },
      authority : types::Authority::ManagedNode,
      signature : types::Signature{ signature: generate_u8_64() } });
  }

}
