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

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};

use types;
use NameType;

/// Header of various message types used on routing level
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct MessageHeader {
    pub message_id: types::MessageId,
    pub destination: types::DestinationAddress,
    pub source: types::SourceAddress,
    pub authority: types::Authority,
    pub signature: Option<types::Signature>,
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
               signature : Option<types::Signature>) -> MessageHeader {
        MessageHeader {
            message_id : message_id, destination : destination,
            source : source, authority : authority, signature : signature
        }
    }

    pub fn message_id(&self) -> types::MessageId {
        self.message_id
    }

    pub fn from_node(&self) -> NameType {
        self.source.from_node.clone()
    }

    pub fn from_group(&self) -> Option<NameType> {
        if self.source.from_group.is_some() {
            self.source.from_group.clone()
        } else {
            None
        }
    }

    pub fn is_from_group(&self) -> bool {
        if self.source.from_group.is_some() {
            true
        } else {
            false
        }
    }

    pub fn is_relayed(&self) -> bool {
        if self.source.reply_to.is_some() {
            true
        } else {
            false
        }
    }

    pub fn reply_to(&self) -> Option<NameType> {
        if self.source.reply_to.is_some() {
            self.source.reply_to.clone()
        } else {
            None
        }
    }

    pub fn from(&self) -> NameType {
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
                reply_to : None
            }
        }
    }

    pub fn get_filter(&self) -> types::FilterType {
        (self.source.from_node.clone(), self.message_id)
    }

    pub fn from_authority(&self) -> types::Authority {
        self.authority.clone()
    }

    pub fn get_signature(&self) -> Option<types::Signature> {
        self.signature.clone()
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod test {
    use super::*;
    use rand::random;
    use rustc_serialize::{Decodable, Encodable};
    use types;
    use cbor;
    use NameType;

    pub fn generate_u8_64() -> Vec<u8> {
        let mut u8_64: Vec<u8> = vec![];
        for _ in (0..64) {
            u8_64.push(random::<u8>());
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
            message_id : random::<u32>(),
            destination : types::DestinationAddress{dest: NameType::generate_random(), reply_to: None },
            source : types::SourceAddress { from_node : NameType::generate_random(),
            from_group : None,
            reply_to: None },
            authority : types::Authority::ManagedNode,
            signature : Some(types::Signature{ signature: generate_u8_64() }) });
    }
}
