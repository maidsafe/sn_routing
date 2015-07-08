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

use types;
use NameType;
use authority::Authority;

/// Header of various message types used on routing level
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct MessageHeader {
    pub message_id: types::MessageId,
    pub destination: types::DestinationAddress,
    pub source: types::SourceAddress,
    pub authority: Authority
}

impl Encodable for MessageHeader {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        CborTagEncode::new(5483_004,
                           &(&self.message_id, &self.destination, &self.source,
                             &self.authority)).encode(e)
    }
}

impl Decodable for MessageHeader {
    fn decode<D: Decoder>(d: &mut D)->Result<MessageHeader, D::Error> {
        try!(d.read_u64());
        let (message_id, destination, source, authority) = try!(Decodable::decode(d));
        Ok(MessageHeader{ message_id : message_id, destination : destination,
            source : source, authority : authority })
    }
}

impl MessageHeader {
    pub fn new(message_id : types::MessageId,
               destination : types::DestinationAddress,
               source : types::SourceAddress,
               authority : Authority) -> MessageHeader {
        MessageHeader {
            message_id : message_id, destination : destination,
            source : source, authority : authority
        }
    }

    pub fn message_id(&self) -> types::MessageId {
        self.message_id
    }

    pub fn from_node(&self) -> NameType {
        self.source.from_node.clone()
    }

    pub fn from_group(&self) -> Option<NameType> {
        self.source.from_group.clone()
    }

    pub fn is_from_group(&self) -> bool {
        self.source.from_group.is_some()
    }

    pub fn from(&self) -> NameType {
        match self.from_group() {
            Some(address) => address,
            None => self.from_node()
        }
    }

    pub fn send_to(&self) -> types::DestinationAddress {
        types::DestinationAddress {
            dest: match self.source.reply_to.clone() {
                       Some(reply_to) => reply_to,
                       None => match self.source.from_group.clone() {
                           Some(group_name) => group_name,
                           None => self.source.from_node.clone()
                       }
            },
            relay_to: self.source.relayed_for.clone()
        }
    }

    // FIXME: add from_authority to filter value
    pub fn get_filter(&self) -> types::FilterType {
        (self.source.from_node.clone(), self.message_id, self.destination.dest.clone())
    }

    pub fn from_authority(&self) -> Authority {
        self.authority.clone()
    }

    pub fn set_relay_name(&mut self, reply_to: &NameType, relay_for: &NameType) {
        self.source.reply_to = Some(reply_to.clone());
        self.source.relayed_for = Some(relay_for.clone());
    }

    /// This creates a new header for Action::SendOn. It clones all the fields,
    /// and then mutates the destination and source accordingly.
    /// Authority is changed at this point as this method is called after
    /// the interface has processed the message.
    /// Note: this is not for XOR-forwarding; then the header is preserved!
    pub fn create_send_on(&self, our_name : &NameType, our_authority : &Authority,
                          destination : &NameType) -> MessageHeader {
        // implicitly preserve all non-mutated fields.
        let mut send_on_header = self.clone();
        send_on_header.source = types::SourceAddress {
            from_node : our_name.clone(),
            from_group : Some(self.destination.dest.clone()),
            reply_to : self.source.reply_to.clone(),
            relayed_for : self.source.relayed_for.clone()
        };
        send_on_header.destination = types::DestinationAddress {
            dest : destination.clone(),
            relay_to : self.destination.relay_to.clone()
        };
        send_on_header.authority = our_authority.clone();
        send_on_header
    }

    /// This creates a new header for Action::Reply. It clones all the fields,
    /// and then mutates the destination and source accordingly.
    /// Authority is changed at this point as this method is called after
    /// the interface has processed the message.
    /// Note: this is not for XOR-forwarding; then the header is preserved!
    pub fn create_reply(&self, our_name : &NameType, our_authority : &Authority)
                        -> MessageHeader {
        // implicitly preserve all non-mutated fields.
        let mut reply_header = self.clone();
        reply_header.source = types::SourceAddress {
            from_node : our_name.clone(),
            from_group : Some(self.destination.dest.clone()),
            reply_to : None,
            relayed_for: None
        };
        reply_header.destination = types::DestinationAddress {
            dest : match self.source.reply_to.clone() {
                       Some(reply_to) => reply_to,
                       None => match self.source.from_group.clone() {
                           Some(group_name) => group_name,
                           None => self.source.from_node.clone()
                       }
                   },
            relay_to : self.source.relayed_for.clone()
        };
        reply_header.authority = our_authority.clone();
        reply_header
    }
}
/*
#[cfg(test)]
#[allow(deprecated)]
mod test {
    use super::*;
    use rand::random;
    use rustc_serialize::{Decodable, Encodable};
    use types;
    use cbor;
    use test_utils::Random;
    use authority::Authority;

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
            destination : types::DestinationAddress{ dest: Random::generate_random(), relay_to: None },
            source : types::SourceAddress { from_node : Random::generate_random(),
                                            from_group : None, reply_to: None, relayed_for: None },
            authority : Authority::ManagedNode });
    }
} */
