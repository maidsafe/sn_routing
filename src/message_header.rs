// Copyright 2014 MaidSafe.net limited
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

use types;

/// Header of various message types used on routing level
pub struct MessageHeader {
  message_id : types::MessageId,
  destionation : types::DestinationAddress,
  source : types::SourceAddress,
  authority : types::Authority,
  signature : types::Signature
}

impl MessageHeader {
  pub fn new(message_id : types::MessageId,
             destionation : types::DestinationAddress,
             source : types::SourceAddress,
             authority : types::Authority,
             signature : types::Signature) -> MessageHeader {
    if source.from_node.len() == 64 {
      MessageHeader {
        message_id : message_id, destionation : destionation,
        source : source, authority : authority, signature : signature
      }
    } else {
      panic!("incorrect input for MessageHeader")
    }
  }

  pub fn from_node(&self) -> types::Address {
    self.source.from_node.clone()
  }

  pub fn from_group(&self) -> Option<types::Address> {
    self.source.from_group.clone()
  }

  pub fn is_relayed(&self) -> bool {
    match self.source.reply_to {
      Some(_) => true,
      None => false
    }
  }

  pub fn reply_to(&self) -> Option<types::Address> {
    self.source.reply_to.clone()
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
        reply_to : self.reply_to()
      }
    } else {
      types::DestinationAddress{
        dest : self.source.from_node.clone(),
        reply_to : None
      }
    }
  }

  pub fn get_filter(&self) -> (types::Address, types::MessageId) {
    (self.source.from_node.clone(), self.message_id)
  }
}
