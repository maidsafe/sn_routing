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
extern crate sodiumoxide;

use sodiumoxide::crypto;

use cbor::CborTagEncode;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};

pub fn vector_as_u8_64_array(vector: Vec<u8>) -> [u8;64] {
  let mut arr = [0u8;64];
  for i in (0..64) {
    arr[i] = vector[i];
  }
  arr
}

pub fn vector_as_u8_32_array(vector: Vec<u8>) -> [u8;32] {
  let mut arr = [0u8;32];
  for i in (0..32) {
    arr[i] = vector[i];
  }
  arr
}

static GROUP_SIZE: u32 = 23;
pub static QUORUM_SIZE: u32 = 19;

pub struct DhtAddress([u8; 64]);

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub enum Authority {
  ClientManager,  // from a node in our range but not routing table
  NaeManager,     // Target (name()) is in the group we are in 
  NodeManager,    // recieved from a node in our routing table (Handle refresh here)
  ManagedNode,    // in our group and routing table
  ManagedClient,  // in our group
  Client,         // detached
  Unknown
}

impl Encodable for Authority {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    let mut authority = "";
    match *self {
      Authority::ClientManager => authority = "ClientManager",
      Authority::NaeManager => authority = "NaeManager",
      Authority::NodeManager => authority = "NodeManager",
      Authority::ManagedNode => authority = "ManagedNode",
      Authority::ManagedClient => authority = "ManagedClient",
      Authority::Client => authority = "Client",
      Authority::Unknown => authority = "Unknown",
    };
    CborTagEncode::new(5483_100, &(&authority)).encode(e)
  }
}

impl Decodable for Authority {
  fn decode<D: Decoder>(d: &mut D)->Result<Authority, D::Error> {
    try!(d.read_u64());
    let mut authority : String = String::new();
    authority = try!(Decodable::decode(d));
    match &authority[..] {
      "ClientManager" => Ok(Authority::ClientManager),
      "NaeManager" => Ok(Authority::NaeManager),
      "NodeManager" => Ok(Authority::NodeManager),
      "ManagedNode" => Ok(Authority::ManagedNode),
      "ManagedClient" => Ok(Authority::ManagedClient),
      "Client" => Ok(Authority::Client),
      _ => Ok(Authority::Unknown)
    }
  }
}

pub type Address = Vec<u8>; // [u8;64] using Vec allowing compare and clone
pub type MessageId = u32;
pub type Signature = Vec<u8>; // [u8;512] using Vec allowing compare and clone
pub type NodeAddress = Address; // (Address, NodeTag)
pub type GroupAddress = Address; // (Address, GroupTag)
pub type SerialisedMessage = Vec<u8>;

pub trait KeyGetterTraits {
  fn get_client_key(&mut self, Address);
  fn get_group_key(&mut self, GroupAddress);
}

pub trait RoutingTrait {
  fn get_name(&self)->Vec<u8>;
  fn get_owner(&self)->Vec<u8>;
  fn refresh(&self)->bool;
  fn merge(&self, &Vec<AccountTransferInfo>) -> Option<AccountTransferInfo>;
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct PublicKey {
  pub public_key : Vec<u8> // Vec form of crypto::asymmetricbox::PublicKey which is an array
}

impl PublicKey {
  pub fn get_public_key(&self) -> crypto::sign::PublicKey {
    crypto::sign::PublicKey(vector_as_u8_32_array(self.public_key.clone()))
  }
}

impl Encodable for PublicKey {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_000, &(&self.public_key)).encode(e)
  }
}

impl Decodable for PublicKey {
  fn decode<D: Decoder>(d: &mut D)->Result<PublicKey, D::Error> {
    try!(d.read_u64());
    let public_key = try!(Decodable::decode(d));
    Ok(PublicKey { public_key: public_key })
  }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct PublicPmid {
  public_key: PublicKey,
  validation_token: Signature
}

impl Encodable for PublicPmid {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_001, &(&self.public_key, &self.validation_token)).encode(e)
  }
}

impl Decodable for PublicPmid {
  fn decode<D: Decoder>(d: &mut D)->Result<PublicPmid, D::Error> {
    try!(d.read_u64());
    let (public_key, validation_token) = try!(Decodable::decode(d));
    Ok(PublicPmid { public_key: public_key, validation_token: validation_token })
  }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct EndPoint {
  pub ip_addr : Vec<u8>,
  pub socket : u32,
}

impl Encodable for EndPoint {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_001, &(&self.ip_addr, &self.socket)).encode(e)
  }
}

impl Decodable for EndPoint {
  fn decode<D: Decoder>(d: &mut D)->Result<EndPoint, D::Error> {
    try!(d.read_u64());
    let (ip_addr, socket) = try!(Decodable::decode(d));
    Ok(EndPoint { ip_addr: ip_addr, socket: socket })
  }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct AccountTransferInfo {
  pub name : Vec<u8>
}

impl Encodable for AccountTransferInfo {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_000, &(&self.name)).encode(e)
  }
}

impl Decodable for AccountTransferInfo {
  fn decode<D: Decoder>(d: &mut D)->Result<AccountTransferInfo, D::Error> {
    try!(d.read_u64());
    let name = try!(Decodable::decode(d));
    Ok(AccountTransferInfo { name: name })
  }
}

impl RoutingTrait for AccountTransferInfo {
  fn get_name(&self)->Vec<u8> { self.name.clone() }
  fn get_owner(&self)->Vec<u8> { Vec::<u8>::new() } // TODO owner
  fn refresh(&self)->bool { true } // TODO is this an account transfer type

   // TODO how do we merge these
  fn merge(&self, _ : &Vec<AccountTransferInfo>) -> Option<AccountTransferInfo> { None }
}

/// Address of the source of the message
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct SourceAddress {
  pub from_node : Address,
  pub from_group : Address,
  pub reply_to : Address
}

impl Encodable for SourceAddress {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_102 , &(&self.from_node, &self.from_group, &self.reply_to)).encode(e)
  }
}

impl Decodable for SourceAddress {
  fn decode<D: Decoder>(d: &mut D)->Result<SourceAddress, D::Error> {
    try!(d.read_u64());
    let (from_node, from_group, reply_to) = try!(Decodable::decode(d));
    Ok(SourceAddress { from_node: from_node, from_group: from_group, reply_to: reply_to })
  }
}

/// Address of the destination of the message
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct DestinationAddress {
  pub dest : Address,
  pub reply_to : Address
}

impl Encodable for DestinationAddress {
  fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
    CborTagEncode::new(5483_101, &(&self.dest, &self.reply_to)).encode(e)
  }
}

impl Decodable for DestinationAddress {
  fn decode<D: Decoder>(d: &mut D)->Result<DestinationAddress, D::Error> {
    try!(d.read_u64());
    let (dest, reply_to) = try!(Decodable::decode(d));
    Ok(DestinationAddress { dest: dest, reply_to: reply_to })
  }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub enum MessageTypeTag {
  Connect,
  ConnectResponse,
  FindGroup,
  FindGroupResponse,
  GetData,
  GetDataResponse,
  GetClientKey,
  GetClientKeyResponse,
  GetGroupKey,
  GetGroupKeyResponse,
  Post,
  PostResponse,
  PutData,
  PutDataResponse,
  PutKey,
  AccountTransfer
}


#[cfg(test)]
#[allow(deprecated)]
mod test {
  extern crate cbor;
  use super::*;
  use std::rand;
  use rustc_serialize::{Decodable, Encodable};

  pub fn generate_address() -> Vec<u8> {
    let mut address: Vec<u8> = vec![];
    for _ in (0..64) {
      address.push(rand::random::<u8>());
    }
    address
  }

  fn test_object<T>(obj_before : T) where T: for<'a> Encodable + Decodable + Eq {
    let mut e = cbor::Encoder::from_memory();
    e.encode(&[&obj_before]).unwrap();
    let mut d = cbor::Decoder::from_bytes(e.as_bytes());
    let obj_after: T = d.decode().next().unwrap().unwrap();
    assert_eq!(obj_after == obj_before, true)
  }

  #[test]
  fn test_authority() {
    test_object(Authority::ClientManager);
    test_object(Authority::NaeManager);
    test_object(Authority::NodeManager);
    test_object(Authority::ManagedNode);
    test_object(Authority::Client);
    test_object(Authority::Unknown);
  }

  #[test]
  fn test_destination_address() {
    test_object(DestinationAddress { dest: generate_address(), reply_to: generate_address() });
  }

  #[test]
  fn test_source_address() {
    test_object(SourceAddress { from_node : generate_address(),
                                from_group : generate_address(),
                                reply_to: generate_address() });
  }
}
