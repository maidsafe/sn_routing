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

use std::collections::HashMap;
use sodiumoxide::crypto;
use cbor;

use accumulator;
use message_header;
use NameType;
use types;
use types::RoutingTrait;
use messages::find_group_response::FindGroupResponse;
use messages::get_client_key_response::GetClientKeyResponse;
use messages::get_group_key_response::GetGroupKeyResponse;
use types::{PublicSignKey, SerialisedMessage};
use rustc_serialize::{Decodable, Encodable};

pub type ResultType = (message_header::MessageHeader,
                       types::MessageTypeTag, SerialisedMessage);

type NodeKeyType = (types::NodeAddress, types::MessageId);
type GroupKeyType = (types::GroupAddress, types::MessageId);
type NodeAccumulatorType = accumulator::Accumulator<NodeKeyType, ResultType>;
type GroupAccumulatorType = accumulator::Accumulator<GroupKeyType, ResultType>;
type KeyAccumulatorType = accumulator::Accumulator<types::GroupAddress, ResultType>;


// TODO (ben 2015-4-2): replace dynamic dispatching with static dispatching
//          https://doc.rust-lang.org/book/static-and-dynamic-dispatch.html
pub trait SendGetKeys {
  fn get_client_key(&mut self, address : NameType);
  fn get_group_key(&mut self, group_address : types::GroupAddress);
}

pub struct Sentinel<'a> {
  send_get_keys_: &'a mut (SendGetKeys + 'a),
  node_accumulator_: NodeAccumulatorType,
  group_accumulator_: GroupAccumulatorType,
  group_key_accumulator_: KeyAccumulatorType,
  node_key_accumulator_: KeyAccumulatorType,
}

impl<'a> Sentinel<'a> {
  pub fn new(send_get_keys: &'a mut SendGetKeys) -> Sentinel<'a> {
    Sentinel {
      send_get_keys_: send_get_keys,
      node_accumulator_: NodeAccumulatorType::new(types::QUORUM_SIZE as usize),
      group_accumulator_: NodeAccumulatorType::new(types::QUORUM_SIZE as usize),
      group_key_accumulator_: KeyAccumulatorType::new(types::QUORUM_SIZE as usize),
      node_key_accumulator_: KeyAccumulatorType::new(types::QUORUM_SIZE as usize)
    }
  }

  // pub fn get_send_get_keys(&'a mut self) -> &'a mut SendGetKeys { self.send_get_keys }

  pub fn add(&mut self, header: message_header::MessageHeader, type_tag: types::MessageTypeTag,
             message : types::SerialisedMessage) -> Option<ResultType> {
    match type_tag {
      types::MessageTypeTag::GetClientKeyResponse => {
        if header.is_from_group() {
          let keys = self.node_key_accumulator_.add(header.from_group().unwrap(),
                                                    (header.clone(), type_tag, message),
                                                    header.from_node());
          if keys.is_some() {
            let key = (header.from_group().unwrap(), header.message_id());
            let messages = self.node_accumulator_.get(key.clone());
            if messages.is_some() {
              let resolved = self.resolve(self.validate_node(messages.unwrap().1,
                                                             keys.unwrap().1), false);
              if resolved.is_some() {
                self.node_accumulator_.delete(key);
                return resolved;
              }
            }
          }
        }
      }
      types::MessageTypeTag::GetGroupKeyResponse => {
        if header.is_from_group() {
          let keys = self.group_key_accumulator_.add(header.from_group().unwrap(),
                                                     (header.clone(), type_tag, message),
                                                     header.from_node());
          if keys.is_some() {
            let key = (header.from_group().unwrap(), header.message_id());
            let messages = self.group_accumulator_.get(key.clone());
            if messages.is_some() {
              let resolved = self.resolve(self.validate_group(messages.unwrap().1,
                                                              keys.unwrap().1), true);
              if resolved.is_some() {
                self.group_accumulator_.delete(key);
                return resolved;
              }
            }
          }
        }
      }
      _ => {
        if header.is_from_group() {
          let key = (header.from_group().unwrap(), header.message_id());
          if !self.group_accumulator_.have_name(key.clone()) {
            self.send_get_keys_.get_group_key(header.from_group().unwrap()); };
          let messages = self.group_accumulator_.add(key.clone(),
                                                     (header.clone(), type_tag, message),
                                                     header.from_node());
          if messages.is_some() {
            let keys = self.group_key_accumulator_.get(header.from_group().unwrap());
            if keys.is_some() {
              let resolved = self.resolve(self.validate_group(messages.unwrap().1,
                                                              keys.unwrap().1), true);
              if resolved.is_some() {
                self.group_accumulator_.delete(key);
                return resolved;
              }
            }
          }
        } else {
          let key = (header.from_node(), header.message_id());
          if !self.node_accumulator_.have_name(key.clone()) {
            self.send_get_keys_.get_client_key(header.from_group().unwrap()); };
          let messages = self.node_accumulator_.add(key.clone(),
                                                    (header.clone(), type_tag, message),
                                                    header.from_node());
          if messages.is_some() {
            let keys = self.node_key_accumulator_.get(header.from_group().unwrap());
            if keys.is_some() {
              let resolved = self.resolve(self.validate_node(messages.unwrap().1,
                                                             keys.unwrap().1), false);
              if resolved.is_some() {
                self.node_accumulator_.delete(key);
                return resolved;
              }
            }
          }
        }
      }
    }
    None
  }

  fn update_key_map(key_map: &mut HashMap<NameType, Vec<PublicSignKey>>, addr: NameType, key: PublicSignKey) {
      if !key_map.contains_key(&addr) {
          key_map.insert(addr, vec![key]);
      }
      else {
          let mut public_keys = key_map.get_mut(&addr).unwrap();
          if !public_keys.contains(&key) {
              public_keys.push(key);
          }
      }
  }

  fn verify_result(response: &ResultType, pub_key: &PublicSignKey) -> Option<ResultType> {
      response.0.get_signature().and_then(|signature| {
        let is_correct = crypto::sign::verify_detached(
                           &signature.get_crypto_signature(),
                           &response.2[..],
                           &pub_key.get_crypto_public_sign_key());

        if !is_correct { return None; }
        Some(response.clone())
      })
  }

  fn validate_node(&self,
                   messages: Vec<accumulator::Response<ResultType>>,
                   keys:     Vec<accumulator::Response<ResultType>>) -> Vec<ResultType> {
      if messages.len() == 0 || keys.len() < types::QUORUM_SIZE as usize {
        return Vec::new();
      }

      let mut keys_map = HashMap::<NameType, Vec<PublicSignKey>>::new();

      for node_key in keys.iter() {
        Sentinel::decode(&node_key.value.2)
            .map(|GetClientKeyResponse{address:addr, public_sign_key:key}| {
                Sentinel::update_key_map(&mut keys_map, addr, key)
            });
      }

      // FIXME: We should take the majority of same keys and
      // if there is QUORUM_SIZE of them, use that.
      if !has_single_entry(&keys_map) { return Vec::new(); }
      let pub_key = &keys_map.iter().next().unwrap().1[0];

      messages.iter().filter_map(
          |&accumulator::Response{address:ref addr, value:ref result}|
              Sentinel::verify_result(result, pub_key))
          .collect()
  }

  fn validate_group(&self, messages:  Vec<accumulator::Response<ResultType>>,
                    keys: Vec<accumulator::Response<ResultType>>) -> Vec<ResultType> {
    if messages.len() < types::QUORUM_SIZE as usize || keys.len() < types::QUORUM_SIZE as usize {
      return Vec::<ResultType>::new();
    }
    let mut keys_map = HashMap::<NameType, Vec<PublicSignKey>>::new();
    for group_key in keys.iter() {
        Sentinel::decode(&group_key.value.2)
            .map(|GetGroupKeyResponse{target_id: target, public_sign_keys: keys}| {
                for (addr, key) in keys {
                    Sentinel::update_key_map(&mut keys_map, addr.clone(), key.clone())
                }
            });
    }

    // TODO(mmoadeli): For the time being, we assume that no invalid public is received
    for (_, pub_key_list) in keys_map.iter() {
      if pub_key_list.len() != 1 {
        panic!("Different keys returned for a single address.");
      }
    }

    let verified_messages = messages.iter().filter_map(|message| {
        keys_map.get_mut(&message.value.0.from_node())
        .and_then(|keys| {
            Sentinel::verify_result(&message.value, &keys[0])
        })
    }).collect::<Vec<_>>();

    if verified_messages.len() < types::QUORUM_SIZE as usize {
      return Vec::new()
    }

    verified_messages
  }

  fn decode<T: Decodable>(data: &SerialisedMessage) -> Option<T> {
      let mut decoder = cbor::Decoder::from_bytes(data.clone());
      decoder.decode().next().and_then(|result_msg| result_msg.ok())
  }

  fn encode<T: Encodable>(value: T) -> SerialisedMessage {
    let mut e = cbor::Encoder::from_memory();
    let _ = e.encode(&[&value]); // FIXME: Panic when failed to encode?
    e.as_bytes().to_vec()
  }

  fn resolve(&self, verified_messages : Vec<ResultType>, _ : bool) -> Option<ResultType> {
    if verified_messages.len() < types::QUORUM_SIZE as usize {
      return None;
    }

    if verified_messages[0].1 == types::MessageTypeTag::FindGroupResponse {
        let decoded_responses = verified_messages.iter()
            .filter_map(|msg| Sentinel::decode::<FindGroupResponse>(&msg.2))
            .collect::<Vec<_>>();

        if decoded_responses.len() == 0 {
            // None of the messages was successfully decoded.
            return None;
        }

        let merged_responses = match FindGroupResponse::merge(&decoded_responses) {
          Some(merged_responses) => merged_responses,
          None => panic!("No merged group confirmed.") // return None;
        };

        return Some((verified_messages[0].0.clone(),
                     verified_messages[0].1.clone(),
                     Sentinel::encode(merged_responses)));
    // if part addresses non-account transfer message types, where an exact match is required
    } else if verified_messages[0].1 != types::MessageTypeTag::AccountTransfer {
      for index in 0..verified_messages.len() {
        let serialised_message = verified_messages[index].2.clone();
        let mut count = 0;
        for message in verified_messages.iter() {
          if message.2 == serialised_message {
            // TODO(ben 2015-04-9) FIX ERROR: overcounts, currently not a problem
            count = count + 1;
          }
        }
        if count > types::QUORUM_SIZE {
          return Some(verified_messages[index].clone());
        }
      }
    } else {  // account transfer
      let mut accounts : Vec<types::AccountTransferInfo> = Vec::new();
      for message in verified_messages.iter() {
        let mut d = cbor::Decoder::from_bytes(message.2.clone());
        let obj_after: types::AccountTransferInfo = d.decode().next().unwrap().unwrap();
        accounts.push(obj_after);
      }
      let result = accounts[0].merge(&accounts);
      if result.is_some() {
        let mut tmp = verified_messages[0].clone();
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&result.unwrap()]).unwrap();
        tmp.2 = types::array_as_vector(e.as_bytes());
        return Some(tmp);
      }
    }
    None
  }
}

fn has_single_entry<T>(key_map: &HashMap<NameType, Vec<T>>) -> bool {
    key_map.len() == 1 && key_map.iter().next().unwrap().1.len() == 1
}

#[cfg(test)]
mod test {

  use super::*;
  use std::cmp;
  use sodiumoxide::crypto;
  use types;
  use types::{RoutingTrait, closer_to_target};
  use NameType;
  use message_header;
  use messages;
  use rustc_serialize::Encodable;
  use rand;
  use cbor;
  use test_utils::Random;


  pub struct AddSentinelMessage {
    header : message_header::MessageHeader,
    tag : types::MessageTypeTag,
    serialised_message : Vec<u8>,
    index : u64
  }

  pub fn generate_u8_64() -> Vec<u8> {
    let mut u8_64: Vec<u8> = vec![];
    for _ in (0..64) {
      u8_64.push(rand::random::<u8>());
    }
    u8_64
  }

  pub fn generate_data(length : usize) -> Vec<u8> {
    let mut data: Vec<u8> = vec![];
    for _ in (0..length) {
      data.push(rand::random::<u8>());
    }
    data
  }

  struct SignatureGroup {
    group_address_ : types::GroupAddress,
    group_size_ : usize,
    authority_ : types::Authority,
    nodes_ : Vec<types::Pmid>
  }

  impl SignatureGroup {
    pub fn new(group_size : usize, authority : types::Authority) -> SignatureGroup {
      let group_address : NameType = Random::generate_random();
      let mut nodes : Vec<types::Pmid> = Vec::with_capacity(group_size);
      for _ in 0..group_size {
        nodes.push(types::Pmid::new());
      }
      SignatureGroup {
        group_address_ : group_address,
        group_size_ : group_size,
        authority_ : authority,
        nodes_ : nodes
      }
    }

    pub fn get_group_address(&self) -> types::GroupAddress { self.group_address_.clone() }

    pub fn get_headers(&self, destination_address : &types::DestinationAddress,
               message_id : &types::MessageId, serialised_message : &Vec<u8> )
              -> Vec<message_header::MessageHeader> {
        let mut headers : Vec<message_header::MessageHeader>
            = Vec::with_capacity(self.group_size_);
      for node in &self.nodes_ {
        headers.push(message_header::MessageHeader::new(message_id.clone(),
                    destination_address.clone(),
                    types::SourceAddress {
                      from_node : node.get_name(),
                      from_group : Some(self.group_address_.clone()),
                      reply_to : None
                    },
                    self.authority_.clone(),
                    Some(types::Signature {
                                signature : crypto::sign::sign(&serialised_message[..],
                                              &node.get_crypto_secret_sign_key())
                    })
        ));
      }
      headers
    }

    pub fn get_public_keys(&self) -> Vec<(NameType, types::PublicSignKey)> {
        let mut public_keys : Vec<(NameType, types::PublicSignKey)>
           = Vec::with_capacity(self.nodes_.len());
      for node in &self.nodes_ {
        public_keys.push((node.get_name(),
          types::PublicSignKey::new(node.get_crypto_public_sign_key())));
      }
      public_keys
    }
  }

  struct EmbeddedSignatureGroup {
    group_address_ : types::GroupAddress,
    group_size_ : usize,
    authority_ : types::Authority,
    nodes_ : Vec<types::Pmid>,
    // store the close nodes according
    // to the close group of original group_address
    nodes_of_nodes_ : Vec<(NameType, Vec<types::Pmid>)>
  }

  impl EmbeddedSignatureGroup {
    pub fn new(group_size : usize, authority : types::Authority)
              -> EmbeddedSignatureGroup {
      let network_size = 10 * group_size;
      let mut all_nodes : Vec<types::Pmid> = Vec::with_capacity(network_size);
      let mut nodes : Vec<types::Pmid> = Vec::with_capacity(group_size);
      let mut nodes_of_nodes : Vec<(NameType, Vec<types::Pmid>)>
                                = Vec::with_capacity(group_size);
      for _ in 0..network_size {
        all_nodes.push(types::Pmid::new()); // generates two keys !
                                            // can be optimised for larger scaled
      }
      let group_address : NameType = Random::generate_random();
      // first sort all nodes to group_address
      all_nodes.sort_by(
        |a, b| if closer_to_target(&a.get_name(), &b.get_name(), &group_address) {
          cmp::Ordering::Less
        } else {
          cmp::Ordering::Greater
        }
      );
      // select group_size closest nodes
      for i in 0..group_size { nodes.push(all_nodes[i].clone()); };
      for node in &nodes {
        // sort all nodes
        all_nodes.sort_by(
          |a, b| if closer_to_target(&a.get_name(), &b.get_name(), &node.get_name()) {
            cmp::Ordering::Less
          } else {
            cmp::Ordering::Greater
          }
        );
        // add ourselves (at 0) and group_size closest
        assert_eq!(all_nodes[0].get_name(), node.get_name());
        let mut nodes_of_node : Vec<types::Pmid> = Vec::with_capacity(group_size + 1);
        for i in 0..group_size + 1 { nodes_of_node.push(all_nodes[i].clone()); };
        nodes_of_nodes.push((node.get_name(), nodes_of_node));
      };
      EmbeddedSignatureGroup {
        group_address_ : group_address,
        group_size_ : group_size,
        authority_ : authority,
        nodes_ : nodes,
        nodes_of_nodes_ : nodes_of_nodes
      }
    }

    pub fn get_group_address(&self) -> types::GroupAddress { self.group_address_.clone() }

    pub fn get_headers(&self, destination_address : &types::DestinationAddress,
               message_id : &types::MessageId, serialised_message : &Vec<u8> )
              -> Vec<message_header::MessageHeader> {
      let mut headers : Vec<message_header::MessageHeader>
          = Vec::with_capacity(self.group_size_);
      for node in &self.nodes_ {
        headers.push(message_header::MessageHeader::new(message_id.clone(),
                    destination_address.clone(),
                    types::SourceAddress {
                      from_node : node.get_name(),
                      from_group : Some(self.group_address_.clone()),
                      reply_to : None
                    },
                    self.authority_.clone(),
                    Some(types::Signature {
                                signature : crypto::sign::sign(&serialised_message[..],
                                              &node.get_crypto_secret_sign_key())
                    })
        ));
      }
      headers
    }

    pub fn get_public_keys(&self, node_name : NameType)
          -> Vec<(NameType, types::PublicSignKey)> {
      let nodes_of_node = &self.nodes_of_nodes_.iter().find(|x| x.0 == node_name).unwrap();
      let mut public_keys : Vec<(NameType, types::PublicSignKey)>
        = Vec::with_capacity(nodes_of_node.1.len());
      for node in &nodes_of_node.1 {
        let public_sign_key =
          types::PublicSignKey::new(node.get_crypto_public_sign_key());
        public_keys.push((node.get_name(), public_sign_key));
      }
      public_keys
    }

    pub fn get_public_pmids(&self, node_name : NameType) -> Vec<types::PublicPmid> {
      let nodes_of_node = &self.nodes_of_nodes_.iter().find(|x| x.0 == node_name).unwrap();
      let mut public_pmids : Vec<types::PublicPmid>
        = Vec::with_capacity(nodes_of_node.1.len());
      for node in &nodes_of_node.1 {
        public_pmids.push(types::PublicPmid::new(&node));
      }
      public_pmids
    }

    pub fn generate_get_group_key_response_messages(&self,
                destination_address : &types::DestinationAddress,
                message_id : &types::MessageId, message_index : &mut u64)
                -> Vec<AddSentinelMessage> {
      let mut collect_messages : Vec<AddSentinelMessage> = Vec::with_capacity(self.group_size_);
      for node in &self.nodes_ {
        let get_group_key_response = messages::get_group_key_response::GetGroupKeyResponse {
          target_id : self.group_address_.clone(),
          public_sign_keys : self.get_public_keys(node.get_name())
        };
        let mut e = cbor::Encoder::from_memory();
        let _ = e.encode(&[&get_group_key_response]);
        let serialised_message_response = e.as_bytes().to_vec();
        let header = message_header::MessageHeader::new(message_id.clone(),
                    destination_address.clone(),
                    types::SourceAddress {
                      from_node : node.get_name(),
                      from_group : Some(self.group_address_.clone()),
                      reply_to : None
                    },
                    self.authority_.clone(),
                    Some(types::Signature {
                                signature : crypto::sign::sign(&serialised_message_response[..],
                                              &node.get_crypto_secret_sign_key())
                    }));
        collect_messages.push(AddSentinelMessage{
                                header : header.clone(),
                                tag : types::MessageTypeTag::GetGroupKeyResponse,
                                serialised_message : serialised_message_response,
                                index : message_index.clone()
                              });
        *message_index += 1;
      }
      collect_messages
    }

    pub fn generate_find_group_response_messages(&self,
                destination_address : &types::DestinationAddress,
                message_id : &types::MessageId, message_index : &mut u64)
                -> Vec<AddSentinelMessage> {
      let mut collect_messages : Vec<AddSentinelMessage> = Vec::with_capacity(self.group_size_);
      for node in &self.nodes_ {
        let find_group_response = messages::find_group_response::FindGroupResponse {
          target_id : self.group_address_.clone(),
          group : self.get_public_pmids(node.get_name())
        };
        let mut e = cbor::Encoder::from_memory();
        let _ = e.encode(&[&find_group_response]);
        let serialised_message_response = e.as_bytes().to_vec();
        let header = message_header::MessageHeader::new(message_id.clone(),
                    destination_address.clone(),
                    types::SourceAddress {
                      from_node : node.get_name(),
                      from_group : Some(self.group_address_.clone()),
                      reply_to : None
                    },
                    self.authority_.clone(),
                    Some(types::Signature {
                                signature : crypto::sign::sign(&serialised_message_response[..],
                                              &node.get_crypto_secret_sign_key())
                    }));
        collect_messages.push(AddSentinelMessage{
                                header : header.clone(),
                                tag : types::MessageTypeTag::FindGroupResponse,
                                serialised_message : serialised_message_response,
                                index : message_index.clone()
                              });
        *message_index += 1;
      }
      collect_messages
    }
  }

  pub struct TraceGetKeys {
    send_get_client_key_calls_ : Vec<NameType>,
    send_get_group_key_calls_ : Vec<types::GroupAddress>,
  }

  impl TraceGetKeys {
    pub fn new()-> TraceGetKeys {
      TraceGetKeys {
        send_get_client_key_calls_ : Vec::new(),
        send_get_group_key_calls_ : Vec::new()
      }
    }

    pub fn count_get_client_key_calls(&self, address : &NameType) -> usize {
      self.send_get_client_key_calls_.iter()
                       .filter(|&x| x == address)
                       .count()
    }

    pub fn count_get_group_key_calls(&self, group_address : &types::GroupAddress) -> usize {
      self.send_get_group_key_calls_.iter()
                        .filter(|&x| x == group_address)
                        .count()
    }
  }

  impl SendGetKeys for TraceGetKeys {
  fn get_client_key(&mut self, address : NameType) {
    self.send_get_client_key_calls_.push(address);
  }
    fn get_group_key(&mut self, group_address : types::GroupAddress) {
      self.send_get_group_key_calls_.push(group_address);
    }
  }

  fn generate_messages(headers : Vec<message_header::MessageHeader>,
               tag : types::MessageTypeTag, message : &Vec<u8>,
               message_index : &mut u64)
               -> Vec<AddSentinelMessage> {
    let mut collect_messages : Vec<AddSentinelMessage> = Vec::with_capacity(headers.len());
    for header in headers {
      collect_messages.push(AddSentinelMessage{ header : header,
                            tag : tag.clone(),
                            serialised_message : message.clone(),
                            index : message_index.clone()});
      *message_index += 1;
    }
    collect_messages
  }

  fn count_none_sentinel_returns(sentinel_returns : &Vec<(u64, Option<ResultType>)>)
                   -> usize {
    sentinel_returns.iter().filter(|&x| x.1.is_none()).count()
  }

  fn verify_exactly_one_response(sentinel_returns : &Vec<(u64, Option<ResultType>)>)
                   -> bool {
    sentinel_returns.iter().filter(|&x| x.1.is_some()).count() == 1
  }

  fn get_selected_sentinel_returns(sentinel_returns: &mut Vec<(u64, Option<ResultType>)>,
                    track_messages : &mut Vec<u64>)
                    ->Vec<(u64, Option<ResultType>)> {
    if track_messages.is_empty() { return Vec::<(u64, Option<ResultType>)>::new(); }
    let mut selected_returns : Vec<(u64, Option<ResultType>)> = Vec::new();
    sentinel_returns.sort_by(|a, b| a.0.cmp(&b.0));
    track_messages.sort();
    let mut track_index = 0;
    for sentinel_return in sentinel_returns {
      let track_message = track_messages[track_index];
      if sentinel_return.0 == track_message {
       selected_returns.push(sentinel_return.clone());
      }
      if sentinel_return.0 >= track_message {
       if track_index != track_messages.len() - 1 {
         track_index += 1;
       } else { break; }
      }
    }
    selected_returns
  }

  fn verify_match_sentinel_return(sentinel_return : &ResultType,
                                  original_message_id : types::MessageId,
                                  original_authority : types::Authority,
                                  original_destination : types::DestinationAddress,
                                  original_source_group : types::GroupAddress,
                                  original_message_type_tag : types::MessageTypeTag,
                                  original_message : types::SerialisedMessage)
                                  -> bool {

  if original_message != sentinel_return.2 { return false; };
  if original_message_type_tag != sentinel_return.1 {return false; };
  if original_message_id != sentinel_return.0.message_id() { return false; };
  if original_authority != sentinel_return.0.from_authority() { return false; };
  if original_destination != sentinel_return.0.send_to() { return false; };

  true
  }

  #[test]
  fn simple_add_put_data() {
    let our_pmid = types::Pmid::new();
    let our_destination = types::DestinationAddress {
      dest : our_pmid.get_name(),
      reply_to : None
    };
    let signature_group = SignatureGroup::new(types::GROUP_SIZE as usize,
               types::Authority::NaeManager);
    let mut trace_get_keys = TraceGetKeys::new();
    let mut sentinel_returns : Vec<(u64, Option<ResultType>)> = Vec::new();
    let mut message_tracker : u64 = 0;
    {
      let mut sentinel = Sentinel::new(&mut trace_get_keys);
      let data : Vec<u8> = generate_data(100usize);
      let put_data = messages::put_data::PutData {        
        name: NameType::new(types::vector_as_u8_64_array(crypto::hash::sha512::hash(&data[..]).0.to_vec())),
        data : data
      };
      let mut e = cbor::Encoder::from_memory();
      let _ = e.encode(&[&put_data]);
      let serialised_message = e.as_bytes().to_vec();
      let message_id = rand::random::<u32>() as types::MessageId;
      let tag = types::MessageTypeTag::PutData;
      let headers = signature_group.get_headers(&our_destination, &message_id, &serialised_message);
      let collect_messages = generate_messages(headers, tag, &serialised_message, &mut message_tracker);

      let get_group_key_response = messages::get_group_key_response::GetGroupKeyResponse {
        target_id : signature_group.get_group_address(),
        public_sign_keys : signature_group.get_public_keys()
      };
      let mut e = cbor::Encoder::from_memory();
      let _ = e.encode(&[&get_group_key_response]);
      let serialised_message_response = e.as_bytes().to_vec();
      let headers_response = signature_group.get_headers(&our_destination, &message_id,
                                 &serialised_message_response);
      let response_tag = types::MessageTypeTag::GetGroupKeyResponse;
      let collect_response_messages = generate_messages(headers_response, response_tag,
          &serialised_message_response, &mut message_tracker);

    for message in collect_messages {
      sentinel_returns.push((message.index,
                             sentinel.add(message.header,
                                          message.tag,
                                          message.serialised_message)));
    }
    assert_eq!(types::GROUP_SIZE as usize, sentinel_returns.len());
    assert_eq!(types::GROUP_SIZE as usize, count_none_sentinel_returns(&sentinel_returns));
    assert_eq!(false, verify_exactly_one_response(&sentinel_returns));

    for message in collect_response_messages {
      sentinel_returns.push((message.index,
                            sentinel.add(message.header,
                                         message.tag,
                                         message.serialised_message)));
    }
    assert_eq!(2 * types::GROUP_SIZE as usize, sentinel_returns.len());
    assert_eq!(2 * types::GROUP_SIZE as usize - 1, count_none_sentinel_returns(&sentinel_returns));
    assert_eq!(true, verify_exactly_one_response(&sentinel_returns));
    assert_eq!(1, get_selected_sentinel_returns(&mut sentinel_returns,
                    &mut vec![(types::GROUP_SIZE + types::QUORUM_SIZE) as u64]).len());
    }
  assert_eq!(0, trace_get_keys.count_get_client_key_calls(&signature_group.get_group_address()));
  assert_eq!(1, trace_get_keys.count_get_group_key_calls(&signature_group.get_group_address()));
  }

  #[test]
  fn embedded_add_put_data() {
    let our_pmid = types::Pmid::new();
    let our_destination = types::DestinationAddress {
      dest : our_pmid.get_name(),
      reply_to : None
    };
    let embedded_signature_group = EmbeddedSignatureGroup::new(types::GROUP_SIZE as usize,
               types::Authority::NaeManager);
    let mut trace_get_keys = TraceGetKeys::new();
    let mut sentinel_returns : Vec<(u64, Option<ResultType>)> = Vec::new();
    let mut message_tracker : u64 = 0;
    {
      let mut sentinel = Sentinel::new(&mut trace_get_keys);
      let data : Vec<u8> = generate_data(100usize);
      let put_data = messages::put_data::PutData {
        name: NameType::new(types::vector_as_u8_64_array(crypto::hash::sha512::hash(&data[..]).0.to_vec())),
        data : data
      };
      let mut e = cbor::Encoder::from_memory();
      let _ = e.encode(&[&put_data]);
      let serialised_message = e.as_bytes().to_vec();
      let message_id = rand::random::<u32>() as types::MessageId;
      let tag = types::MessageTypeTag::PutData;
      let headers = embedded_signature_group.get_headers(&our_destination, &message_id, &serialised_message);
      let collect_messages = generate_messages(headers, tag, &serialised_message, &mut message_tracker);

      let collect_response_messages = embedded_signature_group
                .generate_get_group_key_response_messages(&our_destination,
                                                          &message_id,
                                                          &mut message_tracker);
    for message in collect_messages {
      sentinel_returns.push((message.index,
                             sentinel.add(message.header,
                                          message.tag,
                                          message.serialised_message)));
    }
    assert_eq!(types::GROUP_SIZE as usize, sentinel_returns.len());
    assert_eq!(types::GROUP_SIZE as usize, count_none_sentinel_returns(&sentinel_returns));
    assert_eq!(false, verify_exactly_one_response(&sentinel_returns));

    for message in collect_response_messages {
      sentinel_returns.push((message.index,
                            sentinel.add(message.header,
                                         message.tag,
                                         message.serialised_message)));
    }
    assert_eq!(2 * types::GROUP_SIZE as usize, sentinel_returns.len());
    assert_eq!(2 * types::GROUP_SIZE as usize - 1, count_none_sentinel_returns(&sentinel_returns));
    assert_eq!(true, verify_exactly_one_response(&sentinel_returns));
    assert_eq!(1, get_selected_sentinel_returns(&mut sentinel_returns,
                    &mut vec![(types::GROUP_SIZE + types::QUORUM_SIZE) as u64]).len());
    }
  assert_eq!(0, trace_get_keys.count_get_client_key_calls(&embedded_signature_group.get_group_address()));
  assert_eq!(1, trace_get_keys.count_get_group_key_calls(&embedded_signature_group.get_group_address()));
  }

  #[test]
  fn embedded_find_group_response() {
    // this sentinel is now the destination
    let our_pmid = types::Pmid::new();
    let our_destination = types::DestinationAddress {
      dest : our_pmid.get_name(),
      reply_to : None
    };
    let embedded_signature_group = EmbeddedSignatureGroup::new(types::GROUP_SIZE as usize,
               types::Authority::NaeManager);
    let mut trace_get_keys = TraceGetKeys::new();
    let mut sentinel_returns : Vec<(u64, Option<ResultType>)> = Vec::new();
    let mut message_tracker : u64 = 0;
    {
      let mut sentinel = Sentinel::new(&mut trace_get_keys);
      let message_id = rand::random::<u32>() as types::MessageId;
      let collect_messages = embedded_signature_group
                .generate_find_group_response_messages(&our_destination,
                                                       &message_id,
                                                       &mut message_tracker);

      let collect_response_messages = embedded_signature_group
                .generate_get_group_key_response_messages(&our_destination,
                                                          &message_id,
                                                          &mut message_tracker);
    for message in collect_messages {
      sentinel_returns.push((message.index,
                             sentinel.add(message.header,
                                          message.tag,
                                          message.serialised_message)));
    }
    assert_eq!(types::GROUP_SIZE as usize, sentinel_returns.len());
    assert_eq!(types::GROUP_SIZE as usize, count_none_sentinel_returns(&sentinel_returns));
    assert_eq!(false, verify_exactly_one_response(&sentinel_returns));

    for message in collect_response_messages {
      sentinel_returns.push((message.index,
                            sentinel.add(message.header,
                                         message.tag,
                                         message.serialised_message)));
    }
    assert_eq!(2 * types::GROUP_SIZE as usize, sentinel_returns.len());
    assert_eq!(2 * types::GROUP_SIZE as usize - 1, count_none_sentinel_returns(&sentinel_returns));
    assert_eq!(true, verify_exactly_one_response(&sentinel_returns));
    assert_eq!(1, get_selected_sentinel_returns(&mut sentinel_returns,
                    &mut vec![(types::GROUP_SIZE + types::QUORUM_SIZE) as u64]).len());
    }
  assert_eq!(0, trace_get_keys.count_get_client_key_calls(&embedded_signature_group.get_group_address()));
  assert_eq!(1, trace_get_keys.count_get_group_key_calls(&embedded_signature_group.get_group_address()));
  }
}
