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

extern crate cbor;
extern crate sodiumoxide;

use std::collections::HashMap;
use sodiumoxide::crypto;

use accumulator;
use message_header;
use types;
use types::RoutingTrait;
use messages::get_client_key_response::GetClientKeyResponse;
use messages::get_group_key_response::GetGroupKeyResponse;

pub type ResultType = (message_header::MessageHeader,
	                   types::MessageTypeTag, types::SerialisedMessage);

type NodeKeyType = (types::NodeAddress, types::MessageId);
type GroupKeyType = (types::GroupAddress, types::MessageId);
type NodeAccumulatorType = accumulator::Accumulator<NodeKeyType, ResultType>;
type GroupAccumulatorType = accumulator::Accumulator<GroupKeyType, ResultType>;
type KeyAccumulatorType = accumulator::Accumulator<types::GroupAddress, ResultType>;


// TODO (ben 2015-4-2): replace dynamic dispatching with static dispatching
//          https://doc.rust-lang.org/book/static-and-dynamic-dispatch.html
pub trait SendGetKeys {
  fn get_client_key(&mut self, address : types::Address);
  fn get_group_key(&mut self, group_address : types::GroupAddress);
}

pub struct Sentinel<'a> {
  send_get_keys_ : &'a mut (SendGetKeys + 'a),
  node_accumulator_ : NodeAccumulatorType,
  group_accumulator_ : GroupAccumulatorType,
  group_key_accumulator_ : KeyAccumulatorType,
  node_key_accumulator_ : KeyAccumulatorType
}

impl<'a> Sentinel<'a> {
  pub fn new(send_get_keys: &'a mut SendGetKeys) -> Sentinel<'a> {
  	Sentinel {
  	  send_get_keys_: send_get_keys,
  	  node_accumulator_: NodeAccumulatorType::new(20),
  	  group_accumulator_: NodeAccumulatorType::new(20),
  	  group_key_accumulator_: KeyAccumulatorType::new(20),
  	  node_key_accumulator_: KeyAccumulatorType::new(20)
  	}
  }

  // pub fn get_send_get_keys(&'a mut self) -> &'a mut SendGetKeys { self.send_get_keys }

  pub fn add(&mut self, header : message_header::MessageHeader, type_tag : types::MessageTypeTag,
  	         message : types::SerialisedMessage) -> Option<ResultType> {
  	match type_tag {
  		types::MessageTypeTag::GetClientKeyResponse => {
  			if header.is_from_group() {
	  			let keys = self.node_key_accumulator_.add(header.from_group().unwrap(),
			  				                                    (header.clone(), type_tag, message),
			  				                                    header.from_node());
		      if keys.is_some() {
		      	let key = (header.from_group().unwrap(), header.message_id());
		      	let messages = self.node_accumulator_.get(&key);
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
		      	let messages = self.group_accumulator_.get(&key);
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
					if !self.group_accumulator_.have_name(&key) {
						//self.key_getter_traits_.get_group_key(header.from_group().unwrap());
						self.send_get_keys_.get_group_key(header.from_group().unwrap());
					} else {
						let messages = self.group_accumulator_.add(key.clone(),
							                                         (header.clone(), type_tag, message),
							                                         header.from_node());
						if messages.is_some() {
							let keys = self.group_key_accumulator_.get(&header.from_group().unwrap());
							if keys.is_some() {
		      			let resolved = self.resolve(self.validate_group(messages.unwrap().1,
		      				                                              keys.unwrap().1), true);
		      			if resolved.is_some() {
	      					self.group_accumulator_.delete(key);
	      					return resolved;
		      			}
			      	}
						}
					}
				} else {
					let key = (header.from_node(), header.message_id());
					if !self.node_accumulator_.have_name(&key) {
						//self.key_getter_traits_.get_client_key(header.from_group().unwrap());
						self.send_get_keys_.get_client_key(header.from_group().unwrap());
					} else {
						let messages = self.node_accumulator_.add(key.clone(),
							                                        (header.clone(), type_tag, message),
							                                        header.from_node());
						if messages.is_some() {
							let keys = self.node_key_accumulator_.get(&header.from_group().unwrap());
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
		}
  	None
  }

  fn validate_node(&self, messages : Vec<accumulator::Response<ResultType>>,
  	               keys : Vec<accumulator::Response<ResultType>>) -> Vec<ResultType> {
	  if messages.len() == 0 || keys.len() < types::QUORUM_SIZE as usize {
	    return Vec::<ResultType>::new();
	  }
  	let mut verified_messages : Vec<ResultType> = Vec::new();
  	let mut keys_map : HashMap<types::Address, Vec<types::PublicKey>> = HashMap::new();
  	for node_key in keys.iter() {
      let mut d = cbor::Decoder::from_bytes(node_key.value.2.clone());
      let key_response: GetClientKeyResponse = d.decode().next().unwrap().unwrap();
      if !keys_map.contains_key(&key_response.address) {
				keys_map.insert(key_response.address,
					              vec![types::PublicKey{ public_key : key_response.public_key }]);
      } else {
	      let public_keys = keys_map.get_mut(&key_response.address);
      	let mut public_keys_holder = public_keys.unwrap();
        let target_key = types::PublicKey{ public_key : key_response.public_key };
      	if !public_keys_holder.contains(&target_key) {
      		public_keys_holder.push(target_key);
      	}
	    }      
  	}
  	let mut pub_key_list : Vec<types::PublicKey> = Vec::new();
  	for (_, value) in keys_map.iter() {
  		pub_key_list = value.clone();
  		break;
  	}
  	if keys_map.len() != 1 || pub_key_list.len() != 1 {
  		return Vec::<ResultType>::new();
  	}
  	let public_key = pub_key_list[0].get_public_key();
  	for message in messages.iter() {
  		let signature = message.value.0.get_signature();
  		let ref msg = message.value.2;
  		if crypto::sign::verify_detached(&signature, &msg[..], &public_key) {
  		  verified_messages.push(message.value.clone());
  		}
  	}
  	verified_messages
  }

  fn validate_group(&self, messages : Vec<accumulator::Response<ResultType>>,
  	                keys : Vec<accumulator::Response<ResultType>>) -> Vec<ResultType> {
	  if messages.len() < types::QUORUM_SIZE as usize || keys.len() < types::QUORUM_SIZE as usize {
	    return Vec::<ResultType>::new();
	  }
  	let mut verified_messages : Vec<ResultType> = Vec::new();
  	let mut keys_map : HashMap<types::Address, Vec<types::PublicKey>> = HashMap::new();
  	for group_key in keys.iter() {
      let mut d = cbor::Decoder::from_bytes(group_key.value.2.clone());
      let group_key_response: GetGroupKeyResponse = d.decode().next().unwrap().unwrap();
      for public_key in group_key_response.public_keys.iter() {
      	if !keys_map.contains_key(&public_key.0) {
	      	keys_map.insert(public_key.0.clone(), vec![types::PublicKey{ public_key : public_key.1.clone() }]);
      	} else {
		      let public_keys = keys_map.get_mut(&public_key.0);
	      	let mut public_keys_holder = public_keys.unwrap();
          let target_key = types::PublicKey{ public_key : public_key.1.clone() };
	      	if !public_keys_holder.contains(&target_key) {
	          public_keys_holder.push(target_key);
	        }
		    }
	    }
  	}
  	// TODO(mmoadeli): For the time being, we assume that no invalid public is received
    for (_, pub_key_list) in keys_map.iter() {
    	if pub_key_list.len() != 1 {
    		return Vec::<ResultType>::new();
    	}
    }
    for message in messages.iter() {
    	let key_map_iter = keys_map.get_mut(&message.value.0.from_node());
    	if key_map_iter.is_some() {
		  	let public_key = key_map_iter.unwrap()[0].get_public_key();
        let signature = message.value.0.get_signature();
        let ref msg = message.value.2;
	  		if crypto::sign::verify_detached(&signature, &msg[..], &public_key) {
	  		  verified_messages.push(message.value.clone());
	  		}
		  }
	  }
	  if verified_messages.len() >= types::QUORUM_SIZE as usize {
  		verified_messages
  	} else {
  		Vec::<ResultType>::new()
  	}
  }

  fn resolve(&self, verified_messages : Vec<ResultType>, _ : bool) -> Option<ResultType> {
	  if verified_messages.len() < types::QUORUM_SIZE as usize {
	    return None;
	  }
	  // if part addresses non-account transfer message types, where an exact match is required
	  if verified_messages[0].1 != types::MessageTypeTag::AccountTransfer {
	    for index in 0..verified_messages.len() {
	      let serialised_message = verified_messages[index].2.clone();
	      let mut count = 0;
	      for message in verified_messages.iter() {
	      	if message.2 == serialised_message {
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


#[cfg(test)]
mod test {
  
  extern crate rand;
  extern crate sodiumoxide;
  extern crate cbor;

  use super::*;
  use sodiumoxide::crypto;
  use types;
  use types::RoutingTrait;
  use message_header;
  use messages;
  use std::marker::PhantomData;
  use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};

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
  	pub fn new(group_address : types::GroupAddress,
  		       group_size : usize, authority : types::Authority) -> SignatureGroup {
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

  	pub fn get_headers(&self, destination_address : types::DestinationAddress,
  					   message_id : types::MessageId, serialised_message : &Vec<u8> )
  					  -> Vec<message_header::MessageHeader> {
  	  let mut headers : Vec<message_header::MessageHeader> 
  	  				  = Vec::with_capacity(self.group_size_);
  	  for node in &self.nodes_ {
  	  	headers.push(message_header
  	  		         ::MessageHeader::new(message_id.clone(),
  	  		         		destination_address.clone(),
							types::SourceAddress {
							  from_node : node.get_name(),
							  from_group : self.group_address_.clone(),
	  						  reply_to : generate_u8_64()
							},
							self.authority_.clone(),
						    types::Signature {
							  signature : crypto::sign::sign(&serialised_message[..],
							                                 &node.get_secret_sign_key())
  	  				        }
  	  				));
  	  }
  	  headers
  	}

  	pub fn get_public_keys(&self) -> Vec<(types::Address, Vec<u8>)> {
  	  let public_keys : Vec<(types::Address, Vec<u8>)> 
  	    = Vec::with_capacity(self.nodes_.len());
  	  for node in self.nodes_ {
        public_keys.push((node.get_name(), node.get_public_key()));
  	  }
  	  public_keys
  	}
  }

  pub struct TraceGetKeys {
  	send_get_client_key_calls_ : Vec<types::Address>,
  	send_get_group_key_calls_ : Vec<types::GroupAddress>,
  }

  impl TraceGetKeys {
  	pub fn new()-> TraceGetKeys {
  	  TraceGetKeys {
  	  	send_get_client_key_calls_ : Vec::new(),
  	  	send_get_group_key_calls_ : Vec::new()
  	  }
  	}

  	pub fn count_get_client_key_calls(&self, address : &types::Address) -> usize {
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
	fn get_client_key(&mut self, address : types::Address) {
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

  #[test]
  fn simple_add() {
  	let our_pmid = types::Pmid::new();
    let our_destination = types::DestinationAddress {
    	dest : our_pmid.get_name(),
    	reply_to : generate_u8_64()
    };
    let group_address = generate_u8_64();
    let mut signature_group = SignatureGroup::new(group_address, types::GROUP_SIZE as usize,
    											  types::Authority::NaeManager);
    let mut trace_get_keys = TraceGetKeys::new();
    let mut sentinel_returns : Vec<(u64, Option<ResultType>)> = Vec::new();
    let mut message_tracker : u64 = 0;
    {
      let mut sentinel = Sentinel::new(&mut trace_get_keys);
      let data : Vec<u8> = generate_data(100usize);
      let put_data = messages::put_data::PutData { 
      	name_and_type_id : types::NameAndTypeId {
      	  name : crypto::hash::sha512::hash(&data[..]).0.to_vec(),
      	  type_id : 0u32  // TODO(ben 2015-04-02: how is type_id determined)
        },
        data : data
      };
	  let mut e = cbor::Encoder::from_memory();
	  e.encode(&[&put_data]);
	  let serialised_message = e.as_bytes().to_vec();
      let message_id = rand::random::<u32>() as types::MessageId;
      let tag = types::MessageTypeTag::PutData;
      let headers = signature_group.get_headers(our_destination, message_id, &serialised_message);
      let mut collect_messages = generate_messages(headers, tag, &serialised_message, &mut message_tracker);
      
      let get_group_key_response = messages::get_group_key_response::GetGroupKeyResponse {
	   	target_id : group_address,
	   	public_keys : signature_group.get_public_keys()
	  };


      for message in collect_messages {
      	sentinel.add(message.header, message.tag, message.serialised_message);
      }


    }
  }
}