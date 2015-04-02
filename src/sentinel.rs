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


pub struct Sentinel<'a> {
  // send_get_client_key_ : for <'a> Fn<(types::Address)>,
  // send_get_group_key_ : Fn<(types::GroupAddress),>,
  key_getter_traits_: &'a mut (types::KeyGetterTraits + 'a),
  node_accumulator_ : NodeAccumulatorType,
  group_accumulator_ : GroupAccumulatorType,
  group_key_accumulator_ : KeyAccumulatorType,
  node_key_accumulator_ : KeyAccumulatorType
}

impl<'a> Sentinel<'a> {
  pub fn new(key_getter_traits_in: &'a mut types::KeyGetterTraits) -> Sentinel {
  	Sentinel {
  	  key_getter_traits_: key_getter_traits_in,
  	  node_accumulator_: NodeAccumulatorType::new(20),
  	  group_accumulator_: NodeAccumulatorType::new(20),
  	  group_key_accumulator_: KeyAccumulatorType::new(20),
  	  node_key_accumulator_: KeyAccumulatorType::new(20)
  	}
  }

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
						self.key_getter_traits_.get_group_key(header.from_group().unwrap());
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
						self.key_getter_traits_.get_client_key(header.from_group().unwrap());
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
  
  use super::*;

  struct SignatureGroup {
  	group_address : GroupAddress,
  	group_size : usize,
  	authority : Authority,
  	nodes : Vec<pmid>
  }

  impl SignatureGroup {
  	pub fn new(group_address : GroupAddress,
  		       group_size : usize, ) -> SignatureGroup {

  	}
  }

  #[test]
  fn sentinel_simple_add() {
    
  }
}