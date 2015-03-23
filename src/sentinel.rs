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

use accumulator;
use message_header;
use types;

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

  fn validate_node(&self, _ : Vec<accumulator::Response<ResultType>>,
  	               _ : Vec<accumulator::Response<ResultType>>) -> Vec<ResultType> {
  	Vec::<ResultType>::new()
  }

  fn validate_group(&self, _ : Vec<accumulator::Response<ResultType>>,
  	                _ : Vec<accumulator::Response<ResultType>>) -> Vec<ResultType> {
    Vec::<ResultType>::new()
  }

  fn resolve(&self, _ : Vec<ResultType>, _ : bool) -> Option<ResultType> {
    None
  }

}