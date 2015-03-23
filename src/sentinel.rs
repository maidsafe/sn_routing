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
  traits_: &'a mut (types::SentinelTraits + 'a),
  node_accumulator_ : NodeAccumulatorType,
  group_accumulator_ : GroupAccumulatorType,
  group_key_accumulator_ : KeyAccumulatorType,
  node_key_accumulator_ : KeyAccumulatorType
}

impl<'a> Sentinel<'a> {
  pub fn new(traits_in: &'a mut types::SentinelTraits) -> Sentinel {
  	Sentinel {
  		traits_: traits_in,
  	  node_accumulator_: NodeAccumulatorType::new(20),
  	  group_accumulator_: NodeAccumulatorType::new(20),
  	  group_key_accumulator_: KeyAccumulatorType::new(20),
  	  node_key_accumulator_: KeyAccumulatorType::new(20)
  	}
  }
}