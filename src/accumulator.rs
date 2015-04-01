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

use std::hash::Hash;
use lru_cache::LruCache;

use types;

/// entry in the accumulator
#[derive(Clone)]
pub struct Response<V> {
  /// address where the response come from
  pub address : types::Address,
  /// content of the response
  pub value : V
}

/// entry in the accumulator
#[derive(Clone)]
pub struct Entry<V> {
  /// Expected threshold for resolve
  pub received_response : Vec<Response<V>>
}

/// Accumulator for various message type
pub struct Accumulator<K, V> where K: Eq + Hash + Clone, V: Clone {
  /// Expected threshold for resolve
  quorum : usize,
  storage : LruCache<K, Entry<V>>
}

impl<K: Eq + Hash + Clone, V: Clone> Accumulator<K, V> {
  pub fn new(quorum : usize) -> Accumulator<K, V> {
  	Accumulator { quorum: quorum, storage: LruCache::new(1000)}
  }

  pub fn have_name(&mut self, name : &K) -> bool {
  	self.storage.get(name).is_some()
  }

  pub fn is_quorum_reached(&mut self, name : K) -> bool {
  	let entry = self.storage.get(&name);
  	if entry.is_none() {
  	  false
  	} else {
  	  entry.unwrap().received_response.len() >= self.quorum
  	}
  }

  pub fn add(&mut self, name : K, value : V, sender : types::Address)-> Option<(K, Vec<Response<V>>)> {
  	let entry = self.storage.remove(&name);
  	if entry.is_none() {
  	  let entry_in = Entry { received_response : vec![Response{ address : sender, value : value }] };
  	  self.storage.insert(name.clone(), entry_in.clone());
  	  if self.quorum == 1 {
  	  	let result = (name, entry_in.received_response);
  	  	return Some(result);
  	  }
  	} else {
  	  let mut tmp = entry.unwrap();
  	  tmp.received_response.push(Response{ address : sender, value : value });
  	  self.storage.insert(name.clone(), tmp.clone());
  	  if tmp.received_response.len() >= self.quorum {
  	  	return Some((name, tmp.received_response));
  	  }
  	}
  	None
  }

  pub fn get(&mut self, name : &K) -> Option<(K, Vec<Response<V>>)>{
  	let entry = self.storage.get(name);
  	if entry.is_none() {
  	  None
  	} else {
  	  Some((name.clone(), entry.unwrap().received_response.clone()))
  	}
  }

  pub fn delete(&mut self, name : K) {
  	self.storage.remove(&name);
  }

  pub fn cache_size(&mut self) -> usize {
  	self.storage.len()
  }
}

mod test {
  extern crate cbor;
  use super::*;
  use std::num;
  use types;
  use rand;

  pub fn generate_address() -> Vec<u8> {
    let mut address: Vec<u8> = vec![];
    for _ in (0..64) {
      address.push(rand::random::<u8>());
    }
    address
  }

  #[test]
  fn add() {
    let mut accumulator : Accumulator<i32, u32> = Accumulator::new(1);
    let address1 : Vec<u8> = generate_address();
    let address2 : Vec<u8> = generate_address();

    assert!(accumulator.add(2, 3, address1.clone()).is_some());
    assert_eq!(accumulator.have_name(&1), false);
    assert_eq!(accumulator.have_name(&2), true);
    assert_eq!(accumulator.is_quorum_reached(1), false);
    assert_eq!(accumulator.is_quorum_reached(2), true);
    assert!(accumulator.add(1, 3, address2.clone()).is_some());
    assert_eq!(accumulator.have_name(&1), true);
    assert_eq!(accumulator.is_quorum_reached(1), true);
    assert!(accumulator.add(1, 3, address2.clone()).is_some());
    assert_eq!(accumulator.have_name(&1), true);
    assert_eq!(accumulator.is_quorum_reached(1), true);

    let (key, responses) = accumulator.get(&1).unwrap();

    assert_eq!(key, 1);
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0].value, 3);
    assert_eq!(responses[0].address, address2.clone());
    assert_eq!(responses[1].value, 3);
    assert_eq!(responses[1].address, address2.clone());

    let (key, responses) = accumulator.get(&2).unwrap();

    assert_eq!(key, 2);
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].value, 3);
    assert_eq!(responses[0].address, address1.clone());
  }

  #[test]
  fn delete() {
    let mut accumulator : Accumulator<i32, u32> = Accumulator::new(2);
    let address : Vec<u8> = generate_address();

    assert!(accumulator.add(1, 1, address.clone()).is_none());
    assert_eq!(accumulator.have_name(&1), true);
    assert_eq!(accumulator.is_quorum_reached(1), false);

    let (key, responses) = accumulator.get(&1).unwrap();

    assert_eq!(key, 1);
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].value, 1);
    assert_eq!(responses[0].address, address.clone());

    accumulator.delete(1);

    let option = accumulator.get(&1);

    assert!(option.is_none());

    assert!(accumulator.add(1, 1, address.clone()).is_none());
    assert_eq!(accumulator.have_name(&1), true);
    assert_eq!(accumulator.is_quorum_reached(1), false);
    assert!(accumulator.add(1, 1, address.clone()).is_some());
    assert_eq!(accumulator.have_name(&1), true);
    assert_eq!(accumulator.is_quorum_reached(1), true);

    let (key, responses) = accumulator.get(&1).unwrap();

    assert_eq!(key, 1);
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0].value, 1);
    assert_eq!(responses[0].address, address.clone());
    assert_eq!(responses[1].value, 1);
    assert_eq!(responses[1].address, address.clone());

    accumulator.delete(1);

    let option = accumulator.get(&1);

    assert!(option.is_none());
  }

  #[test]
  fn fill() {
    let mut accumulator : Accumulator<i32, u32> = Accumulator::new(1);
    let address : Vec<u8> = generate_address();

    for count in 0..1000 {
      assert!(accumulator.add(count, 1, address.clone()).is_some());
      assert_eq!(accumulator.have_name(&count), true);
      assert_eq!(accumulator.is_quorum_reached(count), true);
    }

    for count in 0..1000 {
      let (key, responses) = accumulator.get(&count).unwrap();

      assert_eq!(key, count);
      assert_eq!(responses.len(), 1);
      assert_eq!(responses[0].value, 1);
      assert_eq!(responses[0].address, address.clone());
    }
  }

  #[test]
  fn cache_removals() {
    let mut accumulator : Accumulator<i32, u32> = Accumulator::new(2);
    let address : Vec<u8> = generate_address();

    for count in 0..1000 {
      assert!(accumulator.add(count, 1, address.clone()).is_none());
      assert_eq!(accumulator.have_name(&count), true);
      assert_eq!(accumulator.is_quorum_reached(count), false);

      let (key, responses) = accumulator.get(&count).unwrap();

      assert_eq!(key, count);
      assert_eq!(responses.len(), 1);
      assert_eq!(responses[0].value, 1);
      assert_eq!(responses[0].address, address.clone());
      assert_eq!(accumulator.cache_size(), num::cast(count + 1).unwrap());
    }

    assert!(accumulator.add(1000, 1, address.clone()).is_none());
    assert_eq!(accumulator.have_name(&1000), true);
    assert_eq!(accumulator.is_quorum_reached(1000), false);
    assert_eq!(accumulator.cache_size(), 1000);

    for count in 0..1000 {
      let option = accumulator.get(&count);

      assert!(option.is_none());

      assert!(accumulator.add(count + 1001, 1, address.clone()).is_none());
      assert_eq!(accumulator.have_name(&(count + 1001)), true);
      assert_eq!(accumulator.is_quorum_reached(count), false);
      assert_eq!(accumulator.cache_size(), 1000);
    }
  }
}
