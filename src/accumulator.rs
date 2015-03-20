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

use std::hash::Hash;
use std::time::duration::Duration;

use lru_cache::LruCache;
use time::*;

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
pub struct Entry<V> {
  /// Time for the entry first created
  pub first_added_time : Timespec,
  /// Expected threshold for resolve
  pub received_response : Vec<Response<V>>
}

/// Accumulator for various message type
pub struct Accumulator<K, V> where K: Eq + Hash, V: Clone {
  /// Expected threshold for resolve
  quorum : usize,
  /// lifetime for entry, the entry will be cleaned up once expired
  time_to_live : Duration,
  storage : LruCache<K, Entry<V>>
}

impl<K: Eq + Hash, V: Clone> Accumulator<K, V> {
  pub fn new(quorum : usize, time_to_live : Duration) -> Accumulator<K, V> {
  	Accumulator { quorum: quorum, time_to_live: time_to_live, storage: LruCache::new(1000)}
  }

  pub fn have_name(&mut self, name : K) -> bool {
  	self.storage.get(&name).is_none()
  }

  pub fn is_quorum_reached(&mut self, name : K) -> bool {
  	let entry = self.storage.get(&name);
  	if entry.is_none() {
  	  false
  	} else {
  	  entry.unwrap().received_response.len() >= self.quorum
  	}
  }

  pub fn add(&mut self, name : K, value : V, sender : types::Address) {
  	let entry = self.storage.remove(&name);
  	if entry.is_none() {
  	  let entry_in = Entry { first_added_time : get_time(),
  	  	                     received_response : vec![Response{ address : sender, value : value }] };
  	} else {
  	  let mut tmp = entry.unwrap();
  	  tmp.received_response.push(Response{ address : sender, value : value });
  	  self.storage.insert(name, tmp);
  	}
  }

  pub fn get(&mut self, name : K) -> Option<(K, Vec<Response<V>>)>{
  	let entry = self.storage.get(&name);
  	if entry.is_none() {
  	  None
  	} else {
  	  Some((name, entry.unwrap().received_response.clone()))
  	}
  }

  pub fn delete(&mut self, name : K) {
  	self.storage.remove(&name);
  }

  pub fn cache_size(&mut self) -> usize {
  	self.storage.len()
  }
}