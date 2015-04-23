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

use std::collections::BTreeMap;

pub struct Frequency<K: Ord + Clone> {
    map: BTreeMap<K, usize>
}

impl<Key: Ord + Clone> Frequency<Key> {
    pub fn new() -> Frequency<Key> {
        Frequency {
            map: BTreeMap::<Key, usize>::new()
        }
    }

    pub fn update(&mut self, key: Key) {
        *self.map.entry(key).or_insert(0) += 1;
    }

    pub fn sort_by_highest(&self) -> Vec<(Key, usize)> {
        let mut kvs = self.to_vector();
        kvs.sort_by(|a,b| b.1.cmp(&a.1));
        kvs
    }

    fn to_vector(&self) -> Vec<(Key, usize)> {
        self.map.iter().map(|(k,v)| (k.clone(), v.clone())).collect::<Vec<_>>()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn fill_exponential_distribution() {
        
    }
}
