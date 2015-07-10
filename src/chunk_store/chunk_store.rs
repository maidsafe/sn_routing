// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.                                                                */

#![allow(dead_code)]
#![deny(missing_docs)]

use routing::NameType;

/// Data entry in the chunkstore network name and data.
pub struct Entry {
    name: NameType,
    data: Vec<u8>
}

/// Chunkstore is a collection for holding all data chunks.
/// Implements a maximum disk usage to restrict storage.
pub struct ChunkStore {
    entries: Vec<Entry>,
    max_disk_usage: usize,
    current_disk_usage: usize,
}

impl ChunkStore {
    /// Create new chunkstore with zero allowed disk usage.
    pub fn new() -> ChunkStore {
        ChunkStore {
            entries: Vec::new(),
            max_disk_usage: 0,
            current_disk_usage: 0,
        }
    }

    pub fn with_max_disk_usage(max_disk_usage: usize) -> ChunkStore {
        ChunkStore {
            entries: Vec::new(),
            max_disk_usage: max_disk_usage,
            current_disk_usage: 0,
        }
    }

    pub fn put(&mut self, name: NameType, value: Vec<u8>) {
        if !self.has_disk_space(value.len()) {
            panic!("Disk space unavailable. Not enough space");
        }
        self.delete(name.clone()); // To remove if the data is already present
        self.current_disk_usage += value.len();
        self.entries.push(Entry {
          name: name,
          data: value,
        });
    }

    pub fn delete(&mut self, name: NameType) {
        let size_removed : usize;

        for i in 0..self.entries.len() {
            if self.entries[i].name == name {
                size_removed = self.entries[i].data.len();
                self.entries.remove(i);
                self.current_disk_usage -= size_removed;
                break;
            }
        }
    }

    pub fn get(&self, name: NameType) -> Vec<u8> {
      match self.entries.iter().find(|&x| { x.name == name }) {
          Some(entry) => entry.data.clone(),
          _ => Vec::new()
      }
    }

    pub fn max_disk_usage(&self) -> usize {
        self.max_disk_usage
    }

    pub fn current_disk_usage(&self) -> usize {
        self.current_disk_usage
    }

    pub fn set_max_disk_usage(&mut self, new_max: usize) {
        assert!(self.current_disk_usage < new_max);
        self.max_disk_usage = new_max;
    }

    pub fn has_chunk(&self, name: NameType) -> bool {
        match self.entries.iter().find(|&x| { x.name == name }) {
            Some(_) => true,
            _ => false
        }
    }

    pub fn names(&self) -> Vec<NameType> {
        let mut name_vec: Vec<NameType> = Vec::new();
        for it in self.entries.iter() {
           name_vec.push(it.name.clone());
        }

        name_vec
    }

    pub fn has_disk_space(&self, required_space: usize) -> bool {
       self.current_disk_usage + required_space <= self.max_disk_usage
    }
}
#[test]
fn dummy()  {
}
