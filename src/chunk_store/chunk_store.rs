/*  Copyright 2015 MaidSafe.net limited
    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").
    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses
    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.
    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe
    Software.                                                                 */

#![allow(dead_code)]

extern crate self_encryption;
use std::convert::AsRef;

static AES256_KEY_SIZE: usize = 32;
static AES256_IV_SIZE: usize = 16;

pub struct Entry {
  name: Vec<u8>,
  data: Vec<u8>
}

pub struct ChunkStore {
  entries: Vec<Entry>,
  max_disk_usage: usize,
  current_disk_usage: usize,
}

impl ChunkStore {
  pub fn new() -> ChunkStore {
    ChunkStore {
      entries: Vec::new(),
      max_disk_usage: 0,
      current_disk_usage: 0,
    }
  }

  pub fn put(&mut self, name: Vec<u8>, value: Vec<u8>) {
    let mut iv: Vec<u8> = Vec::with_capacity(AES256_IV_SIZE);
    let mut key: Vec<u8> = Vec::with_capacity(AES256_KEY_SIZE);

    for it in name.iter().take(AES256_KEY_SIZE) {
      key.push(*it);
    }
    for it in name.iter().skip(AES256_KEY_SIZE).take(AES256_IV_SIZE) {
      iv.push(*it);
    }

    match self_encryption::encryption::encrypt(value.as_ref(), key.as_ref(), iv.as_ref()) {
      Ok(content) => {
        self.current_disk_usage += content.len();

        self.entries.push(Entry {
          name: name,
          data: content,
        });
      },
      _ => panic!("Unable to encrypt")
    };
  }

  pub fn delete(&mut self, name: Vec<u8>) {
    let mut size_removed = 0usize;

    for i in 0..self.entries.len() {
      if self.entries[i].name == name {
        size_removed = self.entries[i].data.len();
        self.entries.remove(i);
        break;
      }
    }

    self.current_disk_usage -= size_removed;
  }

  pub fn get(&self, name: Vec<u8>) -> Vec<u8> {
    let mut return_val: Vec<u8> = Vec::new();

    for it in self.entries.iter() {
      if it.name == name {
        let mut iv: Vec<u8> = Vec::with_capacity(AES256_IV_SIZE);
        let mut key: Vec<u8> = Vec::with_capacity(AES256_KEY_SIZE);

        for it in name.iter().take(AES256_KEY_SIZE) {
          key.push(*it);
        }
        for it in name.iter().skip(AES256_KEY_SIZE).take(AES256_IV_SIZE) {
          iv.push(*it);
        }

        match self_encryption::encryption::decrypt(it.data.as_ref(), key.as_ref(), iv.as_ref()) {
          Ok(vec) => return_val = vec,
          _ => panic!("Unable to decrypt"),
        };
        break;
      }
    }

    assert!(!return_val.is_empty());
    return_val
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

  pub fn has_chunk(&self, name: Vec<u8>) -> bool {
    for entry in self.entries.iter() {
      if entry.name == name {
        return true;
      }
    }
    false
  }

  pub fn names(&self) -> Vec<Vec<u8>> {
    let mut name_vec: Vec<Vec<u8>> = Vec::new();
    for it in self.entries.iter() {
      name_vec.push(it.name.clone());
    }

    name_vec
  }
// FIXME: Unused
  // fn has_disk_space(&self, required_space: usize) -> bool {
  //   self.current_disk_usage + required_space <= self.max_disk_usage
  // }
}
