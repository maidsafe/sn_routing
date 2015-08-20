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
// relating to use of the SAFE Network Software.

#![allow(dead_code)]
#![deny(missing_docs)]

use routing_types::{NameType, vector_as_u8_64_array};
use std::fs::{File, read_dir, remove_file};
use std::ffi::OsStr;
use std::path::Path;
use std::io::{Read, Write};
use tempdir;
use rustc_serialize::hex::{ToHex, FromHex};


/// Chunkstore is a collection for holding all data chunks.
/// Implements a maximum disk usage to restrict storage.
pub struct ChunkStore {
    tempdir: tempdir::TempDir,
    max_disk_usage: usize,
    current_disk_usage: usize,
}

impl ChunkStore {
    /// Create new chunkstore with zero allowed disk usage.
    pub fn new() -> ChunkStore {
        ChunkStore {
            tempdir: tempdir::TempDir::new("safe_vault").unwrap(),
            max_disk_usage: 0,
            current_disk_usage: 0,
        }
    }

    pub fn with_max_disk_usage(max_disk_usage: usize) -> ChunkStore {
        ChunkStore {
            tempdir: tempdir::TempDir::new("safe_vault").unwrap(),
            max_disk_usage: max_disk_usage,
            current_disk_usage: 0,
        }
    }

    pub fn put(&mut self, name: NameType, value: Vec<u8>) {
        if !self.has_disk_space(value.len()) {
            panic!("Disk space unavailable. Not enough space");
        }

        // If a file with name 'name' already exists, delete it.
        self.delete(name.clone());

        let name = self.to_hex_string(&name);
        let path_name = Path::new(&name);
        let path = self.tempdir.path();
        let path = path.join(path_name);
        let mut file = File::create(&path).unwrap();

        match file.write(&value[..]) {
            Ok(size) => self.current_disk_usage += size,
            _ => (),
        }
        let _ = file.sync_all();
    }

    pub fn delete(&mut self, name: NameType) {
        let name = self.to_hex_string(&name);

        match read_dir(&self.tempdir.path()) {
            Ok(dir_entries) => {
                for dir_entry in dir_entries {
                    match dir_entry {
                        Ok(entry) => {
                            if entry.file_name().to_str() == OsStr::new(&name).to_str() {
                                match entry.metadata() {
                                    Ok(metadata) => {
                                        let len = metadata.len() as usize;
                                        let _ = remove_file(entry.path());
                                        self.current_disk_usage -= len;
                                    },
                                    _ => ()
                                }
                                return
                            }
                        },
                        _ => ()
                    }
                }
            },
            _ => ()
        }
    }

    pub fn get(&self, name: NameType) -> Vec<u8> {
        let name = self.to_hex_string(&name);

        match read_dir(&self.tempdir.path()) {
            Ok(dir_entries) => {
                for dir_entry in dir_entries {
                    match dir_entry {
                        Ok(entry) => {
                            if entry.file_name().to_str() == OsStr::new(&name).to_str() {
                                match File::open(&entry.path()) {
                                    Ok(mut file) => {
                                        let mut contents = Vec::<u8>::new();
                                        let _ = file.read_to_end(&mut contents);
                                        return contents;
                                    },
                                    _ => (),
                                }
                            }
                        },
                        _ => (),
                    }
                }
            },
            _ => return Vec::new(),
        }

        Vec::new()
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
        let name = self.to_hex_string(&name);

        match read_dir(&self.tempdir.path()) {
            Ok(dir_entries) => {
                for dir_entry in dir_entries {
                    match dir_entry {
                        Ok(entry) => {
                            if entry.file_name().to_str() == OsStr::new(&name).to_str() {
                                return true;
                            }
                        },
                        _ => (),
                    }
                }
            },
            _ => return false,
        }

        false
    }

    pub fn names(&self) -> Vec<NameType> {
        let mut names: Vec<NameType> = Vec::new();

        match read_dir(&self.tempdir.path()) {
            Ok(dir_entries) => {
                for dir_entry in dir_entries {
                    match dir_entry {
                        Ok(entry) => {
                            match entry.file_name().to_str() {
                                Some(hex_name) => {
                                    match hex_name.from_hex() {
                                        Ok(name) =>
                                            names.push(NameType::new(vector_as_u8_64_array(name))),
                                        _ => (),
                                    }
                                },
                                _ => (),
                            }
                        },
                        _ => (),
                    }
                }
            },
            _ => ()
        }

        names
    }

    pub fn has_disk_space(&self, required_space: usize) -> bool {
       self.current_disk_usage + required_space <= self.max_disk_usage
    }

    fn to_hex_string(&self, name: &NameType) -> String {
        name.get_id().to_hex()
    }
}
