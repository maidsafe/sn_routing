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

use xor_name::XorName;

/// ChunkStore is a collection for holding all data chunks.
/// Implements a maximum disk usage to restrict storage.
pub struct ChunkStore {
    tempdir: ::tempdir::TempDir,
    max_disk_usage: usize,
    current_disk_usage: usize,
}

impl ChunkStore {
    /// Create new chunkstore with `max_disk_usage` allowed disk usage.
    pub fn new(max_disk_usage: usize) -> Result<ChunkStore, ::error::ChunkStoreError> {
        Self::cleanup();
        let folder_name = format!("safe_vault-{}/", Self::get_own_pid());
        let mut path = ::std::env::temp_dir();
        path.push(folder_name);
        ignore_result!(::std::fs::create_dir(&path));

        let tempdir = try!(::tempdir::TempDir::new_in(path, "chunk_store"));
        Ok(ChunkStore {
            tempdir: tempdir,
            max_disk_usage: max_disk_usage,
            current_disk_usage: 0,
        })
    }

    pub fn put(&mut self, name: &XorName, value: Vec<u8>) {
        use ::std::io::Write;

        if !self.has_disk_space(value.len()) {
            return warn!("Not enough space in ChunkStore.");
        }

        // If a file with name 'name' already exists, delete it.
        self.delete(name);

        let hex_name = self.to_hex_string(name);
        let path_name = ::std::path::Path::new(&hex_name);
        let path = self.tempdir.path().join(path_name);
        let _ = ::std::fs::File::create(&path)
            .and_then(|mut file| {
                file.write(&value[..])
                    .and_then(|size| {
                        self.current_disk_usage += size;
                        file.sync_all().map(|_| self.current_disk_usage)
                    })
                    .map(|_| file)
            })
            .or_else(|error| {
                error!("ChunkStore failed to put to file {:?}: {}", path, error);
                Err(error)
            });
    }

    pub fn delete(&mut self, name: &XorName) {
        let _ = self.dir_entry(name)
                    .and_then(|entry| {
                        let _ = entry.metadata()
                                     .and_then(|metadata|
                                         Ok(self.current_disk_usage -= metadata.len() as usize))
                                     .or_else(|error| {
                                         error!("ChunkStore failed to get metadata for {:?}: {}",
                                                entry.path(), error);
                                         Err(error)
                                     });
                        ::std::fs::remove_file(entry.path())
                            .or_else(|error| {
                                error!("ChunkStore failed to remove {:?}: {}", entry.path(), error);
                                Err(error)
                            })
                            .ok()
                    });
    }

    pub fn get(&self, name: &XorName) -> Vec<u8> {
        use ::std::io::Read;
        self.dir_entry(name)
            .and_then(|entry| ::std::fs::File::open(&entry.path()).ok())
            .and_then(|mut file| {
                let mut contents = Vec::<u8>::new();
                file.read_to_end(&mut contents).ok().and_then(|_| Some(contents))
            }).unwrap_or(vec![])
    }

    pub fn max_disk_usage(&self) -> usize {
        self.max_disk_usage
    }

    pub fn current_disk_usage(&self) -> usize {
        self.current_disk_usage
    }

    pub fn has_chunk(&self, name: &XorName) -> bool {
        self.dir_entry(name).is_some()
    }

    pub fn names(&self) -> Vec<XorName> {
        use ::rustc_serialize::hex::FromHex;
        ::std::fs::read_dir(&self.tempdir.path()).and_then(|dir_entries| {
            let dir_entry_to_routing_name = |dir_entry: ::std::io::Result<::std::fs::DirEntry>| {
                dir_entry.ok()
                         .and_then(|entry| entry.file_name().into_string().ok())
                         .and_then(|hex_name| hex_name.from_hex().ok())
                         .and_then(|bytes| Some(XorName::new(
                             ::routing::types::slice_as_u8_64_array(&*bytes))))
            };
            Ok(dir_entries.filter_map(dir_entry_to_routing_name).collect())
        }).unwrap_or(vec![])
    }

    pub fn has_disk_space(&self, required_space: usize) -> bool {
        self.current_disk_usage + required_space <= self.max_disk_usage
    }

    fn to_hex_string(&self, name: &XorName) -> String {
        use ::rustc_serialize::hex::ToHex;
        name.get_id().to_hex()
    }

    fn dir_entry(&self, name: &XorName) -> Option<::std::fs::DirEntry> {
        ::std::fs::read_dir(&self.tempdir.path()).ok().and_then(|mut dir_entries| {
            let hex_name = self.to_hex_string(name);
            dir_entries.find(|dir_entry| {
                match dir_entry {
                    &Ok(ref entry) => entry.file_name().to_str() == Some(&hex_name[..]),
                    &Err(_) => false,
                }
            }).and_then(|entry_result| entry_result.ok())
        })
    }

    fn cleanup() {
        let vault_pids = Self::get_all_vault_pids();
        match vault_pids {
            Some(safe_vault_pids) => {
                let own_pid = format!("{}", Self::get_own_pid());
                let _ = ::std::fs::read_dir(::std::env::temp_dir()).ok().and_then(|dir_entries| {
                    let own_dir: Vec<Result<::std::fs::DirEntry, ::std::io::Error>>
                            = dir_entries.filter(|dir_entry| {
                        match dir_entry {
                            &Ok(ref entry) => {
                                let line = entry.file_name().into_string().ok().unwrap_or(String::from(""));
                                match (line.contains("safe_vault"), line.contains(&own_pid)) {
                                    (true, false) => {
                                        let v: Vec<&str> = line.split("-").collect();
                                        if v.len() > 1 && !safe_vault_pids.contains(&String::from(v[1])) {
                                            // As the dir itself is not atomic, there is chance other vault
                                            // has cleaned up the directory, no need to panic here
                                            ignore_result!(::std::fs::remove_dir_all(entry.path()));
                                        }
                                    }
                                    (true, true) => return true,
                                    (false, _) => {},
                                }
                            }
                            &Err(_) => {},
                        }
                        false
                    }).collect();
                    Some(own_dir.len())
                });
            }
            None => {},
        }
    }

    #[allow(unsafe_code)]
    fn get_own_pid() -> u32 {
        extern { fn getpid() -> u32; }
        unsafe { getpid() }
    }

    #[cfg(windows)]
    fn get_all_vault_pids() -> Option<Vec<String>> {
        let output = match ::std::process::Command::new("tasklist").output() {
            Ok(output) => output,
            Err(e) => {
                warn!("failed to execute process: {}", e);
                return None;
            }
        };
        Some(Self::find_safe_vault_processes(
                String::from_utf8_lossy(&output.stdout).split("\n").collect(), 1))
    }

    #[cfg(not(windows))]
    fn get_all_vault_pids() -> Option<Vec<String>> {
        let output = match ::std::process::Command::new("ps").arg("-h").output() {
            Ok(output) => output,
            Err(e) => {
                warn!("failed to execute process: {}", e);
                return None;
            }
        };
        Some(Self::find_safe_vault_processes(
                String::from_utf8_lossy(&output.stdout).split("\n").collect(), 0))
    }

    fn find_safe_vault_processes(lines: Vec<&str>, column: usize) -> Vec<String> {
        lines.iter().filter_map(|line| {
            if line.contains("safe_vault") {
                let vv: Vec<&str> = line.split_whitespace().collect();
                Some(String::from(vv[column]))
            } else {
                None
            }
        }).collect()
    }

}
