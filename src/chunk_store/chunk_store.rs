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

/// Chunkstore is a collection for holding all data chunks.
/// Implements a maximum disk usage to restrict storage.
pub struct ChunkStore {
    tempdir: ::tempdir::TempDir,
    max_disk_usage: usize,
    current_disk_usage: usize,
}

impl ChunkStore {
    /// Create new chunkstore with `max_disk_usage` allowed disk usage.
    pub fn new(max_disk_usage: usize) -> ChunkStore {
        ChunkStore {
            // FIXME - Do we really want to panic?  Can we run without chunkstore?  Or try some
            // other path.  Either way, we could return an error which would indicate to the user to
            // specify a different path via the config file.
            tempdir: evaluate_result!(::tempdir::TempDir::new("safe_vault")),
            max_disk_usage: max_disk_usage,
            current_disk_usage: 0,
        }
    }

    pub fn put(&mut self, name: &::routing::NameType, value: Vec<u8>) {
        use ::std::io::Write;

        // FIXME - we probably shouldn't panic here.  Same comments as above in ChunkStore::new.
        if !self.has_disk_space(value.len()) {
            panic!("Disk space unavailable. Not enough space");
        }

        // If a file with name 'name' already exists, delete it.
        self.delete(name);

        let hex_name = self.to_hex_string(name);
        let path_name = ::std::path::Path::new(&hex_name);
        let path = self.tempdir.path().join(path_name);
        // FIXME - another panic.
        let mut file = evaluate_result!(::std::fs::File::create(&path));

        let _ = file.write(&value[..]).and_then(|size| Ok(self.current_disk_usage += size));
        let _ = file.sync_all();
    }

    pub fn delete(&mut self, name: &::routing::NameType) {
        let _ = self.dir_entry(name)
                    .and_then(|entry| {
                        let _ = entry.metadata().and_then(|metadata|
                                    Ok(self.current_disk_usage -= metadata.len() as usize));
                        ::std::fs::remove_file(entry.path()).ok()
                    });
    }

    pub fn get(&self, name: &::routing::NameType) -> Vec<u8> {
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

    pub fn has_chunk(&self, name: &::routing::NameType) -> bool {
        self.dir_entry(name).is_some()
    }

    pub fn names(&self) -> Vec<::routing::NameType> {
        use ::rustc_serialize::hex::FromHex;
        ::std::fs::read_dir(&self.tempdir.path()).and_then(|dir_entries| {
            let dir_entry_to_routing_name = |dir_entry: ::std::io::Result<::std::fs::DirEntry>| {
                dir_entry.ok()
                         .and_then(|entry| entry.file_name().into_string().ok())
                         .and_then(|hex_name| hex_name.from_hex().ok())
                         .and_then(|bytes| Some(::routing::NameType::new(
                             ::routing::types::vector_as_u8_64_array(bytes))))
            };
            Ok(dir_entries.filter_map(dir_entry_to_routing_name).collect())
        }).unwrap_or(vec![])
    }

    pub fn has_disk_space(&self, required_space: usize) -> bool {
        self.current_disk_usage + required_space <= self.max_disk_usage
    }

    fn to_hex_string(&self, name: &::routing::NameType) -> String {
        use ::rustc_serialize::hex::ToHex;
        name.get_id().to_hex()
    }

    fn dir_entry(&self, name: &::routing::NameType) -> Option<::std::fs::DirEntry> {
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
}
