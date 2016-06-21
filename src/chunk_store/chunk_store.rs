// Copyright 2016 MaidSafe.net limited.
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

use std::{cmp, fs};
use std::io::{self, Read, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use maidsafe_utilities::serialisation::{self, SerialisationError};
use rustc_serialize::{Decodable, Encodable};
use rustc_serialize::hex::{FromHex, ToHex};
use tempdir::TempDir;

quick_error! {
    /// `ChunkStore` error.
    #[derive(Debug)]
    pub enum Error {
        /// Error during filesystem IO operations.
        Io(error: io::Error) {
            description("IO error")
            display("IO error: {}", error)
            cause(error)
            from()
        }
        /// Error during serialisation or deserialisation of keys or values.
        Serialisation(error: SerialisationError) {
            description("Serialisation error")
            display("Serialisation error: {}", error)
            cause(error)
            from()
        }
        /// Not enough space in `ChunkStore` to perform `put`.
        NotEnoughSpace {
            description("Not enough space")
            display("Not enough space")
        }
        /// Key, Value pair not found in `ChunkStore`.
        NotFound {
            description("Key, Value not found")
            display("Key, Value not found")
        }
    }
}



/// `ChunkStore` is a store of data held as serialised files on disk, implementing a maximum disk
/// usage to restrict storage.
///
/// The data chunks are deleted when the `ChunkStore` goes out of scope.
pub struct ChunkStore<Key, Value> {
    tempdir: TempDir,
    max_space: u64,
    used_space: u64,
    phantom: PhantomData<(Key, Value)>,
}

impl<Key, Value> ChunkStore<Key, Value>
    where Key: Decodable + Encodable,
          Value: Decodable + Encodable
{
    /// Creates new ChunkStore with `max_space` allowed storage space.
    ///
    /// The data is stored in a temporary directory that contains `prefix` in its name and is placed
    /// in the `root` directory.  If `root` doesn't exist, it will be created.
    pub fn new_in<P: AsRef<Path>>(root: P,
                                  prefix: &str,
                                  max_space: u64)
                                  -> Result<ChunkStore<Key, Value>, Error> {
        fs::create_dir_all(root.as_ref())
            .and_then(|()| TempDir::new_in(root.as_ref(), prefix))
            .map(|tempdir| {
                ChunkStore {
                    tempdir: tempdir,
                    max_space: max_space,
                    used_space: 0,
                    phantom: PhantomData,
                }
            })
            .map_err(From::from)
    }

    /// Stores a new data chunk under `key`.
    ///
    /// If there is not enough storage space available, returns `Error::NotEnoughSpace`.  In case of
    // an IO error, it returns `Error::Io`.
    ///
    /// If the key already exists, it will be overwritten.
    pub fn put(&mut self, key: &Key, value: &Value) -> Result<(), Error> {
        let serialised_value = try!(serialisation::serialise(value));
        if self.used_space + serialised_value.len() as u64 > self.max_space {
            return Err(Error::NotEnoughSpace);
        }

        // If a file corresponding to 'key' already exists, delete it.
        let file_path = try!(self.file_path(key));
        let _ = self.do_delete(&file_path);

        // Write the file.
        fs::File::create(&file_path)
            .and_then(|mut file| {
                file.write_all(&serialised_value)
                    .and_then(|()| file.sync_all())
                    .and_then(|()| file.metadata())
                    .map(|metadata| {
                        self.used_space += metadata.len();
                    })
            })
            .map_err(From::from)
    }

    /// Deletes the data chunk stored under `key`.
    ///
    /// If the data doesn't exist, it does nothing and returns `Ok`.  In the case of an IO error, it
    /// returns `Error::Io`.
    pub fn delete(&mut self, key: &Key) -> Result<(), Error> {
        let file_path = try!(self.file_path(key));
        self.do_delete(&file_path)
    }

    /// Returns a data chunk previously stored under `key`.
    ///
    /// If the data file can't be accessed, it returns `Error::ChunkNotFound`.
    pub fn get(&self, key: &Key) -> Result<Value, Error> {
        match fs::File::open(try!(self.file_path(key))) {
            Ok(mut file) => {
                let mut contents = Vec::<u8>::new();
                let _ = try!(file.read_to_end(&mut contents));
                Ok(try!(serialisation::deserialise::<Value>(&contents)))
            }
            Err(_) => Err(Error::NotFound),
        }
    }

    /// Tests if a data chunk has been previously stored under `key`.
    pub fn has(&self, key: &Key) -> bool {
        let file_path = if let Ok(path) = self.file_path(key) {
            path
        } else {
            return false;
        };
        if let Ok(metadata) = fs::metadata(file_path) {
            return metadata.is_file();
        } else {
            false
        }
    }

    /// Lists all keys of currently-data stored.
    pub fn keys(&self) -> Vec<Key> {
        fs::read_dir(&self.tempdir.path())
            .and_then(|dir_entries| {
                let dir_entry_to_routing_name = |dir_entry: io::Result<fs::DirEntry>| {
                    dir_entry.ok()
                        .and_then(|entry| entry.file_name().into_string().ok())
                        .and_then(|hex_name| hex_name.from_hex().ok())
                        .and_then(|bytes| serialisation::deserialise::<Key>(&*bytes).ok())
                };
                Ok(dir_entries.filter_map(dir_entry_to_routing_name).collect())
            })
            .unwrap_or_else(|_| Vec::new())
    }

    /// Returns the maximum amount of storage space available for this ChunkStore.
    pub fn max_space(&self) -> u64 {
        self.max_space
    }

    /// Returns the amount of storage space already used by this ChunkStore.
    pub fn used_space(&self) -> u64 {
        self.used_space
    }

    fn do_delete(&mut self, file_path: &Path) -> Result<(), Error> {
        if let Ok(metadata) = fs::metadata(file_path) {
            self.used_space -= cmp::min(metadata.len(), self.used_space);
            fs::remove_file(file_path).map_err(From::from)
        } else {
            Ok(())
        }
    }

    fn file_path(&self, key: &Key) -> Result<PathBuf, Error> {
        let filename = try!(serialisation::serialise(key)).to_hex();
        let path_name = Path::new(&filename);
        Ok(self.tempdir.path().join(path_name))
    }
}
