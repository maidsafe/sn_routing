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

macro_rules! assert_err {
    ($cond : expr, $error : pat) => {
        match $cond {
            Err($error) => (),
            result => panic!(concat!("Expecting ", stringify!($error), " got {:?}"), result),
        }
    }
}

#[cfg(test)]
mod test {
    use std::env;
    use std::path::PathBuf;

    use chunk_store::{ChunkStore, Error};
    use maidsafe_utilities::serialisation;
    use rand::{self, Rng};
    use tempdir::TempDir;

    #[cfg_attr(feature="clippy", allow(cast_possible_truncation))]
    fn generate_random_bytes(size: u64) -> Vec<u8> {
        rand::thread_rng().gen_iter().take(size as usize).collect()
    }

    struct Chunks {
        data_and_sizes: Vec<(Vec<u8>, u64)>,
        total_size: u64,
    }

    // Construct random amount of randomly-sized chunks, keeping track of the total size of all
    // chunks when serialised.
    fn generate_random_chunks() -> Chunks {
        let mut chunks = Chunks {
            data_and_sizes: vec![],
            total_size: 0,
        };
        let chunk_count: u8 = rand::random();
        for _ in 0..chunk_count {
            let size: u8 = rand::random();
            let data = generate_random_bytes(size as u64);
            let serialised_size = unwrap_result!(serialisation::serialise(&data)).len() as u64;
            chunks.total_size += serialised_size;
            chunks.data_and_sizes.push((data, serialised_size));
        }
        chunks
    }

    fn temp_test_dir() -> PathBuf {
        use rustc_serialize::hex::ToHex;
        let mut temp_dir = env::temp_dir();
        temp_dir.push(rand::thread_rng().gen_iter().take(8).collect::<Vec<u8>>().to_hex());
        temp_dir
    }

    #[test]
    fn create_multiple_instances_in_the_same_root() {
        // root already exists
        {
            let root = unwrap_result!(TempDir::new("test"));

            let _1 = unwrap_result!(ChunkStore::<u64, u64>::new(root.path().join("store-1"), 64));
            let _2 = unwrap_result!(ChunkStore::<u64, u64>::new(root.path().join("store-2"), 64));
        }

        // root doesn't exist yet
        {
            let root = unwrap_result!(TempDir::new("test"));
            let root_path = root.path().join("foo").join("bar");

            let _1 = unwrap_result!(ChunkStore::<u64, u64>::new(root_path.join("store-1"), 64));
            let _2 = unwrap_result!(ChunkStore::<u64, u64>::new(root_path.join("store-2"), 64));
        }
    }

    #[test]
    fn storedir_cleanup() {
        let tempdir = unwrap_result!(TempDir::new("test"));
        let storedir = tempdir.path().join("test");

        {
            let _store = ChunkStore::<u64, u64>::new(storedir.clone(), 64);
            assert!(storedir.exists());
        }

        assert!(!storedir.exists());
    }

    #[test]
    fn successful_put() {
        let chunks = generate_random_chunks();
        let mut chunk_store = unwrap_result!(ChunkStore::new(temp_test_dir().join("test"),
                                                             chunks.total_size));
        {
            let mut put = |key, value, size| {
                let size_before_insert = chunk_store.used_space();
                assert!(!chunk_store.has(&key));
                unwrap_result!(chunk_store.put(&key, value));
                assert_eq!(chunk_store.used_space(), size + size_before_insert);
                assert!(chunk_store.has(&key));
                assert!(chunk_store.used_space() <= chunks.total_size);
            };

            for (index, &(ref data, ref size)) in chunks.data_and_sizes
                .iter()
                .enumerate()
                .rev() {
                put(index, data, size);
            }
        }
        assert_eq!(chunk_store.used_space(), chunks.total_size);

        let mut keys = chunk_store.keys();
        keys.sort();
        assert_eq!((0..chunks.data_and_sizes.len()).collect::<Vec<_>>(), keys);
    }

    #[test]
    fn failed_put_when_not_enough_space() {
        let k_disk_size = 32;
        let mut store = unwrap_result!(ChunkStore::new(temp_test_dir().join("test"), k_disk_size));
        let key: u8 = rand::random();
        let data = generate_random_bytes(k_disk_size + 1);

        assert_err!(store.put(&key, &data), Error::NotEnoughSpace);
    }

    #[test]
    fn delete() {
        let chunks = generate_random_chunks();
        let mut chunk_store = unwrap_result!(ChunkStore::new(temp_test_dir().join("test"),
                                                             chunks.total_size));
        let mut put_and_delete = |key, value, size| {
            unwrap_result!(chunk_store.put(&key, value));
            assert_eq!(chunk_store.used_space(), size);
            assert!(chunk_store.has(&key));
            unwrap_result!(chunk_store.delete(&key));
            assert!(!chunk_store.has(&key));
            assert_eq!(chunk_store.used_space(), 0);
        };

        for (index, &(ref data, ref size)) in chunks.data_and_sizes.iter().enumerate() {
            put_and_delete(index, data, *size);
        }
    }

    #[test]
    fn put_and_get_value_should_be_same() {
        let chunks = generate_random_chunks();
        let mut chunk_store = unwrap_result!(ChunkStore::new(temp_test_dir().join("test"),
                                                             chunks.total_size));
        for (index, &(ref data, _)) in chunks.data_and_sizes.iter().enumerate() {
            unwrap_result!(chunk_store.put(&(index as u32), data));
        }
        for (index, &(ref data, _)) in chunks.data_and_sizes.iter().enumerate() {
            let retrieved_value = unwrap_result!(chunk_store.get(&(index as u32)));
            assert!(*data == retrieved_value);
        }
    }

    #[test]
    fn overwrite_value() {
        let chunks = generate_random_chunks();
        let mut chunk_store = unwrap_result!(ChunkStore::new(temp_test_dir().join("test"),
                                                             chunks.total_size));
        for (ref data, ref size) in chunks.data_and_sizes {
            unwrap_result!(chunk_store.put(&0, data));
            assert_eq!(chunk_store.used_space(), *size);
            let retrieved_value = unwrap_result!(chunk_store.get(&0));
            assert!(*data == retrieved_value);
        }
    }

    #[test]
    fn get_fails_when_key_does_not_exist() {
        let chunk_store = unwrap_result!(ChunkStore::<u8, u8>::new(temp_test_dir().join("test"),
                                                                   64));
        let key = rand::random();
        assert_err!(chunk_store.get(&key), Error::NotFound);
    }

    #[test]
    fn keys() {
        let chunks = generate_random_chunks();
        let mut chunk_store = unwrap_result!(ChunkStore::new(temp_test_dir().join("test"),
                                                             chunks.total_size));

        for (index, &(ref data, _)) in chunks.data_and_sizes.iter().enumerate() {
            assert!(!chunk_store.keys().contains(&index));
            unwrap_result!(chunk_store.put(&index, data));
            assert!(chunk_store.keys().contains(&index));
            assert_eq!(chunk_store.keys().len(), index + 1);
        }

        for (index, _) in chunks.data_and_sizes.iter().enumerate() {
            assert!(chunk_store.keys().contains(&index));
            unwrap_result!(chunk_store.delete(&index));
            assert!(!chunk_store.keys().contains(&index));
            assert_eq!(chunk_store.keys().len(),
                       chunks.data_and_sizes.len() - index - 1);
        }
    }
}
