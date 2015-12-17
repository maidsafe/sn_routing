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

#[cfg(test)]
mod test {
    use ::rand::random;
    use xor_name::XorName;

    fn get_random_non_empty_string(length: usize) -> String {
        use rand::Rng;
        let mut string = String::new();
        for char in ::rand::thread_rng().gen_ascii_chars().take(length) {
            string.push(char);
        }
        string
    }

    fn has_child_dir(parent: ::std::path::PathBuf, child_name: &str) -> bool {
        ::std::fs::read_dir(&parent)
            .ok()
            .and_then(|mut dir_entries| {
                dir_entries.find(|dir_entry| {
                    match dir_entry {
                        &Ok(ref entry) => entry.file_name().to_str() == Some(child_name),
                        &Err(_) => false,
                    }
                })
            })
            .is_some()
    }

    #[test]
    fn tempdir_cleanup() {
        let k_disk_size: usize = 116;
        let staled_dir_name = "safe_vault-00000";
        {
            let mut staled_dir = ::std::env::temp_dir();
            staled_dir.push(staled_dir_name);
            ignore_result!(::std::fs::create_dir(&staled_dir));
        }
        assert!(has_child_dir(::std::env::temp_dir(), &staled_dir_name));
        let _ = unwrap_result!(::chunk_store::ChunkStore::new(k_disk_size));
        assert!(!has_child_dir(::std::env::temp_dir(), &staled_dir_name));
    }

    #[test]
    fn successful_store() {
        let k_disk_size: usize = 116;
        let mut chunk_store = unwrap_result!(::chunk_store::ChunkStore::new(k_disk_size));

        let mut names = vec![];

        {
            let mut put = |size| {
                let name = random();
                let data = get_random_non_empty_string(size);
                let size_before_insert = chunk_store.current_disk_usage();
                assert!(!chunk_store.has_chunk(&name));
                chunk_store.put(&name, data.into_bytes());
                assert_eq!(chunk_store.current_disk_usage(), size + size_before_insert);
                assert!(chunk_store.has_chunk(&name));
                names.push(name);
                chunk_store.current_disk_usage()
            };

            assert_eq!(put(1usize), 1usize);
            assert_eq!(put(100usize), 101usize);
            assert_eq!(put(10usize), 111usize);
            assert_eq!(put(5usize), k_disk_size);
        }
        assert_eq!(names.sort(), chunk_store.names().sort());
    }

    #[test]
    fn remove_from_disk_store() {
        let k_size: usize = 1;
        let k_disk_size: usize = 116;
        let mut chunk_store = unwrap_result!(::chunk_store::ChunkStore::new(k_disk_size));

        let mut put_and_delete = |size| {
            let name = random();
            let data = get_random_non_empty_string(size);

            chunk_store.put(&name, data.into_bytes());
            assert_eq!(chunk_store.current_disk_usage(), size);
            chunk_store.delete(&name);
            assert_eq!(chunk_store.current_disk_usage(), 0);
        };

        put_and_delete(k_size);
        put_and_delete(k_disk_size);
    }

    #[test]
    fn put_and_get_value_should_be_same() {
        let data_size = 50;
        let k_disk_size: usize = 116;
        let mut chunk_store = unwrap_result!(::chunk_store::ChunkStore::new(k_disk_size));

        let name = random();
        let data = get_random_non_empty_string(data_size).into_bytes();
        chunk_store.put(&name, data.clone());
        let recovered = chunk_store.get(&name);
        assert_eq!(data, recovered);
        assert_eq!(chunk_store.current_disk_usage(), data_size);
    }

    #[test]
    fn repeatedly_storing_same_name() {
        let k_disk_size: usize = 116;
        let mut chunk_store = unwrap_result!(::chunk_store::ChunkStore::new(k_disk_size));

        let mut put = |name, size| {
            let data = get_random_non_empty_string(size);
            chunk_store.put(&name, data.into_bytes());
            chunk_store.current_disk_usage()
        };

        let name = random::<XorName>();
        assert_eq!(put(name.clone(), 1usize), 1usize);
        assert_eq!(put(name.clone(), 100usize), 100usize);
        assert_eq!(put(name.clone(), 10usize), 10usize);
        assert_eq!(put(name.clone(), 5usize), 5usize);  // last inserted data size
    }
}
