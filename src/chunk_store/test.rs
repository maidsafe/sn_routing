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
  use routing_types::*;

  static ONE_KB: usize = 1024;

  static K_DEFAULT_MAX_DISK_USAGE: usize = 4 * 1024;// // 4 * OneKB;

  struct NameValueContainer(Vec<(NameType, String)>);

  fn get_random_non_empty_string(length: usize) -> String {
      use rand::Rng;
      let mut string = String::new();
      for char in ::rand::thread_rng().gen_ascii_chars().take(length) {
          string.push(char);
      }
      string
  }

  fn add_random_name_value_pairs(number: usize, size: usize) -> NameValueContainer {
      let mut i = 0usize;
      let mut container: Vec<(NameType, String)> = Vec::with_capacity(number);
      loop {
          container.push((NameType(vector_as_u8_64_array(generate_random_vec_u8(64))),
                          get_random_non_empty_string(size)));
          i += 1; // i++; is not compiling
          if i == number {
              break;
          }
      }
      NameValueContainer(container)
  }

  struct ChunkStoreTest {
      chunk_store: ::chunk_store::ChunkStore,
      max_disk_storage: usize
  }

  impl ChunkStoreTest {
      pub fn new() -> ChunkStoreTest {
          ChunkStoreTest {
              chunk_store: ::chunk_store::ChunkStore::with_max_disk_usage(K_DEFAULT_MAX_DISK_USAGE),
              max_disk_storage: K_DEFAULT_MAX_DISK_USAGE
          }
      }

  //    pub fn delete_directory(dir_path: &str) -> bool {
  //        match remove_dir_all(dir_path) {
  //            Ok(_) => true,
  //            Err(_) => false
  //        }
  //    }

      pub fn put(&mut self, name: NameType, value: Vec<u8>) {
          self.chunk_store.put(name, value);
      }

      pub fn populate_chunk_store(&mut self, num_entries: usize, disk_entries: usize) -> NameValueContainer {
          let name_value_pairs = add_random_name_value_pairs(num_entries, ONE_KB);
          let disk_usage = disk_entries * ONE_KB;
          self.chunk_store = ::chunk_store::ChunkStore::with_max_disk_usage(disk_usage);
          self.max_disk_storage = disk_usage;
          for name_value in name_value_pairs.0.clone() {
              let data_as_bytes = name_value.1.into_bytes();
              self.chunk_store.put(NameType::new(name_value.0.clone().get_id()), data_as_bytes.clone());
              let recovered = self.chunk_store.get(NameType::new(name_value.0.clone().get_id()));
              assert!(data_as_bytes == recovered);
          }
          name_value_pairs
      }
  }

  #[test]
  fn constructor_initialization() {
      let mut store_1 = ::chunk_store::ChunkStore::new();
      let store_2 = ::chunk_store::ChunkStore::with_max_disk_usage(K_DEFAULT_MAX_DISK_USAGE);
      store_1.set_max_disk_usage(K_DEFAULT_MAX_DISK_USAGE);
      assert_eq!(store_1.max_disk_usage(), store_2.max_disk_usage());
  }

  #[test]
  fn successful_store() {
      let k_disk_size: usize = 116;
      let mut chunk_store = ::chunk_store::ChunkStore::with_max_disk_usage(k_disk_size);

      let mut put = |size| {
          let name = NameType(vector_as_u8_64_array(generate_random_vec_u8(64)));
          let data = get_random_non_empty_string(size);
          let size_before_insert = chunk_store.current_disk_usage();
          chunk_store.put(name, data.into_bytes());
          assert_eq!(chunk_store.current_disk_usage(), size + size_before_insert);
          chunk_store.current_disk_usage()
      };

      assert_eq!(put(1usize), 1usize);
      assert_eq!(put(100usize), 101usize);
      assert_eq!(put(10usize), 111usize);
      assert_eq!(put(5usize), k_disk_size);
  }

  #[test]
  #[should_panic]
  fn should_fail_if_chunk_size_is_greater_than_max_disk_size() {
      let k_disk_size: usize = 116;
      let mut chunk_store = ::chunk_store::ChunkStore::with_max_disk_usage(k_disk_size);
      let name = NameType(vector_as_u8_64_array(generate_random_vec_u8(64)));
      let data = get_random_non_empty_string(k_disk_size + 1);
      chunk_store.put(name, data.into_bytes());
  }

  #[test]
  fn remove_from_disk_store() {
      let k_size: usize = 1;
      let k_disk_size: usize = 116;
      let mut chunk_store = ::chunk_store::ChunkStore::with_max_disk_usage(k_disk_size);

      let mut put_and_delete = |size| {
          let name = NameType(vector_as_u8_64_array(generate_random_vec_u8(64)));
          let data = get_random_non_empty_string(size);

          chunk_store.put(name.clone(), data.into_bytes());
          assert_eq!(chunk_store.current_disk_usage(), size);
          chunk_store.delete(name);
          assert_eq!(chunk_store.current_disk_usage(), 0);
      };

      put_and_delete(k_size);
      put_and_delete(k_disk_size);
  }

  #[test]
  #[should_panic]
  fn should_fail_on_disk_overfill() {
      let num_entries = 4;
      let num_disk_entries = 4;
      let mut chunk_store_utest = ChunkStoreTest::new();
      let name_value_container = chunk_store_utest.populate_chunk_store(num_entries, num_disk_entries).0;
      let name = NameType(vector_as_u8_64_array(generate_random_vec_u8(64)));
      let value = get_random_non_empty_string(2 * ONE_KB);
      // let first_name: routing::NameType = name_value_container[0].0.clone();
      let _ = name_value_container[0].0.clone();
      // let second_name: routing::NameType = name_value_container[1].0.clone();
      let _ = name_value_container[1].0.clone();
      chunk_store_utest.put(name, value.into_bytes());
  }

  #[test]
  fn put_and_get_value_should_be_same() {
      let data_size = 50;
      let k_disk_size: usize = 116;
      let mut chunk_store = ::chunk_store::ChunkStore::with_max_disk_usage(k_disk_size);

      let name = NameType(vector_as_u8_64_array(generate_random_vec_u8(64)));
      let data = get_random_non_empty_string(data_size).into_bytes();
      chunk_store.put(name.clone(), data.clone());
      let recovered = chunk_store.get(name);
      assert_eq!(data, recovered);
      assert_eq!(chunk_store.current_disk_usage(), data_size);
  }

  #[test]
  fn repeatedly_storing_same_name() {
      let k_disk_size: usize = 116;
      let mut chunk_store = ::chunk_store::ChunkStore::with_max_disk_usage(k_disk_size);

      let mut put = |name, size| {
          let data = get_random_non_empty_string(size);
          chunk_store.put(name, data.into_bytes());
          chunk_store.current_disk_usage()
      };

      let name = NameType(vector_as_u8_64_array(generate_random_vec_u8(64)));
      assert_eq!(put(name.clone(), 1usize), 1usize);
      assert_eq!(put(name.clone(), 100usize), 100usize);
      assert_eq!(put(name.clone(), 10usize), 10usize);
      assert_eq!(put(name.clone(), 5usize), 5usize);  // last inserted data size
  }
}
