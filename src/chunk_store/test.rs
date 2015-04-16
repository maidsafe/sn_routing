#[cfg(test)]
mod test {
  extern crate rand;
  extern crate maidsafe_types;
  extern crate routing;


  use rand::{thread_rng, Rng};
  use chunk_store::ChunkStore;
  use self::routing::types::DhtId;

  static ONE_KB: usize = 1024;

  static K_DEFAULT_MAX_DISK_USAGE: usize = 4 * 1024;// // 4 * OneKB;

  struct NameValueContainer(Vec<(maidsafe_types::NameType, String)>);

  fn get_random_name_type() ->  maidsafe_types::NameType {
      let mut v = [0u8; 64];
      thread_rng().fill_bytes(&mut v);
      maidsafe_types::NameType(v)
  }

  fn get_random_non_empty_string(length: usize) -> String {
      let mut string = String::new();
      for char in rand::thread_rng().gen_ascii_chars().take(length) {
          string.push(char);
      }
      string
  }

  fn add_random_name_value_pairs(number: usize, size: usize) -> NameValueContainer {
      let mut i = 0usize;
      let mut container: Vec<(maidsafe_types::NameType, String)> = Vec::with_capacity(number);
      loop {
          container.push((get_random_name_type(), get_random_non_empty_string(size)));
          i += 1; // i++; is not compiling
          if i == number {
              break;
          }
      }
      NameValueContainer(container)
  }

  struct ChunkStoreTest {
      chunk_store: ChunkStore,
      max_disk_storage: usize
  }

  impl ChunkStoreTest {
      pub fn new() -> ChunkStoreTest {
          ChunkStoreTest {
              chunk_store: ChunkStore::with_max_disk_usage(K_DEFAULT_MAX_DISK_USAGE),
              max_disk_storage: K_DEFAULT_MAX_DISK_USAGE
          }
      }

  //    pub fn delete_directory(dir_path: &str) -> bool {
  //        match remove_dir_all(dir_path) {
  //            Ok(_) => true,
  //            Err(_) => false
  //        }
  //    }

      pub fn put(&mut self, name: DhtId, value: Vec<u8>) {
          self.chunk_store.put(name, value);
      }

      pub fn populate_chunk_store(&mut self, num_entries: usize, disk_entries: usize) -> NameValueContainer {
          let name_value_pairs = add_random_name_value_pairs(num_entries, ONE_KB);
          let disk_usage = disk_entries * ONE_KB;
          self.chunk_store = ChunkStore::with_max_disk_usage(disk_usage);
          self.max_disk_storage = disk_usage;
          for name_value in name_value_pairs.0.clone() {
              let data_as_bytes = name_value.1.into_bytes();
              self.chunk_store.put(DhtId::new(&name_value.0.clone().get_id()), data_as_bytes.clone());
              let recovered = self.chunk_store.get(DhtId::new(&name_value.0.clone().get_id()));
              assert!(data_as_bytes == recovered);
          }
          name_value_pairs
      }
  }

  #[test]
  fn constructor_initialization() {
      let mut store_1 = ChunkStore::new();
      let store_2 = ChunkStore::with_max_disk_usage(K_DEFAULT_MAX_DISK_USAGE);
      store_1.set_max_disk_usage(K_DEFAULT_MAX_DISK_USAGE);
      assert_eq!(store_1.max_disk_usage(), store_2.max_disk_usage());
  }

  #[test]
  fn successful_store() {
      let k_disk_size: usize = 116;
      let mut chunk_store = ChunkStore::with_max_disk_usage(k_disk_size);

      let mut put = |size| {
          let name = DhtId::generate_random();
          let data = get_random_non_empty_string(size);
          let size_before_insert = chunk_store.current_disk_usage();
          chunk_store.put(name, data.into_bytes());
          assert_eq!(chunk_store.current_disk_usage(), size + size_before_insert);
          chunk_store.current_disk_usage()
      };

      put(1usize);
      put(100usize);
      put(10usize);
      assert_eq!(put(5usize), k_disk_size);
  }

  #[test]
  #[should_panic]
  fn should_fail_if_chunk_size_is_greater_than_max_disk_size() {
      let k_disk_size: usize = 116;
      let mut chunk_store = ChunkStore::with_max_disk_usage(k_disk_size);
      let name = DhtId::generate_random();
      let data = get_random_non_empty_string(k_disk_size + 1);
      chunk_store.put(name, data.into_bytes());
  }

  #[test]
  fn remove_from_disk_store() {
      let k_size: usize = 1;
      let k_disk_size: usize = 116;
      let mut chunk_store = ChunkStore::with_max_disk_usage(k_disk_size);

      let mut put_and_delete = |size| {
          let name = DhtId::generate_random();
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
      let name = DhtId::generate_random();
      let value = get_random_non_empty_string(2 * ONE_KB);
      // let first_name: maidsafe_types::NameType = name_value_container[0].0.clone();
      name_value_container[0].0.clone();
      // let second_name: maidsafe_types::NameType = name_value_container[1].0.clone();
      name_value_container[1].0.clone();
      chunk_store_utest.put(name, value.into_bytes());
  }

  #[test]
  fn put_and_get_value_should_be_same() {
      let data_size = 50;
      let k_disk_size: usize = 116;
      let mut chunk_store = ChunkStore::with_max_disk_usage(k_disk_size);

      let name = DhtId::generate_random();
      let data = get_random_non_empty_string(data_size).into_bytes();
      chunk_store.put(name.clone(), data.clone());
      let recovered = chunk_store.get(name);
      assert_eq!(data, recovered);
      assert_eq!(chunk_store.current_disk_usage(), data_size);
  }

  #[test]
  fn repeatedly_storing_same_name() {
      let k_disk_size: usize = 116;
      let mut chunk_store = ChunkStore::with_max_disk_usage(k_disk_size);

      let mut put = |name, size| {
          let data = get_random_non_empty_string(size);
          chunk_store.put(name, data.into_bytes());
          chunk_store.current_disk_usage()
      };

      let name = DhtId::generate_random();
      put(name.clone(), 1usize);
      put(name.clone(), 100usize);
      put(name.clone(), 10usize);
      assert_eq!(put(name.clone(), 5usize), 5);// last inserted data size
  }

}
