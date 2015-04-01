extern crate maidsafe_types;
extern crate rand;

use rand::{thread_rng, Rng};
use std::str;
use chunk_store::ChunkStore;
use std::path::Path;
use std::fs::{remove_dir_all};

static ONE_KB: u64 = 1024u64;
static AES_PADDING: u64 = 16u64;
// Allow 16 bytes extra per chunk since we're AES encrypting them
static K_DEFAULT_MAX_DISK_USAGE: u64 = 4 * 1024u64 * 16u64; // 4 * (OneKB + AesPadding);

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
        i = i + 1; // i++; is not compiling
        if i == number {
          break;
        }
    }
    NameValueContainer(container)
}

// TODO (Krishna) - Must support file storage, once the ChunkStore supports file storage. At present ChunkStore is in-memory storage
struct ChunkStoreTest {
    chunk_store: ChunkStore,
    max_disk_storage: u64
}

impl ChunkStoreTest {
    pub fn new() -> ChunkStoreTest {
        ChunkStoreTest {
        chunk_store: ChunkStore::new(),
        max_disk_storage: K_DEFAULT_MAX_DISK_USAGE
        }
    }

    fn delete_directory(dir_path: &str) -> bool {
        match remove_dir_all(dir_path) {
            Ok(_) => true,
            Err(_) => false
          }
    }

    fn populate_chunk_store(&mut self, num_entries: u32, disk_entries: u32) -> NameValueContainer {
        let mut name_value_pairs = add_random_name_value_pairs(num_entries as usize, ONE_KB as usize);
        // DiskUsage disk_usage(disk_entries * (OneKB + AesPadding)); C++ equivalent of the line below.
        // Must check what DiskUsage type actually is
        let disk_usage = (disk_entries as u64) * (ONE_KB + AES_PADDING);
        // chunk_store_.reset(new ChunkStore(chunk_store_path_, disk_usage));
        // CLARIFY :: Next two lines are the conversion of the above C++ equivalent.
        self.chunk_store = ChunkStore::new();
        self.chunk_store.set_max_disk_usage(K_DEFAULT_MAX_DISK_USAGE as usize);
        for name_value in name_value_pairs.0.clone() {
            let data_as_bytes = name_value.1.into_bytes();
            self.chunk_store.put(maidsafe_types::helper::array_as_vector(&name_value.0.clone().get_id()), data_as_bytes.clone());
            let recovered = self.chunk_store.get(maidsafe_types::helper::array_as_vector(&name_value.0.clone().get_id()));
            assert!(data_as_bytes == recovered);
        }
        name_value_pairs
    }
}