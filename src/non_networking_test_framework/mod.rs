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

#![allow(unsafe_code, unused)] // TODO Remove the unused attribute later

mod macros;
pub mod mock_routing_types;

use std::io::{Read, Write};

use self::mock_routing_types::*;

type DataStore = ::std::sync::Arc<::std::sync::Mutex<::std::collections::HashMap<NameType, Vec<u8>>>>;

const STORAGE_FILE_NAME: &'static str = "VaultStorageSimulation";

struct PersistentStorageSimulation {
    data_store: DataStore,
}

// This is a hack because presently cbor isn't able to encode HashMap<NameType, Vec<u8>>
pub fn convert_hashmap_to_vec(hashmap: &::std::collections::HashMap<NameType, Vec<u8>>) -> Vec<(NameType, Vec<u8>)> {
    hashmap.iter().map(|a| (a.0.clone(), a.1.clone())).collect()
}

// This is a hack because presently cbor isn't able to encode HashMap<NameType, Vec<u8>>
pub fn convert_vec_to_hashmap(vec: Vec<(NameType, Vec<u8>)>) -> ::std::collections::HashMap<NameType, Vec<u8>> {
    vec.into_iter().collect()
}

fn get_storage() -> DataStore {
    static mut STORAGE: *const PersistentStorageSimulation = 0 as *const PersistentStorageSimulation;
    static mut ONCE: ::std::sync::Once = ::std::sync::ONCE_INIT;

    unsafe {
        ONCE.call_once(|| {
            let mut memory_storage = ::std::collections::HashMap::new();

            let mut temp_dir_pathbuf = ::std::env::temp_dir();
            temp_dir_pathbuf.push(STORAGE_FILE_NAME);

            if let Ok(mut file) = ::std::fs::File::open(temp_dir_pathbuf) {
                let mut raw_disk_data = Vec::with_capacity(file.metadata().unwrap().len() as usize);
                if let Ok(_) = file.read_to_end(&mut raw_disk_data) {
                    if raw_disk_data.len() != 0 {
                        let vec: Vec<(NameType, Vec<u8>)>;
                        vec = deserialise(&raw_disk_data).unwrap();
                        memory_storage = convert_vec_to_hashmap(vec);
                    }
                }
            }

            STORAGE = ::std::mem::transmute(Box::new(
                    PersistentStorageSimulation {
                        data_store: ::std::sync::Arc::new(::std::sync::Mutex::new(memory_storage)),
                    }
                    ));
        });

        (*STORAGE).data_store.clone()
    }
}

fn sync_disk_storage(memory_storage: &::std::collections::HashMap<NameType, Vec<u8>>) {
    let mut temp_dir_pathbuf = ::std::env::temp_dir();
    temp_dir_pathbuf.push(STORAGE_FILE_NAME);

    let mut file = ::std::fs::File::create(temp_dir_pathbuf).unwrap();
    file.write_all(&serialise(&convert_hashmap_to_vec(memory_storage)).unwrap());
    file.sync_all();
}

pub struct RoutingVaultMock {
    sender          : ::std::sync::mpsc::Sender<(NameType, Data)>,
    network_delay_ms: u32,
}

impl RoutingVaultMock {
    pub fn new() -> (RoutingVaultMock, ::std::sync::mpsc::Receiver<(NameType, Data)>) {
        let (sender, receiver) = ::std::sync::mpsc::channel();

        let mock_routing = RoutingVaultMock {
            sender          : sender,
            network_delay_ms: 1000,
        };

        (mock_routing, receiver)
    }

    #[allow(dead_code)]
    pub fn set_network_delay_for_delay_simulation(&mut self, delay_ms: u32) {
        self.network_delay_ms = delay_ms;
    }

    pub fn get(&mut self, location: NameType, request_for: DataRequest) -> Result<(), ResponseError> {
        let delay_ms = self.network_delay_ms;
        let data_store = get_storage();
        let cloned_sender = self.sender.clone();

        ::std::thread::spawn(move || {
            ::std::thread::sleep_ms(delay_ms);
            match data_store.lock().unwrap().get(&location) {
                Some(raw_data) => {
                    if let Ok(data) = deserialise::<Data>(raw_data) {
                        if match (&data, request_for) {
                            (&Data::ImmutableData(ref immut_data), DataRequest::ImmutableData(ref tag)) => immut_data.get_type_tag() == tag,
                            (&Data::StructuredData(ref struct_data), DataRequest::StructuredData(ref tag)) => struct_data.get_type_tag() == *tag,
                            _ => false,
                        } {
                            let _ = cloned_sender.send((location, data)); // TODO Handle the error case by printing it maybe
                        }
                    }
                },
                None => (),
            };
        });

        Ok(())
    }

    pub fn put(&mut self, location: NameType, data: Data) -> Result<(), ResponseError> {
        let delay_ms = self.network_delay_ms;
        let data_store = get_storage();

        let mut data_store_mutex_guard = data_store.lock().unwrap();
        let success = if data_store_mutex_guard.contains_key(&location) {
            if let Data::ImmutableData(immut_data) = data {
                match deserialise(data_store_mutex_guard.get(&location).unwrap()) {
                    Ok(Data::ImmutableData(immut_data_stored)) => immut_data_stored.get_type_tag() == immut_data.get_type_tag(), // Immutable data is de-duplicated so always allowed
                    _ => false
                }
            } else {
                false
            }
        } else if let Ok(raw_data) = serialise(&data) {
            data_store_mutex_guard.insert(location, raw_data);
            sync_disk_storage(&*data_store_mutex_guard);
            true
        } else {
            false
        };

        // ::std::thread::spawn(move || {
        //     ::std::thread::sleep_ms(delay_ms);
        //     if !success { // TODO Check how routing is going to handle PUT errors
        //     }
        // });

        Ok(())
    }

    pub fn post(&mut self, location: NameType, data: Data) -> Result<(), ResponseError> {
        let delay_ms = self.network_delay_ms;
        let data_store = get_storage();

        let mut data_store_mutex_guard = data_store.lock().unwrap();
        let success = if data_store_mutex_guard.contains_key(&location) {
            match (&data, deserialise(data_store_mutex_guard.get(&location).unwrap())) {
                (&Data::StructuredData(ref struct_data_new), Ok(Data::StructuredData(ref struct_data_stored))) => {
                    if struct_data_new.get_version() != struct_data_stored.get_version() + 1 {
                        false
                    } else {
                        let mut count = 0usize;
                        if struct_data_stored.get_owners().iter().any(|key| { // This is more efficient than filter as it will stop whenever sign count reaches >= 50%
                            if struct_data_new.get_signatures().iter().any(|sig| ::sodiumoxide::crypto::sign::verify_detached(sig, &struct_data_new.data_to_sign(), key)) {
                                count += 1;
                            }

                            count >= struct_data_stored.get_owners().len() / 2 + struct_data_stored.get_owners().len() % 2
                        }) {
                            if let Ok(raw_data) = serialise(&data) {
                                data_store_mutex_guard.insert(location, raw_data);
                                sync_disk_storage(&*data_store_mutex_guard);
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    }
                },
                _ => false,
            }
        } else {
            false
        };

        // ::std::thread::spawn(move || {
        //     ::std::thread::sleep_ms(delay_ms);
        //     if !success { // TODO Check how routing is going to handle POST errors
        //     }
        // });

        Ok(())
    }

    pub fn delete(&mut self, location: NameType, data: Data) -> Result<(), ResponseError> {
        let delay_ms = self.network_delay_ms;
        let data_store = get_storage();

        let mut data_store_mutex_guard = data_store.lock().unwrap();
        let success = if data_store_mutex_guard.contains_key(&location) {
            match (&data, deserialise(data_store_mutex_guard.get(&location).unwrap())) {
                (&Data::StructuredData(ref struct_data_new), Ok(Data::StructuredData(ref struct_data_stored))) => {
                    if struct_data_new.get_version() != struct_data_stored.get_version() + 1 {
                        false
                    } else {
                        let mut count = 0usize;
                        if struct_data_stored.get_owners().iter().any(|key| { // This is more efficient than filter as it will stop whenever sign count reaches >= 50%
                            if struct_data_new.get_signatures().iter().any(|sig| ::sodiumoxide::crypto::sign::verify_detached(sig, &struct_data_new.data_to_sign(), key)) {
                                count += 1;
                            }

                            count >= struct_data_stored.get_owners().len() / 2 + struct_data_stored.get_owners().len() % 2
                        }) {
                            let _ = data_store_mutex_guard.remove(&location);
                            sync_disk_storage(&*data_store_mutex_guard);
                            true
                        } else {
                            false
                        }
                    }
                },
                _ => false,
            }
        } else {
            false
        };

        // ::std::thread::spawn(move || {
        //     ::std::thread::sleep_ms(delay_ms);
        //     if !success { // TODO Check how routing is going to handle DELETE errors
        //     }
        // });

        Ok(())
    }

    pub fn run(&mut self) {
        // let data_store = get_storage();
        // println!("Amount Of Chunks Stored: {:?}", data_store.lock().unwrap().len());
    }

    pub fn bootstrap(&mut self,
                     endpoints: Option<Vec<Endpoint>>,
                     _: Option<u16>) -> Result<(), RoutingError> {
        if let Some(vec_endpoints) = endpoints {
            for endpoint in vec_endpoints {
                println!("Endpoint: {:?}", endpoint);
            }
        }

        Ok(())
    }

    pub fn close(&self) {
        let _ = self.sender.send((NameType::new([0; 64]), Data::ShutDown));
    }
}

// #[cfg(test)]
// mod test {
//     use ::std::error::Error;

//     use super::*;

//     #[test]
//     fn map_serialisation() {
//         let mut map_before = ::std::collections::HashMap::<::routing::NameType, Vec<u8>>::new();
//         map_before.insert(::routing::NameType::new([1; 64]), vec![1; 10]);

//         let vec_before = convert_hashmap_to_vec(&map_before);
//         let serialised_data = eval_result!(mock_routing_types::serialise(&vec_before));

//         let vec_after: Vec<(::routing::NameType, Vec<u8>)> = eval_result!(mock_routing_types::deserialise(&serialised_data));
//         let map_after = convert_vec_to_hashmap(vec_after);
//         assert_eq!(map_before, map_after);
//     }

//     #[test]
//     fn check_put_post_get_delete_for_immutable_data() {
//         let notifier = ::std::sync::Arc::new((::std::sync::Mutex::new(None), ::std::sync::Condvar::new()));
//         let account_packet = ::client::user_account::Account::new(None, None);

//         let id_packet = ::routing::types::Id::with_keys(account_packet.get_maid().public_keys().clone(),
//                                                         account_packet.get_maid().secret_keys().clone());

//         let (routing, receiver) = RoutingVaultMock::new(id_packet);
//         let (message_queue, reciever_joiner) = ::client::message_queue::MessageQueue::new(notifier.clone(), receiver);

//         let mock_routing = ::std::sync::Arc::new(::std::sync::Mutex::new(routing));
//         let mock_routing_clone = mock_routing.clone();

//         let mock_routing_stop_flag = ::std::sync::Arc::new(::std::sync::Mutex::new(false));
//         let mock_routing_stop_flag_clone = mock_routing_stop_flag.clone();

//         struct RAIIThreadExit {
//             routing_stop_flag: ::std::sync::Arc<::std::sync::Mutex<bool>>,
//             join_handle: Option<::std::thread::JoinHandle<()>>,
//         }

//         impl Drop for RAIIThreadExit {
//             fn drop(&mut self) {
//                 *self.routing_stop_flag.lock().unwrap() = true;
//                 self.join_handle.take().unwrap().join().unwrap();
//             }
//         }

//         let _managed_thread = RAIIThreadExit {
//             routing_stop_flag: mock_routing_stop_flag,
//             join_handle: Some(::std::thread::spawn(move || {
//                 while !*mock_routing_stop_flag_clone.lock().unwrap() {
//                     ::std::thread::sleep_ms(10);
//                     mock_routing_clone.lock().unwrap().run();
//                 }
//                 mock_routing_clone.lock().unwrap().close();
//                 reciever_joiner.join().unwrap();
//             })),
//         };

//         // Construct ImmutableData
//         let orig_raw_data: Vec<u8> = eval_result!(mock_routing_types::generate_random_vector(100));
//         let orig_immutable_data = ::client::ImmutableData::new(::client::ImmutableDataType::Normal, orig_raw_data.clone());
//         let orig_data = ::client::Data::ImmutableData(orig_immutable_data.clone());

//         // First PUT should succeed
//         {
//             match mock_routing.lock().unwrap().put(orig_immutable_data.name(), orig_data.clone()) {
//                 Ok(()) => (),
//                 Err(_) => panic!("Failure in PUT !!"),
//             }
//         }

//         // GET ImmutableData should pass
//         {
//             let mut mock_routing_guard = mock_routing.lock().unwrap();
//             match mock_routing_guard.get(orig_immutable_data.name(), ::client::DataRequest::ImmutableData(::client::ImmutableDataType::Normal)) {
//                 Ok(()) => {
//                     let mut response_getter = ::client::response_getter::ResponseGetter::new(Some(notifier.clone()),
//                                                                                              message_queue.clone(),
//                                                                                              orig_immutable_data.name(),
//                                                                                              ::client::DataRequest::ImmutableData(::client::ImmutableDataType::Normal));
//                     match response_getter.get() {
//                         Ok(data) => {
//                             match data {
//                                 ::client::Data::ImmutableData(received_immutable_data) => assert_eq!(orig_immutable_data, received_immutable_data),
//                                 _ => panic!("Unexpected!"),
//                             }
//                         },
//                         Err(_) => panic!("Should have found data put before by a PUT"),
//                     }
//                 },
//                 Err(_) => panic!("Failure in GET !!"),
//             }
//         }

//         // Subsequent PUTs for same ImmutableData should succeed - De-duplication
//         {
//             let put_result = mock_routing.lock().unwrap().put(orig_immutable_data.name(), orig_data.clone());
//             match put_result {
//                 Ok(()) => (),
//                 Err(_) => panic!("Failure in PUT !!"),
//             }
//         }

//         // Construct Backup ImmutableData
//         let new_immutable_data = ::client::ImmutableData::new(::client::ImmutableDataType::Backup, orig_raw_data);
//         let new_data = ::client::Data::ImmutableData(new_immutable_data.clone());

//         // Subsequent PUTs for same ImmutableData of different type should fail
//         {
//             let put_result = mock_routing.lock().unwrap().put(orig_immutable_data.name(), new_data);
//             match put_result {
//                 Ok(()) => (),
//                 Err(_) => panic!("Failure in PUT !!"),
//             }
//         }

//         // POSTs for ImmutableData should fail
//         {
//             let post_result = mock_routing.lock().unwrap().post(orig_immutable_data.name(), orig_data.clone());
//             match post_result {
//                 Ok(()) => (),
//                 Err(_) => panic!("Failure in POST !!"),
//             }
//         }

//         // DELETEs of ImmutableData should fail
//         {
//             let delete_result = mock_routing.lock().unwrap().delete(orig_immutable_data.name(), orig_data);
//             match delete_result {
//                 Ok(()) => (),
//                 Err(_) => panic!("Failure in DELETE !!"),
//             }
//         }

//         // GET ImmutableData should pass
//         {
//             let mut mock_routing_mutex_guard = mock_routing.lock().unwrap();
//             match mock_routing_mutex_guard.get(orig_immutable_data.name(), ::client::DataRequest::ImmutableData(::client::ImmutableDataType::Normal)) {
//                 Ok(()) => {
//                     let mut response_getter = ::client::response_getter::ResponseGetter::new(Some(notifier.clone()),
//                                                                                              message_queue.clone(),
//                                                                                              orig_immutable_data.name(),
//                                                                                              ::client::DataRequest::ImmutableData(::client::ImmutableDataType::Normal));
//                     match response_getter.get() {
//                         Ok(data) => {
//                             match data {
//                                 ::client::Data::ImmutableData(received_immutable_data) => assert_eq!(orig_immutable_data, received_immutable_data), // TODO Improve by directly assert_eq!(data)
//                                 _ => panic!("Unexpected!"),
//                             }
//                         },
//                         Err(_) => panic!("Should have found data put before by a PUT"),
//                     }
//                 },
//                 Err(_) => panic!("Failure in GET !!"),
//             }
//         }
//     }

//     #[test]
//     fn check_put_post_get_delete_for_structured_data() {
//         let notifier = ::std::sync::Arc::new((::std::sync::Mutex::new(None), ::std::sync::Condvar::new()));
//         let account_packet = ::client::user_account::Account::new(None, None);

//         let id_packet = ::routing::types::Id::with_keys(account_packet.get_maid().public_keys().clone(),
//                                                       account_packet.get_maid().secret_keys().clone());

//         let (routing, receiver) = RoutingVaultMock::new(id_packet);
//         let (message_queue, receiver_joiner) = ::client::message_queue::MessageQueue::new(notifier.clone(), receiver);
//         let mock_routing = ::std::sync::Arc::new(::std::sync::Mutex::new(routing));
//         let mock_routing_clone = mock_routing.clone();

//         let mock_routing_stop_flag = ::std::sync::Arc::new(::std::sync::Mutex::new(false));
//         let mock_routing_stop_flag_clone = mock_routing_stop_flag.clone();

//         struct RAIIThreadExit {
//             routing_stop_flag: ::std::sync::Arc<::std::sync::Mutex<bool>>,
//             join_handle: Option<::std::thread::JoinHandle<()>>,
//         }

//         impl Drop for RAIIThreadExit {
//             fn drop(&mut self) {
//                 *self.routing_stop_flag.lock().unwrap() = true;
//                 self.join_handle.take().unwrap().join().unwrap();
//             }
//         }

//         let _managed_thread = RAIIThreadExit {
//             routing_stop_flag: mock_routing_stop_flag,
//             join_handle: Some(::std::thread::spawn(move || {
//                 while !*mock_routing_stop_flag_clone.lock().unwrap() {
//                     ::std::thread::sleep_ms(10);
//                     mock_routing_clone.lock().unwrap().run();
//                 }
//                 mock_routing_clone.lock().unwrap().close();
//                 receiver_joiner.join().unwrap();
//             })),
//         };

//         // Construct ImmutableData
//         let orig_data: Vec<u8> = eval_result!(mock_routing_types::generate_random_vector(100));
//         let orig_immutable_data = ::client::ImmutableData::new(::client::ImmutableDataType::Normal, orig_data);
//         let orig_data_immutable = ::client::Data::ImmutableData(orig_immutable_data.clone());

//         // Construct StructuredData, 1st version, for this ImmutableData
//         const TYPE_TAG: u64 = 999;
//         let keyword = eval_result!(mock_routing_types::generate_random_string(10));
//         let pin = mock_routing_types::generate_random_pin();
//         let user_id = ::client::user_account::Account::generate_network_id(&keyword, pin);
//         let mut account_version = ::client::StructuredData::new(TYPE_TAG,
//                                                                 user_id.clone(),
//                                                                 0,
//                                                                 eval_result!(mock_routing_types::serialise(&vec![orig_immutable_data.name()])),
//                                                                 vec![account_packet.get_public_maid().public_keys().0.clone()],
//                                                                 Vec::new(),
//                                                                 &account_packet.get_maid().secret_keys().0);
//         let mut data_account_version = ::client::Data::StructuredData(account_version.clone());

//         // First PUT of StructuredData should succeed
//         {
//             match mock_routing.lock().unwrap().put(account_version.name(), data_account_version.clone()) {
//                 Ok(()) => (),
//                 Err(_) => panic!("Failure in PUT !!"),
//             }
//         }

//         // PUT for ImmutableData should succeed
//         {
//             match mock_routing.lock().unwrap().put(orig_immutable_data.name(), orig_data_immutable.clone()) {
//                 Ok(()) => (),
//                 Err(_) => panic!("Failure in PUT !!"),
//             }
//         }

//         let mut received_structured_data: ::client::StructuredData;

//         // GET StructuredData should pass
//         {
//             match mock_routing.lock().unwrap().get(account_version.name(), ::client::DataRequest::StructuredData(TYPE_TAG)) {
//                 Ok(()) => {
//                     let mut response_getter = ::client::response_getter::ResponseGetter::new(Some(notifier.clone()),
//                                                                                              message_queue.clone(),
//                                                                                              account_version.name(),
//                                                                                              ::client::DataRequest::StructuredData(TYPE_TAG));
//                     match response_getter.get() {
//                         Ok(data) => {
//                             match data {
//                                 ::client::Data::StructuredData(struct_data) => {
//                                     received_structured_data = struct_data;
//                                     assert!(account_version == received_structured_data);
//                                 },
//                                 _ => panic!("Unexpected!"),
//                             }
//                         },
//                         Err(_) => panic!("Should have found data put before by a PUT"),
//                     }
//                 },
//                 Err(_) => panic!("Failure in GET !!"),
//             }
//         }

//         // GET ImmutableData from lastest version of StructuredData should pass
//         {
//             let mut location_vec = eval_result!(mock_routing_types::deserialise::<Vec<::routing::NameType>>(received_structured_data.get_data()));
//             match mock_routing.lock().unwrap().get(eval_option!(location_vec.pop(), "Value must exist !"), ::client::DataRequest::ImmutableData(::client::ImmutableDataType::Normal)) {
//                 Ok(()) => {
//                     let mut response_getter = ::client::response_getter::ResponseGetter::new(Some(notifier.clone()),
//                                                                                              message_queue.clone(),
//                                                                                              orig_immutable_data.name(),
//                                                                                              ::client::DataRequest::ImmutableData(::client::ImmutableDataType::Normal));
//                     match response_getter.get() {
//                         Ok(data) => {
//                             match data {
//                                 ::client::Data::ImmutableData(received_immutable_data) => assert_eq!(orig_immutable_data, received_immutable_data),
//                                 _ => panic!("Unexpected!"),
//                             }
//                         },
//                         Err(_) => panic!("Should have found data put before by a PUT"),
//                     }
//                 },
//                 Err(_) => panic!("Failure in GET !!"),
//             }
//         }

//         // Construct ImmutableData
//         let new_data: Vec<u8> = eval_result!(mock_routing_types::generate_random_vector(100));
//         let new_immutable_data = ::client::ImmutableData::new(::client::ImmutableDataType::Normal, new_data);
//         let new_data_immutable = ::client::Data::ImmutableData(new_immutable_data.clone());

//         // PUT for new ImmutableData should succeed
//         {
//             match mock_routing.lock().unwrap().put(new_immutable_data.name(), new_data_immutable) {
//                 Ok(()) => (),
//                 Err(_) => panic!("Failure in PUT !!"),
//             }
//         }

//         // Construct StructuredData, 2nd version, for this ImmutableData - IVALID Versioning
//         let invalid_version_account_version = ::client::StructuredData::new(TYPE_TAG,
//                                                                             user_id.clone(),
//                                                                             0,
//                                                                             mock_routing_types::serialise(&vec![orig_immutable_data.name(), new_immutable_data.name()]).ok().unwrap(),
//                                                                             vec![account_packet.get_public_maid().public_keys().0.clone()],
//                                                                             Vec::new(),
//                                                                             &account_packet.get_maid().secret_keys().0);
//         let invalid_version_data_account_version = ::client::Data::StructuredData(invalid_version_account_version.clone());

//         // Construct StructuredData, 2nd version, for this ImmutableData - IVALID Signature
//         let invalid_signature_account_version = ::client::StructuredData::new(TYPE_TAG,
//                                                                               user_id.clone(),
//                                                                               1,
//                                                                               mock_routing_types::serialise(&vec![orig_immutable_data.name(), new_immutable_data.name()]).ok().unwrap(),
//                                                                               vec![account_packet.get_public_maid().public_keys().0.clone()],
//                                                                               Vec::new(),
//                                                                               &account_packet.get_mpid().secret_keys().0);
//         let invalid_signature_data_account_version = ::client::Data::StructuredData(invalid_signature_account_version.clone());

//         // Construct StructuredData, 2nd version, for this ImmutableData - Valid
//         account_version = ::client::StructuredData::new(TYPE_TAG,
//                                                         user_id.clone(),
//                                                         1,
//                                                         mock_routing_types::serialise(&vec![orig_immutable_data.name(), new_immutable_data.name()]).ok().unwrap(),
//                                                         vec![account_packet.get_public_maid().public_keys().0.clone()],
//                                                         Vec::new(),
//                                                         &account_packet.get_maid().secret_keys().0);
//         data_account_version = ::client::Data::StructuredData(account_version.clone());

//         // Subsequent PUTs for same StructuredData should fail
//         {
//             let put_result = mock_routing.lock().unwrap().put(account_version.name(), data_account_version.clone());
//             match put_result {
//                 Ok(()) => (),
//                 Err(_) => panic!("Failure in PUT !!"),
//             }
//         }

//         // Subsequent POSTSs for same StructuredData should fail if versioning is invalid
//         {
//             let post_result = mock_routing.lock().unwrap().post(invalid_version_account_version.name(), invalid_version_data_account_version.clone());
//             match post_result {
//                 Ok(()) => (),
//                 Err(_) => panic!("Failure in POST !!"),
//             }
//         }

//         // Subsequent POSTSs for same StructuredData should fail if signature is invalid
//         {
//             let post_result = mock_routing.lock().unwrap().post(invalid_signature_account_version.name(), invalid_signature_data_account_version.clone());
//             match post_result {
//                 Ok(()) => (),
//                 Err(_) => panic!("Failure in POST !!"),
//             }
//         }

//         // Subsequent POSTSs for existing StructuredData version should pass for valid update
//         {
//             let post_result = mock_routing.lock().unwrap().post(account_version.name(), data_account_version.clone());
//             match post_result {
//                 Ok(()) => (),
//                 Err(_) => panic!("Failure in POST !!"),
//             }
//         }

//         // GET for new StructuredData version should pass
//         {
//             match mock_routing.lock().unwrap().get(account_version.name(), ::client::DataRequest::StructuredData(TYPE_TAG)) {
//                 Ok(()) => {
//                     let mut response_getter = ::client::response_getter::ResponseGetter::new(Some(notifier.clone()),
//                                                                                              message_queue.clone(),
//                                                                                              account_version.name(),
//                                                                                              ::client::DataRequest::StructuredData(TYPE_TAG));
//                     match response_getter.get() {
//                         Ok(data) => {
//                             match data {
//                                 ::client::Data::StructuredData(structured_data) => {
//                                     received_structured_data = structured_data;
//                                     assert!(received_structured_data == account_version);
//                                 },
//                                 _ => panic!("Unexpected!"),
//                             }
//                         },
//                         Err(_) => panic!("Should have found data put before by a PUT"),
//                     }
//                 },
//                 Err(_) => panic!("Failure in GET !!"),
//             }
//         }

//         let location_vec = eval_result!(mock_routing_types::deserialise::<Vec<::routing::NameType>>(received_structured_data.get_data()));
//         assert_eq!(location_vec.len(), 2);

//         // GET new ImmutableData should pass
//         {
//             let get_result = mock_routing.lock().unwrap().get(location_vec[1].clone(), ::client::DataRequest::ImmutableData(::client::ImmutableDataType::Normal));
//             match get_result {
//                 Ok(()) => {
//                     let mut response_getter = ::client::response_getter::ResponseGetter::new(Some(notifier.clone()),
//                                                                                              message_queue.clone(),
//                                                                                              location_vec[1].clone(),
//                                                                                              ::client::DataRequest::ImmutableData(::client::ImmutableDataType::Normal));
//                     match response_getter.get() {
//                         Ok(data) => {
//                             match data {
//                                 ::client::Data::ImmutableData(received_immutable_data) => assert_eq!(new_immutable_data, received_immutable_data),
//                                 _ => panic!("Unexpected!"),
//                             }
//                         },
//                         Err(_) => panic!("Should have found data put before by a PUT"),
//                     }
//                 },
//                 Err(_) => panic!("Failure in GET !!"),
//             }
//         }

//         // GET original ImmutableData should pass
//         {
//             let get_result = mock_routing.lock().unwrap().get(location_vec[0].clone(), ::client::DataRequest::ImmutableData(::client::ImmutableDataType::Normal));
//             match get_result {
//                 Ok(id) => {
//                     let mut response_getter = ::client::response_getter::ResponseGetter::new(Some(notifier.clone()),
//                                                                                              message_queue.clone(),
//                                                                                              location_vec[0].clone(),
//                                                                                              ::client::DataRequest::ImmutableData(::client::ImmutableDataType::Normal));
//                     match response_getter.get() {
//                         Ok(data) => {
//                             match data {
//                                 ::client::Data::ImmutableData(received_immutable_data) => assert_eq!(orig_immutable_data, received_immutable_data),
//                                 _ => panic!("Unexpected!"),
//                             }
//                         },
//                         Err(_) => panic!("Should have found data put before by a PUT"),
//                     }
//                 },
//                 Err(_) => panic!("Failure in GET !!"),
//             }
//         }

//         // TODO this will not function properly presently .. DELETE needs a version Bump too
//         // DELETE of Structured Data should succeed
//         {
//             let delete_result = mock_routing.lock().unwrap().delete(account_version.name(), data_account_version.clone());
//             match delete_result {
//                 Ok(()) => (),
//                 Err(_) => panic!("Failure in DELETE !!"),
//             }
//         }
//     }
// }
