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

use super::Client;

pub fn test(_client: &mut Client) {
    println!("Running StructuredData churn test");
    // let mut processes = start_vaults(4);
    // let (mut client_routing, client_receiver, client_name) = start_client();

    // let name = XorName(slice_as_u8_64_array(&*generate_random_vec_u8(64)));
    // let value = generate_random_vec_u8(1024);
    // let sign_keys = ::sodiumoxide::crypto::sign::gen_keypair();
    // let sd = ::routing::structured_data::StructuredData::new(0,
    //                                                          name,
    //                                                          0,
    //                                                          value.clone(),
    //                                                          vec![sign_keys.0],
    //                                                          vec![],
    //                                                          Some(&sign_keys.1))
    //              .ok()
    //              .unwrap();
    // client_routing.put_request(::routing::Authority::ClientManager(client_name),
    //                            ::routing::data::Data::StructuredData(sd.clone()));
    // let duration = ::std::time::Duration::from_millis(5000);
    // ::std::thread::sleep(duration);

    // let mut new_vault_process = start_vaults(1);

    // client_routing.get_request(::routing::Authority::NaeManager(sd.name()),
    //                            ::routing::data::DataRequest::StructuredData(sd.name(), 0));
    // while let Ok(data) = client_receiver.recv() {
    //     assert_eq!(data, ::routing::data::Data::StructuredData(sd.clone()));
    //     break;
    // }

    // if let Some(mut process) = new_vault_process.pop() {
    //     let _ = process.kill();
    //     let result: Vec<u8> = process.stderr.unwrap().bytes().map(|x| x.unwrap()).collect();
    //     let s = String::from_utf8(result).unwrap();
    //     let sd_v: Vec<&str> = s.split("SdManager transferred structured_data").collect();
    //     assert_eq!(2, sd_v.len());
    //     println!("\n\n     +++++++++++++++++++++++++++++++++++++++\n {} \n\n",
    //              s);
    // };
    // while let Some(mut process) = processes.pop() {
    //     let _ = process.kill();
    //     let result: Vec<u8> = process.stderr.unwrap().bytes().map(|x| x.unwrap()).collect();
    //     let s = String::from_utf8(result).unwrap();
    //     println!("\n\n     +++++++++++++++++++++++++++++++++++++++\n {} \n\n",
    //              s);
    // }
}
