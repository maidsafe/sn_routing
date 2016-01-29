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

use super::*;
use routing::{Data, ImmutableData, ImmutableDataType};

pub fn test(client: &mut Client) {
    println!("Running ImmutableData churn test");

    let value = generate_random_vec_u8(1024);
    let im_data = ImmutableData::new(ImmutableDataType::Normal, value);
    client.put(Data::ImmutableData(im_data.clone()));
    // let duration = Duration::from_millis(5000);
    // thread::sleep(duration);

    // let mut new_vault_process = start_vaults(1);

    // client_routing.get_request(Authority::NaeManager(im_data.name()),
    //                            DataRequest::ImmutableData(im_data.name(), ImmutableDataType::Normal));
    // while let Ok(data) = client_receiver.recv() {
    //     assert_eq!(data, Data::ImmutableData(im_data.clone()));
    //     break;
    // }

    // if let Some(mut process) = new_vault_process.pop() {
    //     let _ = process.kill();
    //     let result: Vec<u8> = process.stderr.unwrap().bytes().map(|x| x.unwrap()).collect();
    //     let s = String::from_utf8(result).unwrap();
    //     let mm_v: Vec<&str> = s.split("MaidManager updated account").collect();
    //     assert_eq!(2, mm_v.len());
    //     let dm_v: Vec<&str> = s.split("ImmutableDataManager updated account").collect();
    //     assert_eq!(2, dm_v.len());
    //     let pm_v: Vec<&str> = s.split("ImmutableDataManager updated account").collect();
    //     assert_eq!(2, pm_v.len());
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
