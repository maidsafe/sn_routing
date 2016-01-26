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

use std::{env, thread};
use std::error::Error;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

pub fn setup_network(vault_count: u32) -> Vec<Child> {
    let mut processes = Vec::new();
    let executable_path = match env::current_exe() {
        Ok(mut exe_path) => {
            exe_path.pop();
            Path::new("./target")
                .join(exe_path.iter().last().unwrap())
                .join("safe_vault")
        }
        Err(e) => panic!("Failed to get current integration test path: {}", e),
    };
    println!("Expecting vault executable at the path of {}",
             executable_path.to_path_buf().display());

    for i in 0..vault_count {
        println!("Starting vault {}", i);
        processes.push(match Command::new(executable_path.to_path_buf())
                                 .stderr(Stdio::piped())
                                 .spawn() {
            Err(why) => panic!("Couldn't spawn vault: {}", why.description()),
            Ok(process) => process,
        });
        thread::sleep(Duration::from_secs(3 + i as u64));
    }
    println!("Waiting 10 seconds to let the network stabilise");
    thread::sleep(Duration::from_secs(10));
    processes
}
