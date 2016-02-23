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

use std::env;
use std::fs::File;
use std::fmt::{self, Debug, Formatter};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

pub struct VaultProcess {
    index: u32,
    child: Child,
}

fn get_path(filename: &str) -> PathBuf {
    match env::current_exe() {
        Ok(mut exe_path) => {
            exe_path.pop();
            Path::new("./target")
                .join(unwrap_option!(exe_path.iter().last(), ""))
                .join(filename)
        }
        Err(e) => panic!("Failed to get current integration test path: {}", e),
    }
}

impl VaultProcess {
    pub fn new(index: u32) -> VaultProcess {
        let executable_path = get_path("safe_vault");
        trace!("Starting vault {}", index);
        match Command::new(executable_path.to_path_buf())
                  .stdout(Stdio::piped())
                  .stderr(Stdio::piped())
                  .spawn() {
            Err(error) => {
                panic!("Couldn't spawn vault {}: {:?}.  Expecting executable at the path of {}",
                       index,
                       error,
                       executable_path.to_path_buf().display())
            }
            Ok(process) => {
                let vault_process = VaultProcess {
                    index: index,
                    child: process,
                };
                info!("Started {:?}", vault_process);
                vault_process
            }
        }
    }
}

impl Drop for VaultProcess {
    fn drop(&mut self) {
        match self.child.kill() {
            Ok(()) => info!("Killed {:?}", self),
            Err(error) => error!("Error killing {:?} - {:?}", self, error),
        }

        let mut log_file_name = String::from("vault_");
        log_file_name.push_str(&self.index.to_string());
        log_file_name.push_str(".log");
        let log_file_path = get_path(&log_file_name);
        let mut stdout_log_result = Vec::<u8>::new();
        match self.child.stdout {
            Some(ref mut stdout) => {
                let _ = stdout.read_to_end(&mut stdout_log_result);
            }
            None => return,
        }
        let mut stderr_log_result = Vec::<u8>::new();
        match self.child.stderr {
            Some(ref mut stderr) => {
                let _ = stderr.read_to_end(&mut stderr_log_result);
            }
            None => return,
        }
        let _ = File::create(&log_file_path).and_then(|mut file| {
            let _ = file.write_all(&stdout_log_result[..]).and_then(|()| file.sync_all());
            file.write_all(&stderr_log_result[..]).and_then(|()| file.sync_all())
        });
    }
}

impl Debug for VaultProcess {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter,
               "Vault {} with process ID {}",
               self.index,
               self.child.id())
    }
}
