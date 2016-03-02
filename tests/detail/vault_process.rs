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
use std::fmt::{self, Debug, Formatter};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

pub struct VaultProcess {
    index: u32,
    child: Child,
}

fn get_path(file_name: &str) -> PathBuf {
    let mut path = unwrap_result!(env::current_exe());
    path.set_file_name(file_name);
    path
}

impl VaultProcess {
    pub fn new(index: u32) -> VaultProcess {
        let executable_path = get_path("safe_vault");
        let logfile_path = get_path(&format!("vault_{}.log", index));
        let args = vec![format!("--output={}", logfile_path.display())];
        trace!("Starting vault {}", index);
        match Command::new(executable_path.to_path_buf())
                  .args(&args)
                  .stdout(Stdio::null())
                  .stderr(Stdio::null())
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
