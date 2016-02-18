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

use super::{TestGroup, VaultProcess};
use std::thread;
use std::time::Duration;

pub fn setup_network(vault_count: u32) -> Vec<VaultProcess> {
    let mut test_group = TestGroup::new(&format!("Setting up network of {} Vaults", vault_count));

    let mut processes = vec![];
    for i in 0..vault_count {
        processes.push(VaultProcess::new(i));
        thread::sleep(Duration::from_secs(1 + i as u64));
    }
    info!("Waiting 10 seconds to let the network stabilise");
    thread::sleep(Duration::from_secs(10));

    test_group.release();
    processes
}
