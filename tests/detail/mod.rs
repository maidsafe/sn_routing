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

mod client;
mod setup_network;
mod test_cases;

pub use self::client::Client;
pub use self::setup_network::setup_network;
pub use self::test_cases::immutable_data::test as immutable_data_test;
pub use self::test_cases::structured_data::test as structured_data_test;
pub use self::test_cases::immutable_data_churn::test as immutable_data_churn_test;
pub use self::test_cases::structured_data_churn::test as structured_data_churn_test;
pub use self::test_cases::messaging::test as messaging_test;

use rand::random;
use routing::{Data, StructuredData};
use xor_name::XorName;

pub fn generate_random_vec_u8(size: usize) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::with_capacity(size);
    for _ in 0..size {
        vec.push(random::<u8>());
    }
    vec
}

pub fn create_account(client: &mut Client) {
    let sd = unwrap_result!(StructuredData::new(0, random::<XorName>(), 0, vec![], vec![], vec![], None));
    let _ = client.put(Data::StructuredData(sd));
}
