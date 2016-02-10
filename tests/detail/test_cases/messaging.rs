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
use rand;
use sodiumoxide::crypto::sign;
use routing::Authority;
use xor_name::XorName;

pub fn test(client: &mut Client) {
    println!("Running Messaging test");

    client.register_online();

    let metadata: Vec<u8> = generate_random_vec_u8(128);
    let body: Vec<u8> = generate_random_vec_u8(128);
    let receiver = Authority::Client { client_key: sign::gen_keypair().0, proxy_node_name: rand::random::<XorName>() };
    let receiver_name = receiver.get_name().clone();

    client.put_message(&metadata, &body, &receiver_name);
}