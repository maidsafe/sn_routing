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

use xor_name::XorName;

/// Format a vector of bytes as a hexadecimal number, ellipsizing all but the first and last three.
///
/// For three bytes with values 1, 2, 3, the output will be "010203". For more than six bytes, e.g. for fifteen bytes
/// with values 1, 2, ..., 15, the output will be "010203..0D0E0F".
pub fn format_binary_array<V: AsRef<[u8]>>(input: V) -> String {
    use std::fmt::Write;
    let input_ref = input.as_ref();
    if input_ref.len() <= 6 {
        let mut ret = String::new();
        for byte in input_ref.iter() {
            unwrap_result!(write!(ret, "{:02x}", byte));
        }
        return ret;
    }
    format!("{:02x}{:02x}{:02x}..{:02x}{:02x}{:02x}",
            input_ref[0],
            input_ref[1],
            input_ref[2],
            input_ref[input_ref.len() - 3],
            input_ref[input_ref.len() - 2],
            input_ref[input_ref.len() - 1])
}


/// Compute the relocated name of a client with the given original name.
///
/// This is used by each member of the client's `ClientManager` group to choose a new name for the
/// client. On the one hand, sufficiently many of them need to agree on the new name to reach quorum
/// size, on the other hand, the client shall not be able to predict it so that it cannot choose
/// who will be its new `NodeManager` after relocation.
///
/// To meet these requirements, the relocated name is computed from the two closest nodes and the
/// client's original name: It is the SHA512 hash of:
///
/// [original_name, 1st closest node id, 2nd closest node id]
///
/// In case of only one close node provided (in initial network setup scenario):
///
/// [original_name, 1st closest node id]
pub fn calculate_relocated_name(mut close_nodes: Vec<XorName>,
                                original_name: &XorName)
                                -> Result<XorName, ::error::RoutingError> {
    if close_nodes.is_empty() {
        return Err(::error::RoutingError::RoutingTableEmpty);
    }
    close_nodes.sort_by(|a, b| {
        if ::xor_name::closer_to_target(&a, &b, original_name) {
            ::std::cmp::Ordering::Less
        } else {
            ::std::cmp::Ordering::Greater
        }
    });
    close_nodes.truncate(2usize);
    close_nodes.insert(0, original_name.clone());

    let mut combined: Vec<u8> = Vec::new();
    for node_id in close_nodes {
        for i in node_id.get_id().iter() {
            combined.push(*i);
        }
    }
    Ok(XorName(::sodiumoxide::crypto::hash::sha512::hash(&combined).0))
}

#[cfg(test)]
mod test {
    extern crate rand;

    use xor_name::XorName;


    #[test]
    fn calculate_relocated_name() {
        let original_name: XorName = rand::random();

        // empty close nodes
        assert!(super::calculate_relocated_name(Vec::new(), &original_name).is_err());

        // one entry
        let mut close_nodes_one_entry: Vec<XorName> = Vec::new();
        close_nodes_one_entry.push(rand::random());
        let actual_relocated_name_one_entry =
            unwrap_result!(super::calculate_relocated_name(close_nodes_one_entry.clone(),
                                                           &original_name));
        assert!(original_name != actual_relocated_name_one_entry);

        let mut combined_one_node_vec: Vec<XorName> = Vec::new();
        combined_one_node_vec.push(original_name.clone());
        combined_one_node_vec.push(close_nodes_one_entry[0].clone());

        let mut combined_one_node: Vec<u8> = Vec::new();
        for node_id in combined_one_node_vec {
            for i in node_id.get_id().iter() {
                combined_one_node.push(*i);
            }
        }

        let expected_relocated_name_one_node =
            XorName(::sodiumoxide::crypto::hash::sha512::hash(&combined_one_node).0);

        assert_eq!(actual_relocated_name_one_entry,
                   expected_relocated_name_one_node);

        // populated closed nodes
        let mut close_nodes: Vec<XorName> = Vec::new();
        for _ in 0..::kademlia_routing_table::GROUP_SIZE {
            close_nodes.push(rand::random());
        }
        let actual_relocated_name =
            unwrap_result!(super::calculate_relocated_name(close_nodes.clone(), &original_name));
        assert!(original_name != actual_relocated_name);
        close_nodes.sort_by(|a, b| {
            if ::xor_name::closer_to_target(&a, &b, &original_name) {
                ::std::cmp::Ordering::Less
            } else {
                ::std::cmp::Ordering::Greater
            }
        });
        let first_closest = close_nodes[0].clone();
        let second_closest = close_nodes[1].clone();
        let mut combined: Vec<u8> = Vec::new();

        for i in original_name.get_id().into_iter() {
            combined.push(*i);
        }
        for i in first_closest.get_id().into_iter() {
            combined.push(*i);
        }
        for i in second_closest.get_id().into_iter() {
            combined.push(*i);
        }

        let expected_relocated_name = XorName(::sodiumoxide::crypto::hash::sha512::hash(&combined)
                                                  .0);
        assert_eq!(expected_relocated_name, actual_relocated_name);

        let mut invalid_combined: Vec<u8> = Vec::new();
        for i in first_closest.get_id().into_iter() {
            invalid_combined.push(*i);
        }
        for i in second_closest.get_id().into_iter() {
            invalid_combined.push(*i);
        }
        for i in original_name.get_id().into_iter() {
            invalid_combined.push(*i);
        }
        let invalid_relocated_name =
            XorName(::sodiumoxide::crypto::hash::sha512::hash(&invalid_combined).0);
        assert!(invalid_relocated_name != actual_relocated_name);
    }
}
