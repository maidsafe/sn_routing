// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use routing_table::Xorable;
use rust_sodium::crypto::hash::sha256;
use std::fmt::{self, Display, Write};
use std::iter;
use std::time::Duration;
use xor_name::XorName;


/// Display a "number" to the given number of decimal places
pub trait DisplayNumber {
    /// Construct a formattable object, with the given precision (number of decimal places).
    fn display_prec(&self, prec: usize) -> DisplayNumberObj;
}

impl DisplayNumber for Duration {
    fn display_prec(&self, prec: usize) -> DisplayNumberObj {
        DisplayNumberObj {
            number: DisplayNumberType::Duration(*self),
            prec: prec,
        }
    }
}

// Enumeration of internal types representable by `DisplayNumberObj`
enum DisplayNumberType {
    Duration(Duration),
}

/// Display a number to the given number of decimal places
pub struct DisplayNumberObj {
    number: DisplayNumberType,
    prec: usize,
}

impl Display for DisplayNumberObj {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.number {
            DisplayNumberType::Duration(dur) => {
                let secs = dur.as_secs() as f64 + dur.subsec_nanos() as f64 * 1e-9;
                // This _does_ round up if the next digit is >= 5
                write!(f, "{:.*}", self.prec, secs)
            }
        }
    }
}

/// Format a vector of bytes as a hexadecimal number, ellipsising all but the first and last three.
///
/// For three bytes with values 1, 2, 3, the output will be "010203".  For more than six bytes, e.g.
/// for fifteen bytes with values 1, 2, ..., 15, the output will be "010203..0d0e0f".
pub fn format_binary_array<V: AsRef<[u8]>>(input: V) -> String {
    let input_ref = input.as_ref();
    if input_ref.len() <= 6 {
        let mut ret = String::new();
        for byte in input_ref.iter() {
            unwrap!(write!(ret, "{:02x}", byte));
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
/// This is used by each member of a joining node's section to choose a new name for the node. On
/// the one hand, sufficiently many of them need to agree on the new name to reach quorum size, on
/// the other hand, the joining node shall not be able to predict it so that it cannot choose where
/// to be relocated to.
///
/// To meet these requirements, the relocated name is computed from the two closest nodes and the
/// joining node's original name: It is the SHA256 hash of:
///
/// [`original_name`, 1st closest node id, 2nd closest node id]
///
/// In case of only one close node provided (in initial network setup scenario):
///
/// [`original_name`, 1st closest node id]
pub fn calculate_relocated_name(mut close_nodes: Vec<XorName>, original_name: &XorName) -> XorName {
    close_nodes.sort_by(|a, b| original_name.cmp_distance(a, b));
    let combined: Vec<u8> = iter::once(original_name)
        .chain(close_nodes.iter().take(2))
        .flat_map(|close_node| close_node.0.into_iter())
        .cloned()
        .collect();
    XorName(sha256::hash(&combined).0)
}

#[cfg(test)]
mod tests {
    use rand;
    use routing_table::Xorable;
    use rust_sodium::crypto::hash::sha256;
    use xor_name::XorName;

    #[test]
    fn calculate_relocated_name() {
        let min_section_size = 8;
        let original_name: XorName = rand::random();

        // one entry
        let mut close_nodes_one_entry: Vec<XorName> = Vec::new();
        close_nodes_one_entry.push(rand::random());
        let actual_relocated_name_one_entry =
            super::calculate_relocated_name(close_nodes_one_entry.clone(), &original_name);
        assert_ne!(original_name, actual_relocated_name_one_entry);

        let mut combined_one_node_vec: Vec<XorName> = Vec::new();
        combined_one_node_vec.push(original_name);
        combined_one_node_vec.push(close_nodes_one_entry[0]);

        let mut combined_one_node: Vec<u8> = Vec::new();
        for node_id in combined_one_node_vec {
            for i in &node_id.0 {
                combined_one_node.push(*i);
            }
        }

        let expected_relocated_name_one_node = XorName(sha256::hash(&combined_one_node).0);

        assert_eq!(actual_relocated_name_one_entry,
                   expected_relocated_name_one_node);

        // TODO: we're not using fixed sizes any more: this code should possibly change!
        // populated closed nodes
        let mut close_nodes: Vec<XorName> = Vec::new();
        for _ in 0..min_section_size {
            close_nodes.push(rand::random());
        }
        let actual_relocated_name = super::calculate_relocated_name(close_nodes.clone(),
                                                                    &original_name);
        assert_ne!(original_name, actual_relocated_name);
        close_nodes.sort_by(|a, b| original_name.cmp_distance(a, b));
        let first_closest = close_nodes[0];
        let second_closest = close_nodes[1];
        let mut combined: Vec<u8> = Vec::new();

        for i in &original_name.0 {
            combined.push(*i);
        }
        for i in &first_closest.0 {
            combined.push(*i);
        }
        for i in &second_closest.0 {
            combined.push(*i);
        }

        let expected_relocated_name = XorName(sha256::hash(&combined).0);
        assert_eq!(expected_relocated_name, actual_relocated_name);

        let mut invalid_combined: Vec<u8> = Vec::new();
        for i in &first_closest.0 {
            invalid_combined.push(*i);
        }
        for i in &second_closest.0 {
            invalid_combined.push(*i);
        }
        for i in &original_name.0 {
            invalid_combined.push(*i);
        }
        let invalid_relocated_name = XorName(sha256::hash(&invalid_combined).0);
        assert_ne!(invalid_relocated_name, actual_relocated_name);
    }
}
