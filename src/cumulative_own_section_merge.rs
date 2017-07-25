// Copyright 2016 MaidSafe.net limited.
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

use peer_manager::SectionMap;
use routing_table::Prefix;
use std::cmp;
use std::collections::BTreeSet;
use xor_name::XorName;

#[derive(Default)]
pub struct CumulativeOwnSectionMerge {
    merge_prefix: Prefix<XorName>,
    version: u64,
    send_other_section_merge: bool,
    our_merged_section: BTreeSet<XorName>,
}

impl CumulativeOwnSectionMerge {
    /// If multiple nodes dropped from our section, duplicated `OwnSectionMerge` will be sent,
    /// containing different dropped out nodes. This will result in different `OtherSectionMerge` to
    /// be sent out, hence causing non-accumulation on the receiver side.
    /// So here we will take a union of our_merged_section from all the `OwnSectionMerge`, and
    /// resend `OtherSectionMerge` whenever the new union is different to the last one sent out.
    ///
    /// returns `Some(our_merged_section)` for resend `OtherSectionMerge`, otherwise returns `None`.
    pub fn extend_our_merged_section(
        &mut self,
        merge_prefix: Prefix<XorName>,
        sections: &SectionMap,
    ) -> Option<BTreeSet<XorName>> {
        let mut version = 1;
        let mut our_merged_section = BTreeSet::new();
        // Extract the version and merged_section list from the incoming section map.
        for (ver_pfx, peers) in sections {
            if ver_pfx.prefix().is_extension_of(&merge_prefix) {
                version = cmp::max(version, ver_pfx.version() + 1);
                our_merged_section.extend(peers.into_iter().map(|peer| *peer.name()));
            }
        }

        let mut result = None;
        if self.merge_prefix == merge_prefix && self.version == version {
            // Only extends the current our_merged_section when the incoming `OwnSectionMerge` is
            // for the merge_prfix and version currently cumulating.
            our_merged_section.extend(self.our_merged_section.iter());
            if self.send_other_section_merge && our_merged_section != self.our_merged_section {
                // Notify a resend when `OtherSectionMerge` has been sent and the section changed.
                result = Some(our_merged_section.clone())
            }
            self.our_merged_section = our_merged_section;
            return result;
        }

        // When incoming `OwnSectionMerge` have a higher version, overwrites the current record.
        if self.version < version {
            self.merge_prefix = merge_prefix;
            self.version = version;
            self.send_other_section_merge = false;
            self.our_merged_section = our_merged_section;
        }
        result
    }

    /// Returns `our_merged_section` if the prefix_version is what currently being cumulated.
    pub fn get_our_merged_section(
        &mut self,
        merge_prefix: Prefix<XorName>,
        version: u64,
    ) -> Option<BTreeSet<XorName>> {
        if self.merge_prefix == merge_prefix && self.version == version {
            Some(self.our_merged_section.clone())
        } else {
            None
        }
    }

    /// Flags `OtherSectionMerge` has been sent for the prefix_version currently being cumulated.
    pub fn set_send_other_section_merge(&mut self, merge_prefix: Prefix<XorName>, version: u64) {
        if self.merge_prefix == merge_prefix && self.version == version {
            self.send_other_section_merge = true;
        }
    }
}
