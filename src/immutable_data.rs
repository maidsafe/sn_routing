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

use std::fmt::{self, Debug, Formatter};

use rustc_serialize::{Decoder, Encodable, Encoder};
use xor_name::{XorName, XOR_NAME_LEN};
use sodiumoxide::crypto::hash::sha512;

const NORMAL_TO_BACKUP: [u8; XOR_NAME_LEN] =
    [128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

const NORMAL_TO_SACRIFICIAL: [u8; XOR_NAME_LEN] = [255; XOR_NAME_LEN];

const BACKUP_TO_SACRIFICIAL: [u8; XOR_NAME_LEN] =
    [127, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
     255, 255, 255, 255];

fn xor(lhs: &[u8; XOR_NAME_LEN], mut rhs: [u8; XOR_NAME_LEN]) -> XorName {
    for i in 0..XOR_NAME_LEN {
        rhs[i] ^= lhs[i];
    }

    XorName(rhs)
}

#[derive(Hash, Clone, Eq, PartialEq, Ord, PartialOrd, RustcEncodable, RustcDecodable, Debug)]
/// The type of an individual copy of immutable data.
pub enum ImmutableDataType {
    /// Used in normal operation. The name of the data is the SHA512 hash of its value.
    Normal,
    /// Used only when no normal copies are left, or if copies need to be relocated. Its name is
    /// `hash(hash(value))`.
    Backup,
    /// Only kept if there is unused space left. If storage space becomes scarce, this copy will be
    /// sacrificed. Its name is `hash(hash(hash(value)))`.
    Sacrificial,
}

/// An immutable chunk of data.
///
/// Its name is computed from its content by applying the SHA512 hash up to three times, depending
/// on the `ImmutableDataType`.
#[derive(Hash, Clone, Eq, PartialEq, Ord, PartialOrd, RustcEncodable, RustcDecodable)]
pub struct ImmutableData {
    type_tag: ImmutableDataType,
    value: Vec<u8>,
}

impl ImmutableData {
    /// Creates a new instance of ImmutableData
    pub fn new(type_tag: ImmutableDataType, value: Vec<u8>) -> ImmutableData {
        ImmutableData {
            type_tag: type_tag,
            value: value,
        }
    }

    /// Returns the value
    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }

    /// Returns the type
    pub fn get_type_tag(&self) -> &ImmutableDataType {
        &self.type_tag
    }

    /// Returns name ensuring invariant
    pub fn name(&self) -> XorName {
        let digest = sha512::hash(&self.value);
        match self.type_tag {
            ImmutableDataType::Normal => XorName(digest.0),
            ImmutableDataType::Backup => xor(&digest.0, NORMAL_TO_BACKUP),
            ImmutableDataType::Sacrificial => xor(&digest.0, NORMAL_TO_SACRIFICIAL),

        }
    }

    /// Return size of contained value.
    pub fn payload_size(&self) -> usize {
        self.value.len()
    }
}

impl Debug for ImmutableData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ImmutableData {{ {:?}, {} }}", self.type_tag, self.name())
    }
}

/// Convert normal ImmutableData name to backup name.
pub fn normal_to_backup(name: &XorName) -> XorName {
    xor(&name.0, NORMAL_TO_BACKUP)
}

/// Convert backup ImmutableData name to normal name.
pub fn backup_to_normal(name: &XorName) -> XorName {
    xor(&name.0, NORMAL_TO_BACKUP)
}

/// Convert normal ImmutableData name to sacrificial name.
pub fn normal_to_sacrificial(name: &XorName) -> XorName {
    xor(&name.0, NORMAL_TO_SACRIFICIAL)
}

/// Convert sacrificial ImmutableData name to normal name.
pub fn sacrificial_to_normal(name: &XorName) -> XorName {
    xor(&name.0, NORMAL_TO_SACRIFICIAL)
}

/// Convert backup ImmutableData name to sacrificial name.
pub fn backup_to_sacrificial(name: &XorName) -> XorName {
    xor(&name.0, BACKUP_TO_SACRIFICIAL)
}

/// Convert sacrificial ImmutableData name to backup name.
pub fn sacrificial_to_backup(name: &XorName) -> XorName {
    xor(&name.0, BACKUP_TO_SACRIFICIAL)
}

#[cfg(test)]
mod test {
    extern crate rand;

    use super::*;
    use self::rand::Rng;
    use rustc_serialize::hex::ToHex;
    use sodiumoxide::crypto::hash::sha512;
    use xor_name::XorName;

    fn generate_random() -> Vec<u8> {
        let size = 64;
        let mut data = Vec::with_capacity(size);
        let mut rng = rand::thread_rng();
        for _ in 0..size {
            data.push(rng.gen::<u8>());
        }
        data
    }

    #[test]
    fn deterministic_test() {
        let value = "immutable data value".to_owned().into_bytes();

        // Normal
        let immutable_data = ImmutableData::new(ImmutableDataType::Normal, value);
        let immutable_data_name = immutable_data.name().0.as_ref().to_hex();
        let expected_immutable_data_name = "9f1c9e526f47e36d782de464ea9df0a31a5c19c321f\
                                            2a5d9c8faacdda4d59abc713445c8c853e1842d7c2c\
                                            2311650df1ee24107371935b6be88a10cbf4cd2f8f";

        assert_eq!(&expected_immutable_data_name, &immutable_data_name);

        // Backup
        let immutable_data_backup = ImmutableData::new(ImmutableDataType::Backup, immutable_data.value().clone());
        let immutable_data_backup_name = immutable_data_backup.name().0.as_ref().to_hex();
        let expected_immutable_data_backup_name = "1f1c9e526f47e36d782de464ea9df0a31a5c19c321f\
                                                   2a5d9c8faacdda4d59abc713445c8c853e1842d7c2c\
                                                   2311650df1ee24107371935b6be88a10cbf4cd2f8f";

        assert_eq!(&expected_immutable_data_backup_name, &immutable_data_backup_name);

        // Sacrificial
        let immutable_data_sacrificial = ImmutableData::new(ImmutableDataType::Sacrificial,
                                                            immutable_data.value().clone());
        let immutable_data_sacrificial_name = immutable_data_sacrificial.name().0.as_ref().to_hex();
        let expected_immutable_data_sacrificial_name = "60e361ad90b81c9287d21b9b15620f5ce5a3e63cde0\
                                                        d5a26370553225b2a65438ecbba3737ac1e7bd283d3\
                                                        dcee9af20e11dbef8c8e6ca4941775ef340b32d070";

        assert_eq!(&expected_immutable_data_sacrificial_name, &immutable_data_sacrificial_name);
    }

    #[test]
    fn name_is_xor_related_to_lesser_type_name() {
        let value = generate_random();
        let normal = ImmutableData::new(ImmutableDataType::Normal, value.clone());
        let backup = ImmutableData::new(ImmutableDataType::Backup, value.clone());
        let sacrificial = ImmutableData::new(ImmutableDataType::Sacrificial, value.clone());

        assert_eq!(normal.name(), XorName(sha512::hash(&value).0));
        assert_eq!(normal.name(), backup_to_normal(&backup.name()));
        assert_eq!(normal.name(), sacrificial_to_normal(&sacrificial.name()));
        assert_eq!(backup.name(), normal_to_backup(&normal.name()));
        assert_eq!(backup.name(), sacrificial_to_backup(&sacrificial.name()));
        assert_eq!(sacrificial.name(), normal_to_sacrificial(&normal.name()));
        assert_eq!(sacrificial.name(), backup_to_sacrificial(&backup.name()));
    }

}
