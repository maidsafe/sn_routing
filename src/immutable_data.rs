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

use std::fmt::{Debug, Formatter, Error};

use rustc_serialize::{Decoder, Encodable, Encoder};
use NameType;
use sodiumoxide::crypto;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, RustcEncodable, RustcDecodable, Debug)]
/// ImmutableDataType.
pub enum ImmutableDataType {
    /// Normal.
    Normal,
    /// Backup.
    Backup,
    /// Sacrificial.
    Sacrificial,
}

/// ImmutableData
/// hash == SHA512
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, RustcEncodable, RustcDecodable)]
pub struct ImmutableData {
    type_tag: ImmutableDataType,
    value: Vec<u8>,
}

impl ImmutableData {

    /// Creates a new instance of ImmutableData
    pub fn new(type_tag: ImmutableDataType, value: Vec<u8>) -> ImmutableData {
        ImmutableData { type_tag: type_tag, value: value }
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
    pub fn name(&self) -> NameType {
        let digest = crypto::hash::sha512::hash(&self.value);
        match self.type_tag {
            ImmutableDataType::Normal => return NameType(digest.0),
            ImmutableDataType::Backup => return NameType(crypto::hash::sha512::hash(&digest.0).0),
            ImmutableDataType::Sacrificial => return NameType(crypto::hash::sha512::hash(
            &crypto::hash::sha512::hash(&digest.0).0).0),
        }
    }

    /// Return size of contained value.
    pub fn payload_size(&self) -> usize {
        self.value.len()
    }
}

impl Debug for ImmutableData {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), Error> {
        formatter.write_str(&format!(" {:?}, {:?} ", self.type_tag, self.name()))
    }
}


#[cfg(test)]
mod test {
    extern crate rand;

    use super::{ImmutableData, ImmutableDataType};
    use self::rand::Rng;
    use rustc_serialize::hex::ToHex;
    use sodiumoxide::crypto;

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

        let value = "immutable data value".to_string().into_bytes();
        // Normal
        let immutable_data = ImmutableData::new(ImmutableDataType::Normal, value);
        let immutable_data_name = immutable_data.name().0.as_ref().to_hex();
        let expected_immutable_data_name =
                "9f1c9e526f47e36d782de464ea9df0a31a5c19c321f2a5d9c8faacdda4d59abc713445c8c853e1842d\
                 7c2c2311650df1ee24107371935b6be88a10cbf4cd2f8f";
        assert_eq!(&expected_immutable_data_name, &immutable_data_name);
        // Backup
        let immutable_data_backup = ImmutableData::new(ImmutableDataType::Backup,
                                                       immutable_data.value().clone());
        let immutable_data_backup_name = immutable_data_backup.name().0.as_ref().to_hex();
        let expected_immutable_data_backup_name = "8c6377c848321dd3c6886a53b1a2bc28a5bc8ce35ac85d10\
                                                   d75467a5df9434abaee19ce2c710507533d306302b165b43\
                                                   87458b752579fc15e520daaf984a2e38";
        assert_eq!(&expected_immutable_data_backup_name, &immutable_data_backup_name);
        // Sacrificial
        let immutable_data_sacrificial = ImmutableData::new(ImmutableDataType::Sacrificial,
                                                            immutable_data.value().clone());
        let immutable_data_sacrificial_name = immutable_data_sacrificial.name().0.as_ref().to_hex();
        let expected_immutable_data_sacrificial_name ="ecb6c761c35d4da33b25057fbf6161e68711f9e0c111\
                                                       22732e62661340e630d3c59f7c165f4862d51db5254a\
                                                       38ab9b15a9b8af431e8500a4eb558b9136bd4135";
        assert_eq!(&expected_immutable_data_sacrificial_name, &immutable_data_sacrificial_name);
    }

    #[test]
    fn name_is_hash_of_lesser_type_name() {
        let value = generate_random();
        let normal = ImmutableData::new(ImmutableDataType::Normal, value.clone());
        let backup = ImmutableData::new(ImmutableDataType::Backup, value.clone());
        let sacrificial = ImmutableData::new(ImmutableDataType::Sacrificial, value.clone());
        assert_eq!(normal.name().0.as_ref().to_hex(), crypto::hash::sha512::hash(&value).0.to_hex());
        assert_eq!(backup.name().0.as_ref().to_hex(), crypto::hash::sha512::hash(&normal.name().0).0.to_hex());
        assert_eq!(sacrificial.name().0.as_ref().to_hex(), crypto::hash::sha512::hash(&backup.name().0).0.to_hex());
    }

}
