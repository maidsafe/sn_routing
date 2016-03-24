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

use error::RoutingError;
use rustc_serialize::{Decoder, Encodable, Encoder};
use xor_name::XorName;
use sodiumoxide::crypto::hash::sha512;

#[derive(Hash, Clone, Eq, PartialEq, Ord, PartialOrd, RustcEncodable, RustcDecodable, Debug)]
/// The type of an individual copy of immutable data.
pub enum ImmutableDataName {
    /// Used in normal operation. The name of the data is the SHA512 hash of its value.
    Normal(XorName),
    /// Used only when no normal copies are left, or if copies need to be relocated. Its name is
    /// `hash(hash(value))`.
    Backup(XorName),
    /// Only kept if there is unused space left. If storage space becomes scarce, this copy will be
    /// sacrificed. Its name is `hash(hash(hash(value)))`.
    Sacrificial(XorName),
}

impl ImmutableDataName {
    /// Construct a new Normal name by taking the SHA512 digest of `value`.
    pub fn new(value: &[u8]) -> ImmutableDataName {
        ImmutableDataName::Normal(XorName(sha512::hash(value).0))
    }

    /// Construct a new Normal name by copying `raw_name`.
    pub fn from_raw(raw_name: &XorName) -> ImmutableDataName {
        ImmutableDataName::Normal(*raw_name)
    }

    /// Returns the underlying data name without any type info.
    pub fn raw(&self) -> &XorName {
        match *self {
            ImmutableDataName::Normal(ref name) => name,
            ImmutableDataName::Backup(ref name) => name,
            ImmutableDataName::Sacrificial(ref name) => name,
        }
    }

    /// Converts `self` to a Backup name.  Returns an error if the initial type is not Normal or
    /// Backup.
    pub fn to_backup(&self) -> Result<ImmutableDataName, RoutingError> {
        match *self {
            ImmutableDataName::Normal(ref name) => {
                Ok(ImmutableDataName::Backup(XorName(sha512::hash(&name.0).0)))
            }
            ImmutableDataName::Backup(_) => Ok(self.clone()),
            ImmutableDataName::Sacrificial(_) => Err(RoutingError::UnableToDeriveName),
        }
    }

    /// Converts `self` to a Sacrificial name.
    pub fn to_sacrificial(&self) -> ImmutableDataName {
        match *self {
            ImmutableDataName::Normal(ref name) => {
                ImmutableDataName::Sacrificial(XorName(sha512::hash(&sha512::hash(&name.0).0).0))
            }
            ImmutableDataName::Backup(ref name) => {
                ImmutableDataName::Sacrificial(XorName(sha512::hash(&name.0).0))
            }
            ImmutableDataName::Sacrificial(_) => self.clone(),
        }
    }
}

/// An immutable chunk of data.
///
/// Its name is computed from its content by applying the SHA512 hash up to three times, depending
/// on the type ([see `ImmutableDataName` for further details](enum.ImmutableDataName.html)).
#[derive(Hash, Clone, Eq, PartialEq, Ord, PartialOrd, RustcEncodable, RustcDecodable)]
pub struct ImmutableData {
    name: ImmutableDataName,
    value: Vec<u8>,
}

impl ImmutableData {
    /// Creates a new Normal instance of ImmutableData.
    pub fn new(value: Vec<u8>) -> ImmutableData {
        ImmutableData {
            name: ImmutableDataName::new(&value),
            value: value,
        }
    }

    /// Returns the name (which also specifies the chunk type).
    pub fn name(&self) -> &ImmutableDataName {
        &self.name
    }

    /// Returns the underlying name without any type info.
    pub fn raw_name(&self) -> &XorName {
        self.name.raw()
    }

    /// Returns the value.
    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }

    /// Return size of contained value.
    pub fn payload_size(&self) -> usize {
        self.value.len()
    }

    /// Converts the type to Normal, consuming `self`.
    pub fn into_normal(self) -> ImmutableData {
        if let ImmutableDataName::Normal(_) = self.name {
            self
        } else {
            ImmutableData::new(self.value)
        }
    }

    /// Converts the type to Backup, consuming `self`.
    pub fn into_backup(self) -> ImmutableData {
        match self.name {
            ImmutableDataName::Normal(_) => {
                ImmutableData {
                    name: self.name.to_backup().expect("This can't fail"),
                    value: self.value,
                }
            }
            ImmutableDataName::Backup(_) => self,
            ImmutableDataName::Sacrificial(_) => {
                ImmutableData {
                    name: ImmutableDataName::new(&self.value).to_backup().expect("This can't fail"),
                    value: self.value,
                }
            }
        }
    }

    /// Converts the type to Sacrificial, consuming `self`.
    pub fn into_sacrificial(self) -> ImmutableData {
        if let ImmutableDataName::Sacrificial(_) = self.name {
            self
        } else {
            ImmutableData {
                name: self.name.to_sacrificial(),
                value: self.value,
            }
        }
    }
}

impl Debug for ImmutableData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ImmutableData {{ {:?} }}", self.name)
    }
}

#[cfg(test)]
mod test {
    extern crate rand;

    use super::*;
    use self::rand::Rng;
    use rustc_serialize::hex::ToHex;
    use sodiumoxide::crypto::hash::sha512;

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
        let immutable_data = ImmutableData::new(value);
        let immutable_data_name = immutable_data.raw_name().0.to_hex();
        let expected_immutable_data_name = "9f1c9e526f47e36d782de464ea9df0a31a5c19c321f2a5d9c8faac\
                                            dda4d59abc713445c8c853e1842d7c2c2311650df1ee2410737193\
                                            5b6be88a10cbf4cd2f8f";
        assert_eq!(&expected_immutable_data_name, &immutable_data_name);
        // Backup
        let immutable_data_backup = immutable_data.into_backup();
        let immutable_data_backup_name = immutable_data_backup.raw_name().0.to_hex();
        let expected_immutable_data_backup_name = "8c6377c848321dd3c6886a53b1a2bc28a5bc8ce35ac85d1\
                                                   0d75467a5df9434abaee19ce2c710507533d306302b165b\
                                                   4387458b752579fc15e520daaf984a2e38";
        assert_eq!(&expected_immutable_data_backup_name,
                   &immutable_data_backup_name);
        // Sacrificial
        let immutable_data_sacrificial = immutable_data_backup.into_sacrificial();
        let immutable_data_sacrificial_name = immutable_data_sacrificial.raw_name().0.to_hex();
        let expected_immutable_data_sacrificial_name = "ecb6c761c35d4da33b25057fbf6161e68711f9e0c1\
                                                        1122732e62661340e630d3c59f7c165f4862d51db5\
                                                        254a38ab9b15a9b8af431e8500a4eb558b9136bd41\
                                                        35";
        assert_eq!(&expected_immutable_data_sacrificial_name,
                   &immutable_data_sacrificial_name);
    }

    #[test]
    fn name_is_hash_of_lesser_type_name() {
        let value = generate_random();
        let normal = ImmutableData::new(value.clone());
        let backup = normal.clone().into_backup();
        let sacrificial = normal.clone().into_sacrificial();
        assert_eq!(normal.raw_name().0.to_hex(),
                   sha512::hash(&value).0.to_hex());
        assert_eq!(backup.raw_name().0.to_hex(),
                   sha512::hash(&normal.raw_name().0).0.to_hex());
        assert_eq!(sacrificial.raw_name().0.to_hex(),
                   sha512::hash(&backup.raw_name().0).0.to_hex());
    }
}
