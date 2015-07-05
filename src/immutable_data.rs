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

use rustc_serialize::{Decoder, Encodable, Encoder};
use NameType;
use sodiumoxide::crypto;

#[derive(Clone, RustcEncodable, RustcDecodable, PartialEq, Debug)]
pub enum ImmutableDataType {
    Normal,
    Backup,
    Sacrificaial,
}

/// ImmutableData
/// hash == SHA512
#[derive(Clone, RustcEncodable, RustcDecodable, PartialEq, Debug)]
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


    /// Returns name ensuring invariant
    pub fn name(&self) -> NameType {
        let digest = crypto::hash::sha512::hash(&self.value);
        match self.type_tag {
        ImmutableDataType::Normal => return NameType(digest.0),
        ImmutableDataType::Backup => return NameType(crypto::hash::sha512::hash(&digest.0).0),        
        ImmutableDataType::Sacrificaial => return NameType(crypto::hash::sha512::hash(&crypto::hash::sha512::hash(&digest.0).0).0)
        }
    }

}


#[cfg(test)]
mod test {
    extern crate rand;

    use super::*;
    use self::rand::Rng;
    use cbor::{ Encoder, Decoder};
    use rustc_serialize::{Decodable, Encodable};
    use Random;
    use routing::sendable::Sendable;
    use routing::types::array_as_vector;
    use sodiumoxide::crypto;

    #[allow(unused_variables)]
    impl Random for ImmutableData {
        fn generate_random() -> ImmutableData {
            let size = 64;
            let mut data = Vec::with_capacity(size);
            let mut rng = rand::thread_rng();
            for i in 0..size {
                data.push(rng.gen());
            }
            ImmutableData::new(data)
        }
    }

    #[test]
    fn creation() {
        use rustc_serialize::hex::ToHex;

        let value = "immutable data value".to_string().into_bytes();

        let immutable_data = ImmutableData::new(value);
        let immutable_data_name = immutable_data.name().0.as_ref().to_hex();
        let expected_immutable_data_name =
                "9f1c9e526f47e36d782de464ea9df0a31a5c19c321f2a5d9c8faacdda4d59abc\
                 713445c8c853e1842d7c2c2311650df1ee24107371935b6be88a10cbf4cd2f8f";
        assert_eq!(&expected_immutable_data_name, &immutable_data_name);

        let immutable_data_backup = ImmutableDataBackup::new(immutable_data.clone());
        let immutable_data_backup_name = immutable_data_backup.name().0.as_ref().to_hex();
        let expected_immutable_data_backup_name =
                "8c6377c848321dd3c6886a53b1a2bc28a5bc8ce35ac85d10d75467a5df9434ab\
                 aee19ce2c710507533d306302b165b4387458b752579fc15e520daaf984a2e38";       
        assert_eq!(&expected_immutable_data_backup_name, &immutable_data_backup_name);

        let immutable_data_sacrificial = ImmutableDataSacrificial::new(immutable_data);
        let immutable_data_sacrificial_name = immutable_data_sacrificial.name().0.as_ref().to_hex();
        let expected_immutable_data_sacrificial_name =
                "ecb6c761c35d4da33b25057fbf6161e68711f9e0c11122732e62661340e630d3\
                 c59f7c165f4862d51db5254a38ab9b15a9b8af431e8500a4eb558b9136bd4135";
        assert_eq!(&expected_immutable_data_sacrificial_name, &immutable_data_sacrificial_name);
    }

    #[test]
    fn serialisation() {
        let immutable_data = ImmutableData::generate_random();
        let immutable_data_backup = ImmutableDataBackup::new(immutable_data.clone());
        let immutable_data_sacrificial = ImmutableDataSacrificial::new(immutable_data.clone());

        // ImmutableData
        let mut immutable_data_encoder = Encoder::from_memory();
        immutable_data_encoder.encode(&[&immutable_data]).unwrap();
        let mut immutable_data_decoder =
                Decoder::from_bytes(immutable_data_encoder.as_bytes());
        match immutable_data_decoder.decode().next().unwrap().unwrap() {
            ::test_utils::Parser::ImmutData(decoded_immutable_data) => assert_eq!(immutable_data, decoded_immutable_data),
            _ => panic!("Unexpected!"),
        }

        // ImmutableDataBackup
        let mut immutable_data_backup_encoder = Encoder::from_memory();
        immutable_data_backup_encoder.encode(&[&immutable_data_backup]).unwrap();
        let mut immutable_data_backup_decoder =
                Decoder::from_bytes(immutable_data_backup_encoder.as_bytes());
        match immutable_data_backup_decoder.decode().next().unwrap().unwrap() {
            ::test_utils::Parser::ImmutDataBkup(decoded_immutable_data_backup) => assert_eq!(immutable_data_backup, decoded_immutable_data_backup),
            _ => panic!("Unexpected!"),
        }

        // ImmutableDataSacrificial
        let mut immutable_data_sacrificial_encoder = Encoder::from_memory();
        immutable_data_sacrificial_encoder.encode(&[&immutable_data_sacrificial]).unwrap();
        let mut immutable_data_sacrificial_decoder =
                Decoder::from_bytes(immutable_data_sacrificial_encoder.as_bytes());
        match immutable_data_sacrificial_decoder.decode().next().unwrap().unwrap() {
            ::test_utils::Parser::ImmutDataSacrificial(decoded_immutable_data_sacrificial) => assert_eq!(immutable_data_sacrificial, decoded_immutable_data_sacrificial),
            _ => panic!("Unexpected!"),
        }
    }

    #[test]
    fn equality() {
        let immutable_data_first = ImmutableData::generate_random();
        let immutable_data_second = ImmutableData::generate_random();
        let immutable_data_second_clone = immutable_data_second.clone();

        assert!(immutable_data_first != immutable_data_second);
        assert!(immutable_data_second_clone == immutable_data_second);

        let immutable_data_backup_first = ImmutableDataBackup::new(immutable_data_first.clone());
        let immutable_data_backup_second = ImmutableDataBackup::new(immutable_data_second.clone());
        let immutable_data_backup_second_clone = immutable_data_backup_second.clone();

        assert!(immutable_data_backup_first != immutable_data_backup_second);
        assert!(immutable_data_backup_second_clone == immutable_data_backup_second);

        let immutable_data_sacrificial_first = ImmutableDataSacrificial::new(immutable_data_first.clone());
        let immutable_data_sacrificial_second = ImmutableDataSacrificial::new(immutable_data_second.clone());
        let immutable_data_sacrificial_second_clone = immutable_data_sacrificial_second.clone();

        assert!(immutable_data_sacrificial_first != immutable_data_sacrificial_second);
        assert!(immutable_data_sacrificial_second_clone == immutable_data_sacrificial_second);
    }

    #[test]
    fn invariant_check() {
        let immutable_data = ImmutableData::generate_random();
        let immutable_data_name = array_as_vector(&immutable_data.name().get_id());
        let hash_value = array_as_vector(&crypto::hash::sha512::hash(&immutable_data.value()).0);

        assert_eq!(immutable_data_name, hash_value);
    }
}
