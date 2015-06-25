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

use rustc_serialize::{Decodable, Decoder};

use data_manager::DataManagerStatsSendable;
use data_manager::database::DataManagerSendable;
use maid_manager::database::MaidManagerAccountWrapper;
use pmid_manager::database::PmidManagerAccountWrapper;
use version_handler::VersionHandlerSendable;

mod transfer_tags {
    use maidsafe_types;
    pub const MAIDSAFE_TRANSFER_TAG: u64 = maidsafe_types::MAIDSAFE_TAG + 200;

    pub const MAID_MANAGER_ACCOUNT_TAG: u64 = MAIDSAFE_TRANSFER_TAG + 1;
    pub const DATA_MANAGER_ACCOUNT_TAG: u64 = MAIDSAFE_TRANSFER_TAG + 2;
    pub const PMID_MANAGER_ACCOUNT_TAG: u64 = MAIDSAFE_TRANSFER_TAG + 3;
    pub const VERSION_HANDLER_ACCOUNT_TAG: u64 = MAIDSAFE_TRANSFER_TAG + 4;
    pub const DATA_MANAGER_STATS_TAG: u64 = MAIDSAFE_TRANSFER_TAG + 5;
}

pub enum Transfer {
    MaidManagerAccount(MaidManagerAccountWrapper),
    DataManagerAccount(DataManagerSendable),
    PmidManagerAccount(PmidManagerAccountWrapper),
    VersionHandlerAccount(VersionHandlerSendable),
    DataManagerStats(DataManagerStatsSendable),
    Unknown(u64),
}

impl Decodable for Transfer {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Transfer, D::Error> {
        let tag = try!(decoder.read_u64());
        match tag {
            transfer_tags::MAID_MANAGER_ACCOUNT_TAG => Ok(Transfer::MaidManagerAccount(try!(Decodable::decode(decoder)))),
            transfer_tags::DATA_MANAGER_ACCOUNT_TAG => Ok(Transfer::DataManagerAccount(try!(Decodable::decode(decoder)))),
            transfer_tags::PMID_MANAGER_ACCOUNT_TAG => Ok(Transfer::PmidManagerAccount(try!(Decodable::decode(decoder)))),
            transfer_tags::VERSION_HANDLER_ACCOUNT_TAG => Ok(Transfer::VersionHandlerAccount(try!(Decodable::decode(decoder)))),
            transfer_tags::DATA_MANAGER_STATS_TAG => Ok(Transfer::DataManagerStats(try!(Decodable::decode(decoder)))),
            _ => Ok(Transfer::Unknown(tag)),
        }
    }
}

/*
#[cfg(test)]
 mod test {
    extern crate rand;
    extern crate cbor;

    use rand::Rng;

    use super::*;
    use maidsafe_types::*;

    #[test]
    fn transfer_parsing() {
        let size = 64;
        let mut data = Vec::with_capacity(size);
        let mut rng = rand::thread_rng();
        for _ in 0..size {
            data.push(rng.gen());
        }
        let immutable_data = ImmutableData::new(data);

        let mut encoder = cbor::Encoder::from_memory();
        encoder.encode(&[&immutable_data]).unwrap();

        let mut decoder = cbor::Decoder::from_bytes(encoder.as_bytes());

        match decoder.decode().next().unwrap().unwrap() {
            Data::Immutable(immut_data) => assert_eq!(immut_data, immutable_data),
            _ => panic!("Unexpected!"),
        }
    }
}
*/
