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

#![allow(unused, dead_code, missing_docs)]

use std::collections::BTreeMap;
use std::convert::From;
use std::cmp::*;
use std::error;
use std::fmt;
use std::hash;
use std::io;
use std::marker::PhantomData;
use std::str;

use cbor;
use cbor::CborError;
use cbor::CborTagEncode;
use rand::random;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use sodiumoxide;
use sodiumoxide::crypto;
use sodiumoxide::crypto::sign;

use routing::authority::Authority;
use routing::data::{Data, DataRequest};
use routing::immutable_data::ImmutableDataType;
use routing::NameType;
use routing::types::{Address, FromAddress, ToAddress, NodeAddress};
use routing::error::{RoutingError, InterfaceError, ResponseError};

pub trait Mergeable {
    fn merge<'a, I>(xs: I) -> Option<Self> where I: Iterator<Item=&'a Self>;
}


/// This trait is required for any type of message to be
/// passed to routing, refresh / account transfer is optional
/// The name will let routing know its a NaeManager and the owner will allow routing to hash
/// the requesters ID with this name (by hashing the requesters ID) for put and post messages
pub trait Sendable {
    fn name(&self)->NameType;
    fn type_tag(&self)->u64;
    fn serialised_contents(&self)->Vec<u8>;
    fn owner(&self)->Option<NameType> { None }
    fn refresh(&self)->bool; // is this an account transfer type
    fn merge(&self, responses: Vec<Box<Sendable>>) -> Option<Box<Sendable>>;
}


/// MethodCall denotes a specific request to be carried out by routing.
#[derive(PartialEq, Eq, Clone)]
pub enum MethodCall {
    /// request to have `destination` to handle put for the `content`
    Put { destination: NameType, content: Data },
    /// request to retreive data with specified type and name from network
    Get { name: NameType, data_request: DataRequest },
    /// request to post
    Post { destination: NameType, content: Data },
    /// Request delete
    Delete { name: NameType, data : Data },
    /// request to refresh
    Refresh { type_tag: u64, from_group: NameType, payload: Vec<u8> },
    /// request to forward on the request to destination for further handling
    Forward { destination: NameType },
    /// reply
    Reply { data: Data },
    /// terminate
    Terminate,
    /// shutdown
    ShutDown
}

