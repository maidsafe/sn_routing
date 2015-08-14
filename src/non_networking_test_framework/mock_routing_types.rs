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

pub use crust::Endpoint;

pub const NAME_TYPE_LEN : usize = 64;
pub const POLL_DURATION_IN_MILLISEC: u32 = 1;

pub fn array_as_vector(arr: &[u8]) -> Vec<u8> {
  let mut vector = Vec::new();
  for i in arr.iter() {
    vector.push(*i);
  }
  vector
}

pub fn vector_as_u8_64_array(vector: Vec<u8>) -> [u8;64] {
  let mut arr = [0u8;64];
  for i in (0..64) {
    arr[i] = vector[i];
  }
  arr
}

pub fn vector_as_u8_32_array(vector: Vec<u8>) -> [u8;32] {
  let mut arr = [0u8;32];
  for i in (0..32) {
    arr[i] = vector[i];
  }
  arr
}

pub fn generate_random_vec_u8(size: usize) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::with_capacity(size);
    for _ in 0..size {
        vec.push(random::<u8>());
    }
    vec
}

pub static GROUP_SIZE: usize = 8;
pub static QUORUM_SIZE: usize = 6;

pub trait Mergeable {
    fn merge<'a, I>(xs: I) -> Option<Self> where I: Iterator<Item=&'a Self>;
}

pub type MessageId = u32;
pub type NodeAddress = NameType; // (Address, NodeTag)
pub type FromAddress = NameType; // (Address, NodeTag)
pub type ToAddress = NameType; // (Address, NodeTag)
pub type GroupAddress = NameType; // (Address, GroupTag)
pub type SerialisedMessage = Vec<u8>;
pub type IdNode = NameType;
pub type IdNodes = Vec<IdNode>;
pub type Bytes = Vec<u8>;

#[derive(RustcEncodable, RustcDecodable)]
struct SignedKey {
  sign_public_key: sign::PublicKey,
  encrypt_public_key: crypto::box_::PublicKey,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct NameAndTypeId {
  pub name : NameType,
  pub type_id : u64
}


//                        +-> from_node name
//                        |           +-> preserve the message_id when sending on
//                        |           |         +-> destination name
//                        |           |         |
pub type FilterType = (SourceAddress, MessageId, DestinationAddress);

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug, RustcEncodable, RustcDecodable)]
pub enum Address {
    Client(crypto::sign::PublicKey),
    Node(NameType),
}

/// Address of the source of the message
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug, RustcEncodable, RustcDecodable)]
pub enum SourceAddress {
    RelayedForClient(FromAddress /* the relay node */, crypto::sign::PublicKey),
    RelayedForNode(FromAddress   /* the relay node */, NodeAddress),
    Direct(FromAddress),
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug, RustcEncodable, RustcDecodable)]
pub enum DestinationAddress {
    RelayToClient(ToAddress, crypto::sign::PublicKey),
    RelayToNode(ToAddress, FromAddress),
    Direct(ToAddress),
}

impl SourceAddress  {
    pub fn non_relayed_source(&self) -> NameType {
        match *self {
            SourceAddress::RelayedForClient(addr, _) => addr,
            SourceAddress::RelayedForNode(addr, _)   => addr,
            SourceAddress::Direct(addr)              => addr,
        }
    }

    pub fn actual_source(&self) -> Address {
       match *self {
           SourceAddress::RelayedForClient(_, addr) => Address::Client(addr),
           SourceAddress::RelayedForNode(_, addr)   => Address::Node(addr),
           SourceAddress::Direct(addr)              => Address::Node(addr),
       }
    }
}

impl DestinationAddress {
    pub fn non_relayed_destination(&self) -> NameType {
        match *self {
            DestinationAddress::RelayToClient(to_address, _) => to_address,
            DestinationAddress::RelayToNode(to_address, _)   => to_address,
            DestinationAddress::Direct(to_address)           => to_address,
        }
    }
}


#[derive(RustcEncodable, RustcDecodable, PartialEq, PartialOrd, Eq, Ord, Debug, Clone)]
pub enum Authority {
  ClientManager(NameType),  // signed by a client and corresponding ClientName is in our range
  NaeManager(NameType),     // we are responsible for this element
                            // and the destination is the element
  NodeManager(NameType),    // the destination is not the element, and we are responsible for it
  ManagedNode,              // our name is the destination
                            // and the message came from within our range
  ManagedClient(crypto::sign::PublicKey),  // in our group
  Client(crypto::sign::PublicKey),         // detached
  Unknown,
}

///
/// Returns true if both slices are equal in length and have equal contents
///
pub fn slice_equal<T: PartialEq>(lhs: &[T], rhs: &[T]) -> bool {
    lhs.len() == rhs.len() && lhs.iter().zip(rhs.iter()).all(|(a, b)| a == b)
}

/// NameType can be created using the new function by passing ID as it’s parameter.
#[derive(Eq, Copy)]
pub struct NameType(pub [u8; NAME_TYPE_LEN]);

impl NameType {
    pub fn new(id: [u8; NAME_TYPE_LEN]) -> NameType {
        NameType(id)
    }

    // TODO(Ben): Resolve from_data
    // pub fn from_data(data : &[u8]) -> NameType {
    //     NameType::new(&crypto::hash::sha512::hash(data).0)
    // }

    pub fn get_id(&self) -> [u8; NAME_TYPE_LEN] {
        self.0
    }

    // private function exposed in fmt Debug {:?} and Display {} traits
    fn get_debug_id(&self) -> String {
      format!("{:02x}{:02x}{:02x}..{:02x}{:02x}{:02x}",
              self.0[0],
              self.0[1],
              self.0[2],
              self.0[NAME_TYPE_LEN-3],
              self.0[NAME_TYPE_LEN-2],
              self.0[NAME_TYPE_LEN-1])
    }

    // // private function exposed in fmt LowerHex {:x} trait
    // // note(ben): UpperHex explicitly not implemented to prevent mixed usage
    // fn get_full_id(&self) -> String {
    //   let mut full_id = String::with_capacity(2 * NAME_TYPE_LEN);
    //   for char in self.0.iter() {
    //     full_id.push_str(format!("{:02x}", char).as_str());
    //   }
    //   full_id
    // }
}

impl fmt::Debug for NameType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
      write!(f, "{}", self.get_debug_id())
    }
}

impl fmt::Display for NameType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
      write!(f, "{}", self.get_debug_id())
    }
}

// impl fmt::LowerHex for NameType {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(f, "{}", self.get_full_id())
//     }
// }


impl PartialEq for NameType {
    fn eq(&self, other: &NameType) -> bool {
        slice_equal(&self.0, &other.0)
    }
}

/// Returns true if `lhs` is closer to `target` than `rhs`.  "Closer" here is as per the Kademlia
/// notion of XOR distance, i.e. the distance between two `NameType`s is the bitwise XOR of their
/// values.
pub fn closer_to_target(lhs: &NameType, rhs: &NameType, target: &NameType) -> bool {
    for i in 0..lhs.0.len() {
        let res_0 = lhs.0[i] ^ target.0[i];
        let res_1 = rhs.0[i] ^ target.0[i];

        if res_0 != res_1 {
            return res_0 < res_1
        }
    }
    false
}

/// Returns true if `lhs` is closer to `target` than `rhs`, or when `lhs == rhs`.
/// "Closer" here is as per the Kademlia notion of XOR distance,
/// i.e. the distance between two `NameType`s is the bitwise XOR of their values.
pub fn closer_to_target_or_equal(lhs: &NameType, rhs: &NameType, target: &NameType) -> bool {
    for i in 0..lhs.0.len() {
        let res_0 = lhs.0[i] ^ target.0[i];
        let res_1 = rhs.0[i] ^ target.0[i];

        if res_0 != res_1 {
            return res_0 < res_1
        }
    }
    true
}

/// The `NameType` can be ordered from zero as a normal Euclidean number
impl Ord for NameType {
    #[inline]
    fn cmp(&self, other : &NameType) -> Ordering {
        Ord::cmp(&&self.0[..], &&other.0[..])
    }
}

impl PartialOrd for NameType {
    #[inline]
    fn partial_cmp(&self, other : &NameType) -> Option<Ordering> {
        PartialOrd::partial_cmp(&&self.0[..], &&other.0[..])
    }
    #[inline]
    fn lt(&self, other : &NameType) -> bool {
        PartialOrd::lt(&&self.0[..], &&other.0[..])
    }
    #[inline]
    fn le(&self, other : &NameType) -> bool {
        PartialOrd::le(&&self.0[..], &&other.0[..])
    }
    #[inline]
    fn gt(&self, other : &NameType) -> bool {
        PartialOrd::gt(&&self.0[..], &&other.0[..])
    }
    #[inline]
    fn ge(&self, other : &NameType) -> bool {
        PartialOrd::ge(&&self.0[..], &&other.0[..])
    }
}

impl hash::Hash for NameType {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0[..])
    }
}

impl Clone for NameType {
    fn clone(&self) -> Self {
        let mut arr_cloned = [0u8; NAME_TYPE_LEN];
        let &NameType(arr_self) = self;

        for i in 0..arr_self.len() {
            arr_cloned[i] = arr_self[i];
        }

        NameType(arr_cloned)
    }
}

impl Encodable for NameType {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        CborTagEncode::new(5483_000, &(self.0.as_ref())).encode(e)
    }
}

impl Decodable for NameType {
    fn decode<D: Decoder>(d: &mut D)->Result<NameType, D::Error> {
        try!(d.read_u64());
        let id : Vec<u8> = try!(Decodable::decode(d));

        match container_of_u8_to_array!(id, NAME_TYPE_LEN) {
            Some(id_arr) => Ok(NameType(id_arr)),
            None => Err(d.error("Bad NameType size"))
        }
    }
}


pub const MAX_STRUCTURED_DATA_SIZE_IN_BYTES: usize = 102400;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, RustcEncodable, RustcDecodable, Debug)]
pub enum ImmutableDataType {
    Normal,
    Backup,
    Sacrificial,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, RustcEncodable, RustcDecodable, Debug)]
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

    /// Returns the value
    pub fn get_type_tag(&self) -> &ImmutableDataType {
        &self.type_tag
    }

    /// Returns name ensuring invariant
    pub fn name(&self) -> NameType {
        let digest = ::sodiumoxide::crypto::hash::sha512::hash(&self.value);
        match self.type_tag {
            ImmutableDataType::Normal       => NameType(digest.0),
            ImmutableDataType::Backup       => NameType(::sodiumoxide::crypto::hash::sha512::hash(&digest.0).0),
            ImmutableDataType::Sacrificial  => NameType(::sodiumoxide::crypto::hash::sha512::hash(&::sodiumoxide::crypto::hash::sha512::hash(&digest.0).0).0)
        }
    }

    pub fn payload_size(&self) -> usize {
        self.value.len()
    }
}

#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Clone)]
pub struct StructuredData {
    type_tag: u64,
    identifier: NameType,
    version: u64,
    data: Vec<u8>,
    current_owner_keys: Vec<::sodiumoxide::crypto::sign::PublicKey>,
    previous_owner_keys: Vec<::sodiumoxide::crypto::sign::PublicKey>,
    previous_owner_signatures: Vec<::sodiumoxide::crypto::sign::Signature>,
}

impl StructuredData {
    pub fn new(type_tag: u64,
               identifier: NameType,
               data: Vec<u8>,
               previous_owner_keys: Vec<crypto::sign::PublicKey>,
               version: u64,
               current_owner_keys: Vec<crypto::sign::PublicKey>,
               previous_owner_signatures: Vec<crypto::sign::Signature>) -> StructuredData {

        StructuredData {
                   type_tag: type_tag,
                   identifier: identifier,
                   data: data,
                   previous_owner_keys: previous_owner_keys,
                   version: version,
                   current_owner_keys : current_owner_keys,
                   previous_owner_signatures: previous_owner_signatures
                 }
    }

    pub fn get_data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn get_identifier(&self) -> &NameType {
        &self.identifier
    }

    pub fn get_version(&self) -> u64 {
        self.version
    }

    pub fn get_signatures(&self) -> &Vec<::sodiumoxide::crypto::sign::Signature> {
        &self.previous_owner_signatures
    }

    pub fn get_owners(&self) -> &Vec<::sodiumoxide::crypto::sign::PublicKey> {
        &self.current_owner_keys
    }

    pub fn get_previous_owners(&self) -> &Vec<::sodiumoxide::crypto::sign::PublicKey> {
        &self.previous_owner_keys
    }

    /// Returns number of previous_owner_signatures still required (if any, 0 means this is complete)
    pub fn add_signature(&mut self, secret_key: &crypto::sign::SecretKey) -> Result<isize, RoutingError> {
        let data = try!(self.data_to_sign());
        let sig = crypto::sign::sign_detached(&data, secret_key);
        self.previous_owner_signatures.push(sig);
        Ok(((self.previous_owner_keys.len() + 1) as isize / 2) -
             self.previous_owner_signatures.len() as isize)
    }

    pub fn data_to_sign(&self) -> Result<Vec<u8>, RoutingError> {
        // seems overkill to use serialisation here, but done
        // to ensure cross platform signature handling is OK
        let mut enc = cbor::Encoder::from_memory();
        try!(enc.encode(self.type_tag.to_string().as_bytes()));
        try!(enc.encode(&[self.identifier]));
        try!(enc.encode(&self.data));
        try!(enc.encode(&self.previous_owner_keys));
        try!(enc.encode(&self.current_owner_keys));
        try!(enc.encode(self.version.to_string().as_bytes()));
        Ok(enc.into_bytes())
    }

    pub fn get_type_tag(&self) -> u64 {
        self.type_tag
    }

    pub fn name(&self) -> NameType {
        StructuredData::compute_name(self.type_tag, &self.identifier)
    }

    pub fn compute_name(type_tag: u64, identifier: &NameType) -> NameType {
        use ::sodiumoxide::crypto::hash::sha512::hash;
        NameType(
            hash(&hash(&identifier.0).0.iter().chain(type_tag.to_string().as_bytes().iter()).map(|a| *a).collect::<Vec<u8>>()[..]).0)
    }

    /// replace this data item with an updated version if such exists, otherwise fail.
    /// This is done this way to allow types to be created and previous_owner_signatures added one by one
    /// To transfer ownership the current owner signs over the data, the previous owners field
    /// must have the previous owners of version - 1 as the current owners of that last version.
    pub fn replace_with_other(&mut self, other: StructuredData) -> Result<(), RoutingError> {
        // TODO(dirvine) Increase error types to be more descriptive  :07/07/2015
        if      other.type_tag != self.type_tag     ||
                other.identifier != self.identifier ||
                other.version != self.version + 1   ||
                other.previous_owner_keys != self.current_owner_keys  {
            return Err(RoutingError::UnknownMessageType)
        }
        try!(other.verify_previous_owner_signatures());

                   self.type_tag = other.type_tag;
                   self.identifier = other.identifier;
                   self.data = other.data;
                   self.previous_owner_keys = other.previous_owner_keys;
                   self.version = other.version;
                   self.current_owner_keys  = other.current_owner_keys;
                   self.previous_owner_signatures = other.previous_owner_signatures;
                   Ok(())
    }

    pub fn replace_signatures(&mut self, new_signatures: Vec<::sodiumoxide::crypto::sign::Signature>) {
        self.previous_owner_signatures = new_signatures;
    }

    pub fn payload_size(&self) -> usize {
        self.data.len()
    }

    /// Confirms *unique and valid* previous_owner_signatures are at least 50% of total owners
    fn verify_previous_owner_signatures(&self) -> Result<(), RoutingError> {
         // Refuse any duplicate previous_owner_signatures (people can have many owner keys)
         // Any duplicates invalidates this type
         if self.previous_owner_signatures.iter().filter(|&sig| self.previous_owner_signatures.iter()
                                  .any(|ref sig_check| NameType(sig.0) == NameType(sig_check.0)))
                                  .count() > (self.previous_owner_keys.len() + 1) /2 {

            return Err(RoutingError::DuplicateSignatures);
         }


         // Refuse when not enough previous_owner_signatures found
         if self.previous_owner_signatures.len() < (self.previous_owner_keys.len()  + 1 ) / 2 {
             return Err(RoutingError::NotEnoughSignatures);
         }

         let data = try!(self.data_to_sign());
         // Count valid previous_owner_signatures and refuse if quantity is not enough
         if self.previous_owner_signatures.iter()
                        .filter(|&sig| self.previous_owner_keys
                          .iter()
                          .any(|ref pub_key| crypto::sign::verify_detached(&sig, &data, &pub_key)))
                            .count() < self.previous_owner_keys.len() / 2 {
            return Err(RoutingError::NotEnoughSignatures);
         }
         Ok(())
    }

}

impl ::rustc_serialize::Encodable for StructuredData {
    fn encode<E: ::rustc_serialize::Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        let mut curr_owner = Vec::<Vec<u8>>::new();
        for it in self.current_owner_keys.iter() {
            curr_owner.push(it.0.iter().map(|a| *a).collect());
        }

        let mut prev_owner = Vec::<Vec<u8>>::new();
        for it in self.previous_owner_keys.iter() {
            prev_owner.push(it.0.iter().map(|a| *a).collect());
        }

        let mut previous_owner_signatures = Vec::<Vec<u8>>::new();
        for it in self.previous_owner_signatures.iter() {
            previous_owner_signatures.push(it.0.iter().map(|a| *a).collect());
        }

        ::cbor::CborTagEncode::new(100_001, &(&self.identifier,
                                           self.type_tag,
                                           self.version,
                                           &self.data,
                                           curr_owner,
                                           prev_owner,
                                           previous_owner_signatures)).encode(e)
    }
}

impl ::rustc_serialize::Decodable for StructuredData {
    fn decode<D: ::rustc_serialize::Decoder>(d: &mut D) -> Result<Self, D::Error> {
        try!(d.read_u64());

        let (identifier,
             type_tag,
             version,
             data,
             curr_owner,
             previous_owner_keys,
             previous_owner_signatures):
            (NameType,
             u64,
             u64,
             Vec<u8>,
             Vec<Vec<u8>>,
             Vec<Vec<u8>>,
             Vec<Vec<u8>>) = try!(::rustc_serialize::Decodable::decode(d));

        let mut vec_current_owner = Vec::<::sodiumoxide::crypto::sign::PublicKey>::new();
        for it in curr_owner.iter() {
            let mut arr_current = [0u8; 32];
            for it_inner in it.iter().enumerate() {
                arr_current[it_inner.0] = *it_inner.1;
            }

            vec_current_owner.push(::sodiumoxide::crypto::sign::PublicKey(arr_current));
        }

        let mut vec_prev_owner = Vec::<::sodiumoxide::crypto::sign::PublicKey>::new();
        for it in previous_owner_keys.iter() {
            let mut arr_current = [0u8; 32];
            for it_inner in it.iter().enumerate() {
                arr_current[it_inner.0] = *it_inner.1;
            }

            vec_prev_owner.push(::sodiumoxide::crypto::sign::PublicKey(arr_current));
        }

        let mut signatures_decoded = Vec::<::sodiumoxide::crypto::sign::Signature>::new();
        for it in previous_owner_signatures.iter() {
            let mut arr_current = [0u8; 64];
            for it_inner in it.iter().enumerate() {
                arr_current[it_inner.0] = *it_inner.1;
            }

            signatures_decoded.push(::sodiumoxide::crypto::sign::Signature(arr_current));
        }

        Ok(StructuredData {
            type_tag: type_tag,
            identifier: identifier,
            version: version,
            data: data,
            current_owner_keys: vec_current_owner,
            previous_owner_keys: vec_prev_owner,
            previous_owner_signatures: signatures_decoded,
        })
    }
}


#[derive(Clone, PartialEq, Eq, RustcEncodable, RustcDecodable)]
pub enum DataRequest {
    StructuredData(u64),
    ImmutableData(ImmutableDataType),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, RustcEncodable, RustcDecodable)]
pub enum Data {
    StructuredData(StructuredData),
    ImmutableData(ImmutableData),
    ShutDown
}

impl Data {
    pub fn name(&self) -> NameType {
        match *self {
            Data::StructuredData(ref d) => d.name(),
            Data::ImmutableData(ref d)  => d.name(),
            _ => NameType::new([0; 64]),
        }
    }

    pub fn payload_size(&self) -> usize {
        match *self {
            Data::StructuredData(ref d) => d.payload_size(),
            Data::ImmutableData(ref d)  => d.payload_size(),
            _ => 0,
        }
    }
}


//------------------------------------------------------------------------------
#[deny(missing_docs)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
/// represents response errors
pub enum ResponseError {
    /// data not found
    NoData,
    /// invalid request
    InvalidRequest,
    /// failure to store data
    FailedToStoreData(Data)
}

impl error::Error for ResponseError {
    fn description(&self) -> &str {
        match *self {
            ResponseError::NoData => "No Data",
            ResponseError::InvalidRequest => "Invalid request",
            ResponseError::FailedToStoreData(_) => "Failed to store data",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ResponseError::NoData => fmt::Display::fmt("ResponsError::NoData", f),
            ResponseError::InvalidRequest => fmt::Display::fmt("ResponsError::InvalidRequest", f),
            ResponseError::FailedToStoreData(_) =>
                fmt::Display::fmt("ResponseError::FailedToStoreData", f),
        }
    }
}

impl Encodable for ResponseError {
    fn encode<E: Encoder>(&self, e: &mut E)->Result<(), E::Error> {
        let type_tag;
        let mut data : Option<Data> = None;
        match *self {
            ResponseError::NoData => type_tag = "NoData",
            ResponseError::InvalidRequest => type_tag = "InvalidRequest",
            ResponseError::FailedToStoreData(ref err_data) => {
                type_tag = "FailedToStoreData";
                data = Some(err_data.clone());
            }
        };
        CborTagEncode::new(5483_100, &(&type_tag, &data)).encode(e)
    }
}

impl Decodable for ResponseError {
    fn decode<D: Decoder>(d: &mut D)->Result<ResponseError, D::Error> {
        try!(d.read_u64());
        // let mut type_tag : String;
        // // let mut data : Option<Vec<u8>>;
        let (type_tag, data) : (String, Option<Data>)
            = try!(Decodable::decode(d));
        match &type_tag[..] {
            "NoData" => Ok(ResponseError::NoData),
            "InvalidRequest" => Ok(ResponseError::InvalidRequest),
            "FailedToStoreData" => {
                match data {
                    Some(err_data) => Ok(ResponseError::FailedToStoreData(err_data)),
                    None => Err(d.error("No data in FailedToStoreData"))
                }
            },
            _ => Err(d.error("Unrecognised ResponseError"))
        }
    }
}

//------------------------------------------------------------------------------
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum InterfaceError {
    Abort,
    Response(ResponseError),
}

impl From<ResponseError> for InterfaceError {
    fn from(e: ResponseError) -> InterfaceError {
        InterfaceError::Response(e)
    }
}

impl error::Error for InterfaceError {
    fn description(&self) -> &str {
        match *self {
            InterfaceError::Abort => "Aborted",
            InterfaceError::Response(_) => "Invalid response",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            InterfaceError::Response(ref err) => Some(err),
            _ => None,
        }
    }
}

impl fmt::Display for InterfaceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            InterfaceError::Abort => fmt::Display::fmt("InterfaceError::Abort", f),
            InterfaceError::Response(ref err) => fmt::Display::fmt(err, f)
        }
    }
}

//------------------------------------------------------------------------------
pub enum ClientError {
    Io(io::Error),
    Cbor(CborError),
}

impl From<CborError> for ClientError {
    fn from(e: CborError) -> ClientError { ClientError::Cbor(e) }
}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> ClientError { ClientError::Io(e) }
}

//------------------------------------------------------------------------------
#[deny(missing_docs)]
#[derive(Debug)]
/// Represents routing error types
pub enum RoutingError {
    /// The node/client has not bootstrapped yet
    NotBootstrapped,
    /// invalid requester or handler authorities
    BadAuthority,
    /// failure to connect to an already connected node
    AlreadyConnected,
    /// received message having unknown type
    UnknownMessageType,
    /// Failed signature check
    FailedSignature,
    /// Not Enough signatures
    NotEnoughSignatures,
    /// Duplicate signatures
    DuplicateSignatures,
    /// duplicate request received
    FilterCheckFailed,
    /// failure to bootstrap off the provided endpoints
    FailedToBootstrap,
    /// unexpected empty routing table
    RoutingTableEmpty,
    /// public id rejected because of unallowed relocated status
    RejectedPublicId,
    /// routing table did not add the node information,
    /// either because it was already added, or because it did not improve the routing table
    RefusedFromRoutingTable,
    /// We received a refresh message but it did not contain group source address
    RefreshNotFromGroup,
    /// String errors
    Utf8(str::Utf8Error),
    /// interface error
    Interface(InterfaceError),
    /// i/o error
    Io(io::Error),
    /// serialisation error
    Cbor(CborError),
    /// invalid response
    Response(ResponseError),
}

impl From<str::Utf8Error> for RoutingError {
    fn from(e: str::Utf8Error) -> RoutingError { RoutingError::Utf8(e) }
}


impl From<ResponseError> for RoutingError {
    fn from(e: ResponseError) -> RoutingError { RoutingError::Response(e) }
}

impl From<CborError> for RoutingError {
    fn from(e: CborError) -> RoutingError { RoutingError::Cbor(e) }
}

impl From<io::Error> for RoutingError {
    fn from(e: io::Error) -> RoutingError { RoutingError::Io(e) }
}

impl From<InterfaceError> for RoutingError {
    fn from(e: InterfaceError) -> RoutingError { RoutingError::Interface(e) }
}

impl error::Error for RoutingError {
    fn description(&self) -> &str {
        match *self {
            RoutingError::NotBootstrapped => "Not bootstrapped",
            RoutingError::BadAuthority => "Invalid authority",
            RoutingError::AlreadyConnected => "Already connected",
            RoutingError::UnknownMessageType => "Invalid message type",
            RoutingError::FilterCheckFailed => "Filter check failure",
            RoutingError::FailedSignature => "Signature check failure",
            RoutingError::NotEnoughSignatures => "Not enough signatures",
            RoutingError::DuplicateSignatures => "Not enough signatures",
            RoutingError::FailedToBootstrap => "Could not bootstrap",
            RoutingError::RoutingTableEmpty => "Routing table empty",
            RoutingError::RejectedPublicId => "Rejected Public Id",
            RoutingError::RefusedFromRoutingTable => "Refused from routing table",
            RoutingError::RefreshNotFromGroup => "Refresh message not from group",
            RoutingError::Utf8(_) => "String/Utf8 error",
            RoutingError::Interface(_) => "Interface error",
            RoutingError::Io(_) => "I/O error",
            RoutingError::Cbor(_) => "Serialisation error",
            RoutingError::Response(_) => "Response error",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            RoutingError::Interface(ref err) => Some(err),
            RoutingError::Io(ref err) => Some(err),
            // RoutingError::Cbor(ref err) => Some(err as &error::Error),
            RoutingError::Response(ref err) => Some(err),
            _ => None,
        }
    }
}

impl fmt::Display for RoutingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RoutingError::NotBootstrapped => fmt::Display::fmt("Not bootstrapped", f),
            RoutingError::BadAuthority => fmt::Display::fmt("Bad authority", f),
            RoutingError::AlreadyConnected => fmt::Display::fmt("already connected", f),
            RoutingError::UnknownMessageType => fmt::Display::fmt("Unknown message", f),
            RoutingError::FilterCheckFailed => fmt::Display::fmt("filter check failed", f),
            RoutingError::FailedSignature => fmt::Display::fmt("Signature check failed", f),
            RoutingError::NotEnoughSignatures => fmt::Display::fmt("Not enough signatures (multi-sig)", f),
            RoutingError::DuplicateSignatures => fmt::Display::fmt("Duplicated signatures (multi-sig)", f),
            RoutingError::FailedToBootstrap => fmt::Display::fmt("could not bootstrap", f),
            RoutingError::RoutingTableEmpty => fmt::Display::fmt("routing table empty", f),
            RoutingError::RejectedPublicId => fmt::Display::fmt("Rejected Public Id", f),
            RoutingError::RefusedFromRoutingTable => fmt::Display::fmt("Refused from routing table", f),
            RoutingError::RefreshNotFromGroup => fmt::Display::fmt("Refresh message not from group", f),
            RoutingError::Utf8(ref err) => fmt::Display::fmt(err, f),
            RoutingError::Interface(ref err) => fmt::Display::fmt(err, f),
            RoutingError::Io(ref err) => fmt::Display::fmt(err, f),
            RoutingError::Cbor(ref err) => fmt::Display::fmt(err, f),
            RoutingError::Response(ref err) => fmt::Display::fmt(err, f),
        }
    }
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



// TODO: the following definition is just temporary, needs to be replaced with new routing API
pub enum RoutingMessage {
    HandleGet ( DataRequest,            // data_request
                Authority,              // our_authority
                Authority,              // from_authority
                SourceAddress ),        // from_address
    HandlePut ( Authority,              // our_authority
                Authority,              // from_authority
                SourceAddress,          // from_address
                DestinationAddress,     // dest_address
                Data ),                 // data
    // HandlePost { our_authority : Authority,
    //              from_authority: Authority,
    //              from_address  : SourceAddress,
    //              dest_address  : DestinationAddress,
    //              data          : Data },
    // HandleRefresh { type_tag   : u64,
    //                 from_group : NameType,
    //                 payloads   : Vec<Vec<u8>> },
    // HandleChurn { close_group  : Vec<NameType> },
    // HandleGetResponse { from_address    : NameType,
    //                        response     : Data},
    // HandlePutResponse { from_authority  : Authority,
    //                     from_address    : SourceAddress,
    //                     response        : ResponseError },
    // HandlePostResponse { from_authority : Authority,
    //                      from_address   : SourceAddress,
    //                      response       : ResponseError },
    // HandleCacheGet { data_request       : DataRequest,
    //                  data_location      : NameType,
    //                  from_address       : NameType },
    // HandleCachePut { from_authority     : Authority,
    //                  from_address       : NameType,
    //                  data               : Data },
    ShutDown
}


#[deny(missing_docs)]
/// The Interface trait introduces the methods expected to be implemented by the user
pub trait Interface : Sync + Send {
    /// depending on our_authority and from_authority, data or address of the node
    /// potentially storing data with specified name and type_id is returned, on success.
    /// failure to provide data or an address is indicated as an InterfaceError.
    /// OurAuthority contains the NameType when relevant.
    fn handle_get(&mut self,
                  data_request   : DataRequest,
                  our_authority  : Authority,
                  from_authority : Authority,
                  from_address   : SourceAddress) -> Result<Vec<MethodCall>, InterfaceError>;

    /// depending on our_authority and from_authority, data is stored on current node or an address
    /// (with different authority) for further handling of the request is provided.
    /// failure is indicated as an InterfaceError.
    fn handle_put(&mut self,
                  our_authority  : Authority,
                  from_authority : Authority,
                  from_address   : SourceAddress,
                  dest_address   : DestinationAddress,
                  data           : Data) -> Result<Vec<MethodCall>, InterfaceError>;

    /// depending on our_authority and from_authority, post request is handled by current node or
    /// an address for further handling of the request is provided. Failure is indicated as an
    /// InterfaceError.
    fn handle_post(&mut self,
                   our_authority : Authority,
                   from_authority: Authority,
                   from_address  : SourceAddress,
                   dest_address  : DestinationAddress,
                   data          : Data) -> Result<Vec<MethodCall>, InterfaceError>;

    /// Handle messages internal to the group (triggered by churn events). Payloads
    /// from these messages are grouped by (type_tag, from_group) key, and once
    /// there is enough of them, they are returned in the `payloads` argument.
    fn handle_refresh(&mut self, type_tag: u64, from_group: NameType, payloads: Vec<Vec<u8>>);

    /// handles the response to a put request. Depending on ResponseError, performing an action of
    /// type MethodCall is requested.
    fn handle_get_response(&mut self,
                           from_address : NameType,
                           response     : Data) -> Vec<MethodCall>;

    /// handles the response to a put request. Depending on ResponseError, performing an action of
    /// type MethodCall is requested.
    fn handle_put_response(&mut self,
                           from_authority : Authority,
                           from_address   : SourceAddress,
                           response       : ResponseError) -> Vec<MethodCall>;

    /// handles the response to a post request. Depending on ResponseError, performing an action of
    /// type MethodCall is requested.
    fn handle_post_response(&mut self,
                            from_authority : Authority,
                            from_address   : SourceAddress,
                            response       : ResponseError) -> Vec<MethodCall>;

    /// handles the actions to be carried out in the event of a churn. The function provides a list
    /// of actions (of type MethodCall) to be carried out in order to update relevant nodes.
    fn handle_churn(&mut self, close_group: Vec<NameType>) -> Vec<MethodCall>;

    /// attempts to potentially retrieve data from cache.
    fn handle_cache_get(&mut self,
                        data_request  : DataRequest,
                        data_location : NameType,
                        from_address  : NameType) -> Result<MethodCall, InterfaceError>;

    /// attempts to store data in cache. The type of data and/or from_authority indicates
    /// if store in cache is required.
    fn handle_cache_put(&mut self,
                        from_authority: Authority,
                        from_address: NameType,
                        data: Data) -> Result<MethodCall, InterfaceError>;
}


/// utility function to serialise an Encodable type
pub fn serialise<T>(data: &T) -> Result<Vec<u8>, ResponseError>
                                 where T: Encodable {
    let mut encoder = ::cbor::Encoder::from_memory();
    encoder.encode(&[data]);
    Ok(encoder.into_bytes())
}


/// utility function to deserialise a Decodable type
pub fn deserialise<T>(data: &[u8]) -> Result<T, ResponseError>
                                      where T: Decodable {
    let mut d = cbor::Decoder::from_bytes(data);
    Ok(d.decode().next().ok_or(ResponseError::InvalidRequest).unwrap().unwrap())
}



#[derive(Clone)]
pub struct Id {
  sign_keys: (crypto::sign::PublicKey, crypto::sign::SecretKey),
  encrypt_keys: (crypto::box_::PublicKey, crypto::box_::SecretKey),
  name: NameType
}

impl Id {
    pub fn new() -> Id {

        let sign_keys =  sodiumoxide::crypto::sign::gen_keypair();
        let name = NameType::new(crypto::hash::sha512::hash(&sign_keys.0[..]).0);
        Id {
          sign_keys : sign_keys,
          encrypt_keys : sodiumoxide::crypto::box_::gen_keypair(),
          name : name,
        }
    }

    // FIXME: We should not copy private nor public keys.
    pub fn signing_public_key(&self) -> crypto::sign::PublicKey {
        self.sign_keys.0
    }

    pub fn signing_private_key(&self) -> &crypto::sign::SecretKey {
        &self.sign_keys.1
    }

    pub fn encrypting_public_key(&self) -> crypto::box_::PublicKey {
        self.encrypt_keys.0
    }

    pub fn with_keys(sign_keys: (crypto::sign::PublicKey, crypto::sign::SecretKey),
                     encrypt_keys: (crypto::box_::PublicKey, crypto::box_::SecretKey))-> Id {
        let name = NameType::new(crypto::hash::sha512::hash(&sign_keys.0[..]).0);
        Id {
          sign_keys : sign_keys,
          encrypt_keys : encrypt_keys,
          name : name,
        }
    }

    pub fn name(&self) -> NameType {
      self.name
    }

    pub fn set_name(&mut self, name: NameType) {
        // This function should not exist, it is here only temporarily
        // to fix compilation.
        self.name = name;
    }

    pub fn is_self_relocated(&self) -> bool {
        // This function should not exist, it is here only temporarily
        // to fix compilation.
        self.name == NameType::new(crypto::hash::sha512::hash(&self.sign_keys.0[..]).0)
    }

    // name field is initially same as original_name, this should be later overwritten by
    // relocated name provided by the network using this method
    pub fn assign_relocated_name(&mut self, relocated_name: NameType) -> bool {
        if self.is_relocated() || self.name == relocated_name {
            return false;
        }
        self.name = relocated_name;
        return true;
    }

    // checks if the name is updated to a relocated name
    pub fn is_relocated(&self) -> bool {
        self.name != NameType::new(crypto::hash::sha512::hash(&self.sign_keys.0[..]).0)
    }
}