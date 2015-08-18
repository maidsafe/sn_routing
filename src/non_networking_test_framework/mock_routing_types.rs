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

pub use routing::data::{Data, DataRequest};
pub use routing::immutable_data::ImmutableDataType;
pub use routing::NameType;

use routing::types::{Address, FromAddress, ToAddress, NodeAddress};

pub trait Mergeable {
    fn merge<'a, I>(xs: I) -> Option<Self> where I: Iterator<Item=&'a Self>;
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

pub const MAX_STRUCTURED_DATA_SIZE_IN_BYTES: usize = 102400;


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