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

use std::io;
use std::convert::From;
use cbor::CborError;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use std::error;
use std::fmt;
use std::str;
use data::Data;

//------------------------------------------------------------------------------
#[deny(missing_docs)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
/// represents response errors
pub enum ResponseError {
    /// Abort is for user to indicate that the state can be dropped;
    /// if received by routing, it will drop the state.
    Abort,
    /// On low balance or no account registered
    LowBalance(Data, u32),
    /// invalid request
    InvalidRequest(Data),
    /// failure to complete request for data
    FailedRequestForData(Data),
    /// had to clear Sacrificial Data in order to complete request
    HadToClearSacrificial(::NameType, u32),
}

impl From<CborError> for ResponseError {
    fn from(e: CborError) -> ResponseError {
        ResponseError::Abort
    }
}

impl error::Error for ResponseError {
    fn description(&self) -> &str {
        match *self {
            ResponseError::Abort => "Abort",
            ResponseError::LowBalance(_, _) => "LowBalance",
            ResponseError::InvalidRequest(_) => "Invalid request",
            ResponseError::FailedRequestForData(_) => "Failed request for data",
            ResponseError::HadToClearSacrificial(_, _) => "Had to clear Sacrificial data to
              complete request",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ResponseError::Abort => fmt::Display::fmt("ResponseError::Abort", f),
            ResponseError::LowBalance(_, _) => fmt::Display::fmt("ResponseError::LowBalance", f),
            ResponseError::InvalidRequest(_) =>
                fmt::Display::fmt("ResponsError::InvalidRequest", f),
            ResponseError::FailedRequestForData(_) =>
                fmt::Display::fmt("ResponseError::FailedToStoreData", f),
            ResponseError::HadToClearSacrificial(_, _) =>
                fmt::Display::fmt("ResponseError::HadToClearSacrificial", f),
        }
    }
}


//------------------------------------------------------------------------------
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum InterfaceError {
    NotConnected,
}

impl error::Error for InterfaceError {
    fn description(&self) -> &str {
        match *self {
            InterfaceError::NotConnected => "Not Connected",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            _ => None,
        }
    }
}

impl fmt::Display for InterfaceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            InterfaceError::NotConnected => fmt::Display::fmt("InterfaceError::NotConnected", f),
        }
    }
}

//------------------------------------------------------------------------------
pub enum ClientError {
    Io(io::Error),
    Cbor(CborError),
}

impl From<CborError> for ClientError {
    fn from(e: CborError) -> ClientError {
        ClientError::Cbor(e)
    }
}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> ClientError {
        ClientError::Io(e)
    }
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
    fn from(e: str::Utf8Error) -> RoutingError {
        RoutingError::Utf8(e)
    }
}


impl From<ResponseError> for RoutingError {
    fn from(e: ResponseError) -> RoutingError {
        RoutingError::Response(e)
    }
}

impl From<CborError> for RoutingError {
    fn from(e: CborError) -> RoutingError {
        RoutingError::Cbor(e)
    }
}

impl From<io::Error> for RoutingError {
    fn from(e: io::Error) -> RoutingError {
        RoutingError::Io(e)
    }
}

impl From<InterfaceError> for RoutingError {
    fn from(e: InterfaceError) -> RoutingError {
        RoutingError::Interface(e)
    }
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
            RoutingError::Interface(ref err) => Some(err as &error::Error),
            RoutingError::Io(ref err) => Some(err as &error::Error),
            // RoutingError::Cbor(ref err) => Some(err as &error::Error),
            RoutingError::Response(ref err) => Some(err as &error::Error),
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
            RoutingError::NotEnoughSignatures => fmt::Display::fmt("Not enough signatures \
                                   (multi-sig)",
                                  f),
            RoutingError::DuplicateSignatures => fmt::Display::fmt("Duplicated signatures \
                                   (multi-sig)",
                                  f),
            RoutingError::FailedToBootstrap => fmt::Display::fmt("could not bootstrap", f),
            RoutingError::RoutingTableEmpty => fmt::Display::fmt("routing table empty", f),
            RoutingError::RejectedPublicId => fmt::Display::fmt("Rejected Public Id", f),
            RoutingError::RefusedFromRoutingTable =>
                fmt::Display::fmt("Refused from routing table", f),
            RoutingError::RefreshNotFromGroup =>
                fmt::Display::fmt("Refresh message not from group", f),
            RoutingError::Utf8(ref err) => fmt::Display::fmt(err, f),
            RoutingError::Interface(ref err) => fmt::Display::fmt(err, f),
            RoutingError::Io(ref err) => fmt::Display::fmt(err, f),
            RoutingError::Cbor(ref err) => fmt::Display::fmt(err, f),
            RoutingError::Response(ref err) => fmt::Display::fmt(err, f),
        }
    }
}

#[cfg(test)]
mod test {

    fn test_object<T>(obj_before: T)
        where T: for<'a> ::rustc_serialize::Encodable + ::rustc_serialize::Decodable + Eq
    {
        let mut e = ::cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();
        let mut d = ::cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: T = d.decode().next().unwrap().unwrap();
        assert_eq!(obj_after == obj_before, true)
    }
    
    fn create_data() -> Result<::structured_data::StructuredData, ::error::RoutingError> {
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let owner_keys = vec![keys.0];
        ::structured_data::StructuredData::new(0,
                                  ::test_utils::Random::generate_random(),
                                  0,
                                  vec![],
                                  owner_keys.clone(),
                                  vec![],
                                  Some(&keys.1))   
    }

    #[test]
    fn response_error_serialization() {
        // test serialization of ResponseError::Abort
        test_object(::error::ResponseError::Abort);
        
        // test serialization of LowBalance(Data, u32)
        match create_data() {
            Ok(d) => test_object(::error::ResponseError::LowBalance(::data::Data::StructuredData(d), 0u32)),
            Err(error) => panic!("Error: {:?}", error),                                 
        }

        // test serialization of InvalidRequest(Data)
        match create_data() {
            Ok(d) => test_object(::error::ResponseError::InvalidRequest(::data::Data::StructuredData(d))),
            Err(error) => panic!("Error: {:?}", error),                                 
        }
        
        // test serialization of FailedRequestForData(Data)
        match create_data() {
            Ok(d) => test_object(::error::ResponseError::FailedRequestForData(::data::Data::StructuredData(d))),
            Err(error) => panic!("Error: {:?}", error),                                 
        }        
        
        // test serialization of HadToClearSacrificial(::NameType, u32)
        let name: ::name_type::NameType = ::test_utils::Random::generate_random();
        test_object(::error::ResponseError::HadToClearSacrificial(name, 0u32));       
    }
    
    #[test]
    fn response_error_from() {
        let e = ::cbor::CborError::UnexpectedEOF;
        // from() returns Abort for a CborError
        assert_eq!(::error::ResponseError::Abort, ::error::ResponseError::from(e));
    }

    #[test]
    fn response_error_description() {
        assert_eq!("Abort", ::std::error::Error::description(& ::error::ResponseError::Abort));

        match create_data() {
            Ok(d) => assert_eq!("LowBalance",
                ::std::error::Error::description(& ::error::ResponseError::LowBalance(::data::Data::StructuredData(d), 0u32))),
            Err(error) => panic!("Error: {:?}", error),
        }

        match create_data() {
            Ok(d) => assert_eq!("Invalid request",
                ::std::error::Error::description(& ::error::ResponseError::InvalidRequest(::data::Data::StructuredData(d)))),
            Err(error) => panic!("Error: {:?}", error),
        }

        match create_data() {
            Ok(d) => assert_eq!("Failed request for data",
                ::std::error::Error::description(& ::error::ResponseError::FailedRequestForData(::data::Data::StructuredData(d)))),
            Err(error) => panic!("Error: {:?}", error),
        }

        //FIXME is that error str meant to be with newline???
        let name: ::name_type::NameType = ::test_utils::Random::generate_random();
        assert_eq!("Had to clear Sacrificial data to\n              complete request",
            ::std::error::Error::description(& ::error::ResponseError::HadToClearSacrificial(name, 0u32)));
    }

    #[test]
    fn response_error_cause() {
        match ::std::error::Error::cause(&::error::ResponseError::Abort) {
            None => {},
            Some(cause) => assert!(false)
        }
    }

    #[test]
    fn interface_error_description() {
        assert_eq!("Not Connected", ::std::error::Error::description(& ::error::InterfaceError::NotConnected));
    }

    #[test]
    fn inferface_error_cause() {
        match ::std::error::Error::cause(&::error::InterfaceError::NotConnected) {
            None => {},
            Some(cause) => assert!(false)
        }
    }

    #[test]
    fn routing_error_description() {
        assert_eq!("Not bootstrapped", ::std::error::Error::description(& ::error::RoutingError::NotBootstrapped));
        assert_eq!("Invalid authority", ::std::error::Error::description(& ::error::RoutingError::BadAuthority));
        assert_eq!("Already connected", ::std::error::Error::description(& ::error::RoutingError::AlreadyConnected));
        assert_eq!("Invalid message type", ::std::error::Error::description(& ::error::RoutingError::UnknownMessageType));
        assert_eq!("Filter check failure", ::std::error::Error::description(& ::error::RoutingError::FilterCheckFailed));
        assert_eq!("Signature check failure", ::std::error::Error::description(& ::error::RoutingError::FailedSignature));
        assert_eq!("Not enough signatures", ::std::error::Error::description(& ::error::RoutingError::NotEnoughSignatures));
        // FIXME the impl should be "Dublicate signatures", right???
        //assert_eq!("Dublicate signatures", ::std::error::Error::description(& ::error::RoutingError::DuplicateSignatures));
        assert_eq!("Could not bootstrap", ::std::error::Error::description(& ::error::RoutingError::FailedToBootstrap));
        assert_eq!("Routing table empty", ::std::error::Error::description(& ::error::RoutingError::RoutingTableEmpty));
        assert_eq!("Rejected Public Id", ::std::error::Error::description(& ::error::RoutingError::RejectedPublicId));
        assert_eq!("Refused from routing table", ::std::error::Error::description(& ::error::RoutingError::RefusedFromRoutingTable));
        assert_eq!("Refresh message not from group", ::std::error::Error::description(& ::error::RoutingError::RefreshNotFromGroup));
        // FIXME could not create a Utf8Error-struct
        //let utf8 = ::std::str::Utf8Error::new();
        //assert_eq!("String/Utf8 error", ::std::error::Error::description(& ::error::RoutingError::Utf8Error(utf8)));
        assert_eq!("Interface error",
            ::std::error::Error::description(& ::error::RoutingError::Interface(::error::InterfaceError::NotConnected)));
        assert_eq!("I/O error",
            ::std::error::Error::description(& ::error::RoutingError::Io(::std::io::Error::new(::std::io::ErrorKind::Other, "I/O error"))));
        assert_eq!("Serialisation error",
            ::std::error::Error::description(& ::error::RoutingError::Cbor(::cbor::CborError::UnexpectedEOF)));
        assert_eq!("Response error",
            ::std::error::Error::description(& ::error::RoutingError::Response(::error::ResponseError::Abort)));
    }
    
    #[test]
    fn routing_error_cause() {
        match ::std::error::Error::cause(&::error::RoutingError::NotBootstrapped) {
            None => {},
            Some(err) => assert!(false)
        }        
        match ::std::error::Error::cause(&::error::RoutingError::BadAuthority) {
            None => {},
            Some(err) => assert!(false)
        }        
        match ::std::error::Error::cause(&::error::RoutingError::AlreadyConnected) {
            None => {},
            Some(err) => assert!(false)
        }        
        match ::std::error::Error::cause(&::error::RoutingError::FilterCheckFailed) {
            None => {},
            Some(err) => assert!(false)
        }        
        match ::std::error::Error::cause(&::error::RoutingError::FailedSignature) {
            None => {},
            Some(err) => assert!(false)
        }        
        match ::std::error::Error::cause(&::error::RoutingError::NotEnoughSignatures) {
            None => {},
            Some(err) => assert!(false)
        }        
        match ::std::error::Error::cause(&::error::RoutingError::DuplicateSignatures) {
            None => {},
            Some(err) => assert!(false)
        }        
        match ::std::error::Error::cause(&::error::RoutingError::FailedToBootstrap) {
            None => {},
            Some(err) => assert!(false)
        }        
        match ::std::error::Error::cause(&::error::RoutingError::RoutingTableEmpty) {
            None => {},
            Some(err) => assert!(false)
        }
        match ::std::error::Error::cause(&::error::RoutingError::RejectedPublicId) {
            None => {},
            Some(err) => assert!(false)
        }               
        match ::std::error::Error::cause(&::error::RoutingError::RefusedFromRoutingTable) {
            None => {},
            Some(err) => assert!(false)
        }               
        match ::std::error::Error::cause(&::error::RoutingError::RefreshNotFromGroup) {
            None => {},
            Some(err) => assert!(false)
        }               
        match ::std::error::Error::cause(&::error::RoutingError::Interface(::error::InterfaceError::NotConnected)) {
            Some(err) => {},
            None => assert!(false)
        }
        // FIXME could not create a Utf8Error-struct
        //let utf8 = ::std::str::Utf8Error::new();        
        //match ::std::error::Error::cause(&::error::RoutingError::Utf8(utf8)) {
        //    None => {},
        //    Some(err) => assert!(false)
        //}               
        match ::std::error::Error::cause(&::error::RoutingError::Io(::std::io::Error::new(::std::io::ErrorKind::Other, "I/O error"))) {
            Some(err) => {},
            None => assert!(false)
        }
        match ::std::error::Error::cause(&::error::RoutingError::Response(::error::ResponseError::Abort)) {
            Some(err) => {},
            None => assert!(false)
        }
        match ::std::error::Error::cause(&::error::RoutingError::Cbor(::cbor::CborError::UnexpectedEOF)) {
            None => {},
            Some(err) => assert!(false)
        }        
    }   
}
