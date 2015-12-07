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

// ------------------------------------------------------------------------------
#[deny(missing_docs)]
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, RustcEncodable, RustcDecodable)]
/// Represents response errors.
pub enum ResponseError {
    /// Abort is for user to indicate that the state can be dropped;
    /// if received by routing, it will drop the state.
    Abort,
    /// On low balance or no account registered
    LowBalance(::data::Data, u32),
    /// invalid request
    InvalidRequest(::data::Data),
    /// failure to complete request for data
    FailedRequestForData(::data::Data),
    /// had to clear Sacrificial Data in order to complete request
    HadToClearSacrificial(::XorName, u32),
}

impl From<::cbor::CborError> for ResponseError {
    fn from(_error: ::cbor::CborError) -> ResponseError {
        ResponseError::Abort
    }
}

impl ::std::error::Error for ResponseError {
    fn description(&self) -> &str {
        match *self {
            ResponseError::Abort => "Abort",
            ResponseError::LowBalance(_, _) => "LowBalance",
            ResponseError::InvalidRequest(_) => "Invalid request",
            ResponseError::FailedRequestForData(_) => "Failed request for data",
            ResponseError::HadToClearSacrificial(_, _) => {
                "Had to clear sacrificial data to complete request"
            }
        }
    }

    fn cause(&self) -> Option<&::std::error::Error> {
        None
    }
}

impl ::std::fmt::Display for ResponseError {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self {
            ResponseError::Abort => ::std::fmt::Display::fmt("ResponseError::Abort", formatter),
            ResponseError::LowBalance(_, _) => {
                ::std::fmt::Display::fmt("ResponseError::LowBalance", formatter)
            }
            ResponseError::InvalidRequest(_) => {
                ::std::fmt::Display::fmt("ResponsError::InvalidRequest", formatter)
            }
            ResponseError::FailedRequestForData(_) => {
                ::std::fmt::Display::fmt("ResponseError::FailedToStoreData", formatter)
            }
            ResponseError::HadToClearSacrificial(_, _) => {
                ::std::fmt::Display::fmt("ResponseError::HadToClearSacrificial", formatter)
            }
        }
    }
}


// ------------------------------------------------------------------------------
#[derive(PartialEq, Eq, Clone, Debug)]
/// InterfaceError.
pub enum InterfaceError {
    /// NotConnected.
    NotConnected,
}

impl ::std::error::Error for InterfaceError {
    fn description(&self) -> &str {
        match *self {
            InterfaceError::NotConnected => "Not Connected",
        }
    }

    fn cause(&self) -> Option<&::std::error::Error> {
        match *self {
            _ => None,
        }
    }
}

impl ::std::fmt::Display for InterfaceError {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self {
            InterfaceError::NotConnected => {
                ::std::fmt::Display::fmt("InterfaceError::NotConnected", formatter)
            }
        }
    }
}

// ------------------------------------------------------------------------------
/// ClientError.
pub enum ClientError {
    /// Report Input/Output error.
    Io(::std::io::Error),
    /// Report serialisation error.
    Cbor(::cbor::CborError),
}

impl From<::cbor::CborError> for ClientError {
    fn from(error: ::cbor::CborError) -> ClientError {
        ClientError::Cbor(error)
    }
}

impl From<::std::io::Error> for ClientError {
    fn from(error: ::std::io::Error) -> ClientError {
        ClientError::Io(error)
    }
}

// ------------------------------------------------------------------------------
#[allow(variant_size_differences)]
#[derive(Debug)]
/// RoutingError.
pub enum RoutingError {
    /// The node/client has not bootstrapped yet
    NotBootstrapped,
    /// Invalid State
    Terminated,
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
    Utf8(::std::str::Utf8Error),
    /// interface error
    Interface(InterfaceError),
    /// i/o error
    Io(::std::io::Error),
    /// serialisation error
    Cbor(::cbor::CborError),
    /// invalid response
    Response(ResponseError),
    /// Current state is invalid for the operation
    InvalidStateForOperation,
    /// Serialisation Error
    SerialisationError(::maidsafe_utilities::serialisation::SerialisationError),
    /// Asymmetric Decryption Failure
    AsymmetricDecryptionFailure,
}

impl From<::std::str::Utf8Error> for RoutingError {
    fn from(error: ::std::str::Utf8Error) -> RoutingError {
        RoutingError::Utf8(error)
    }
}


impl From<ResponseError> for RoutingError {
    fn from(error: ResponseError) -> RoutingError {
        RoutingError::Response(error)
    }
}

impl From<::cbor::CborError> for RoutingError {
    fn from(error: ::cbor::CborError) -> RoutingError {
        RoutingError::Cbor(error)
    }
}

impl From<::std::io::Error> for RoutingError {
    fn from(error: ::std::io::Error) -> RoutingError {
        RoutingError::Io(error)
    }
}

impl From<InterfaceError> for RoutingError {
    fn from(error: InterfaceError) -> RoutingError {
        RoutingError::Interface(error)
    }
}

impl From<::maidsafe_utilities::serialisation::SerialisationError> for RoutingError {
    fn from(error: ::maidsafe_utilities::serialisation::SerialisationError) -> RoutingError {
        RoutingError::SerialisationError(error)
    }
}

#[cfg(test)]
mod test {
    use rand;

    fn test_object<T>(obj_before: T)
        where T: for<'a> ::rustc_serialize::Encodable + ::rustc_serialize::Decodable + Eq
    {
        let mut e = ::cbor::Encoder::from_memory();
        unwrap_result!(e.encode(&[&obj_before]));
        let mut d = ::cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: T = unwrap_result!(unwrap_option!(d.decode().next(), ""));
        assert_eq!(obj_after == obj_before, true)
    }

    fn create_data() -> Result<::structured_data::StructuredData, ::error::RoutingError> {
        let keys = ::sodiumoxide::crypto::sign::gen_keypair();
        let owner_keys = vec![keys.0];
        ::structured_data::StructuredData::new(0,
                                               rand::random(),
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
            Ok(d) => {
                test_object(::error::ResponseError::LowBalance(::data::Data::StructuredData(d),
                                                               0u32))
            }
            Err(error) => panic!("Error: {:?}", error),
        }

        // test serialization of InvalidRequest(Data)
        match create_data() {
            Ok(d) => test_object(::error::ResponseError::InvalidRequest(
                ::data::Data::StructuredData(d))),
            Err(error) => panic!("Error: {:?}", error),
        }

        // test serialization of FailedRequestForData(Data)
        match create_data() {
            Ok(d) => test_object(::error::ResponseError::FailedRequestForData(
                ::data::Data::StructuredData(d))),
            Err(error) => panic!("Error: {:?}", error),
        }

        // test serialization of HadToClearSacrificial(::XorName, u32)
        let name: ::XorName = rand::random();
        test_object(::error::ResponseError::HadToClearSacrificial(name, 0u32));
    }

    #[test]
    fn response_error_from() {
        let e = ::cbor::CborError::UnexpectedEOF;
        // from() returns Abort for a CborError
        assert_eq!(::error::ResponseError::Abort,
                   ::error::ResponseError::from(e));
    }

    #[test]
    fn response_error_description() {
        assert_eq!("Abort",
                   ::std::error::Error::description(&::error::ResponseError::Abort));

        match create_data() {
            Ok(d) => {
                assert_eq!("LowBalance",
                ::std::error::Error::description(
                    &::error::ResponseError::LowBalance(::data::Data::StructuredData(d), 0u32)))
            }
            Err(error) => panic!("Error: {:?}", error),
        }

        match create_data() {
            Ok(d) => {
                assert_eq!("Invalid request",
                ::std::error::Error::description(
                    &::error::ResponseError::InvalidRequest(::data::Data::StructuredData(d))))
            }
            Err(error) => panic!("Error: {:?}", error),
        }

        match create_data() {
            Ok(d) => {
                assert_eq!("Failed request for data",
                ::std::error::Error::description(
                   &::error::ResponseError::FailedRequestForData(::data::Data::StructuredData(d))))
            }
            Err(error) => panic!("Error: {:?}", error),
        }

        let name: ::xor_name::XorName = rand::random();
        assert_eq!("Had to clear sacrificial data to complete request",
                   ::std::error::Error::description(
                       &::error::ResponseError::HadToClearSacrificial(name, 0u32)));
    }

    #[test]
    fn response_error_cause() {
        match ::std::error::Error::cause(&::error::ResponseError::Abort) {
            None => {}
            Some(_) => assert!(false),
        }
    }

    #[test]
    fn interface_error_description() {
        assert_eq!("Not Connected",
                   ::std::error::Error::description(&::error::InterfaceError::NotConnected));
    }

    #[test]
    fn inferface_error_cause() {
        match ::std::error::Error::cause(&::error::InterfaceError::NotConnected) {
            None => {}
            Some(_) => assert!(false),
        }
    }
}
