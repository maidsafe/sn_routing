
use std::io;
use std::convert::From;
use cbor::CborError;

//------------------------------------------------------------------------------
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum ResponseError {
    NoData,
    InvalidRequest,
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

//------------------------------------------------------------------------------
#[derive(Debug)]
pub enum RoutingError {
    Other, // TODO: Discuss: we probably don't need this error
    BadAuthority,
    AlreadyConnected,
    UnknownMessageType,
    FilterCheckFailed,
    FailedToBootstrap,
    Interface(InterfaceError),
    Io(io::Error),
    CborError(CborError),
    Response(ResponseError),
}

impl From<ResponseError> for RoutingError {
    fn from(e: ResponseError) -> RoutingError { RoutingError::Response(e) }
}

impl From<CborError> for RoutingError {
    fn from(e: CborError) -> RoutingError { RoutingError::CborError(e) }
}

impl From<io::Error> for RoutingError {
    fn from(e: io::Error) -> RoutingError { RoutingError::Io(e) }
}

impl From<InterfaceError> for RoutingError {
    fn from(e: InterfaceError) -> RoutingError { RoutingError::Interface(e) }
}

