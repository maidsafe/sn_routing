
use std::io;
use std::convert::From;
use cbor::CborError;

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum InterfaceError {
  Abort,
  NoData,
  InvalidRequest,
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum ResponseError {
  FailedToBootstrap,
  NoData,
  IncorrectData(Vec<u8>),
}

#[derive(Debug)]
pub enum RoutingError {
    DontKnow,
    Interface(InterfaceError),
    Io(io::Error),
    CborError(CborError),
    ResponseError(ResponseError),
}


impl From<()> for RoutingError {
    fn from(e: ()) -> RoutingError { RoutingError::DontKnow }
}

impl From<ResponseError> for RoutingError {
    fn from(e: ResponseError) -> RoutingError { RoutingError::ResponseError(e) }
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

