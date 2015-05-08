
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
pub enum RoutingError {
  FailedToBootstrap,
  NoData,
  IncorrectData(Vec<u8>),
}

#[derive(Debug)]
pub enum RecvError {
    DontKnow,
    Interface(InterfaceError),
    Io(io::Error),
    CborError(CborError),
    RoutingError(RoutingError),
}


impl From<()> for RecvError {
    fn from(e: ()) -> RecvError { RecvError::DontKnow }
}

impl From<RoutingError> for RecvError {
    fn from(e: RoutingError) -> RecvError { RecvError::RoutingError(e) }
}

impl From<CborError> for RecvError {
    fn from(e: CborError) -> RecvError { RecvError::CborError(e) }
}

impl From<io::Error> for RecvError {
    fn from(e: io::Error) -> RecvError { RecvError::Io(e) }
}

impl From<InterfaceError> for RecvError {
    fn from(e: InterfaceError) -> RecvError { RecvError::Interface(e) }
}

