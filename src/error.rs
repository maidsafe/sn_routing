
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
pub enum RecvError {
    DontKnow,
    Interface(InterfaceError),
    Io(io::Error),
    CborError(CborError),
    ResponseError(ResponseError),
}


impl From<()> for RecvError {
    fn from(e: ()) -> RecvError { RecvError::DontKnow }
}

impl From<ResponseError> for RecvError {
    fn from(e: ResponseError) -> RecvError { RecvError::ResponseError(e) }
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

