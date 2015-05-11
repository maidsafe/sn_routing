
use std::io;
use std::convert::From;
use cbor::CborError;
use std::error;
use std::fmt;

//------------------------------------------------------------------------------
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum ResponseError {
    NoData,
    InvalidRequest,
}

impl error::Error for ResponseError {
    fn description(&self) -> &str {
        match *self {
            ResponseError::NoData => "No Data",
            ResponseError::InvalidRequest => "Invalid request",
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
            InterfaceError::Response(ref err) => "Invalid response",
        }
    }
    
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            InterfaceError::Response(ref err) => Some(err as &error::Error),
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
#[derive(Debug)]
pub enum RoutingError {
    BadAuthority,
    AlreadyConnected,
    UnknownMessageType,
    FilterCheckFailed,
    FailedToBootstrap,
    Interface(InterfaceError),
    Io(io::Error),
    Cbor(CborError),
    Response(ResponseError),
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
            RoutingError::BadAuthority => "Invalid authority",
            RoutingError::AlreadyConnected => "Already connected",
            RoutingError::UnknownMessageType => "Invalid message type",
            RoutingError::FilterCheckFailed => "Filter check failure",
            RoutingError::FailedToBootstrap => "Could not bootstrap",
            RoutingError::Interface(ref e) => "Interface error",
            RoutingError::Io(ref err) => "I/O error",
            RoutingError::Cbor(ref err) => "Serialisation error",
            RoutingError::Response(ref err) => "Response error",
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
            RoutingError::BadAuthority => fmt::Display::fmt("Bad authority", f),
            RoutingError::AlreadyConnected => fmt::Display::fmt("already connected", f),
            RoutingError::UnknownMessageType => fmt::Display::fmt("Unknown message", f),
            RoutingError::FilterCheckFailed => fmt::Display::fmt("filter check failed", f),
            RoutingError::FailedToBootstrap => fmt::Display::fmt("could not bootstrap", f),
            RoutingError::Interface(ref err) => fmt::Display::fmt(err, f),
            RoutingError::Io(ref err) => fmt::Display::fmt(err, f),
            RoutingError::Cbor(ref err) => fmt::Display::fmt(err, f),
            RoutingError::Response(ref err) => fmt::Display::fmt(err, f),
        }
    }
}

