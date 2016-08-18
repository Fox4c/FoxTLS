use std::{io, result, error, fmt};
use std::convert::From;

use openssl::ssl::error::SslError;

#[derive(Debug)]
pub enum FoxTLSError {
    Ssl(SslError),
    Io(io::Error),
}

pub type Result<T> = result::Result<T, FoxTLSError>;

impl fmt::Display for FoxTLSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FoxTLSError::Ssl(ref e) => write!(f, "SSL error: {}", e),
            FoxTLSError::Io(ref e) => write!(f, "IO error: {}", e),
        }
    }
}

impl error::Error for FoxTLSError {
    fn description(&self) -> &str {
        match *self {
            FoxTLSError::Ssl(ref e) => e.description(),
            FoxTLSError::Io(ref e) => e.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            FoxTLSError::Ssl(ref e) => Some(e),
            FoxTLSError::Io(ref e) => Some(e),
        }
    }
}

impl From<SslError> for FoxTLSError {
    fn from(err: SslError) -> FoxTLSError {
        FoxTLSError::Ssl(err)
    }
}

impl From<io::Error> for FoxTLSError {
    fn from(err: io::Error) -> FoxTLSError {
        FoxTLSError::Io(err)
    }
}
