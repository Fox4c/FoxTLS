use std::{io, result, error, fmt};
use std::convert::From;

use openssl::ssl::error::SslError;

#[derive(Debug)]
pub enum CaesarError {
    Ssl(SslError),
    Io(io::Error),
}

pub type Result<T> = result::Result<T, CaesarError>;

impl fmt::Display for CaesarError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CaesarError::Ssl(ref e) => write!(f, "SSL error: {}", e),
            CaesarError::Io(ref e) => write!(f, "IO error: {}", e),
        }
    }
}

impl error::Error for CaesarError {
    fn description(&self) -> &str {
        match *self {
            CaesarError::Ssl(ref e) => e.description(),
            CaesarError::Io(ref e) => e.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            CaesarError::Ssl(ref e) => Some(e),
            CaesarError::Io(ref e) => Some(e),
        }
    }
}

impl From<SslError> for CaesarError {
    fn from(err: SslError) -> CaesarError {
        CaesarError::Ssl(err)
    }
}

impl From<io::Error> for CaesarError {
    fn from(err: io::Error) -> CaesarError {
        CaesarError::Io(err)
    }
}
