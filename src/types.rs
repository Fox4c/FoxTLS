use std::{io, result};

use openssl::ssl::error::SslError;

#[derive(Debug)]
pub enum CaesarError {
    Ssl(SslError),
    Io(io::Error),
}

pub type Result<T> = result::Result<T, CaesarError>;
