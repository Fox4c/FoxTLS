extern crate openssl;

mod types;
mod tcp;

pub use types::{Result, CaesarError};
pub use tcp::*;
