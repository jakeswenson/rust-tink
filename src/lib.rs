use crate::keysets::ReadError;
use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
pub enum TinkError {
    DecryptionError,
    KeysetReadError(ReadError),
}

impl std::error::Error for TinkError {}

pub struct TinkConfige {}

pub trait TinkProvider {
    fn aeads() -> Vec<Box<dyn aead::Aead>>;
}

impl Display for TinkError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TinkError::DecryptionError => write!(f, "DecryptionError"),
            TinkError::KeysetReadError(read_error) => write!(f, "{:?}", read_error),
        }
    }
}

pub mod aead;
pub mod keysets;
pub mod mac;
mod protos;
pub mod signature;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
