use std::fmt::{self, Display, Formatter};

use crate::keysets::ReadError;
use crate::protos::tink::key_data::KeyMaterialType;

#[derive(Debug)]
pub enum TinkError {
    DecryptionError,
    KeysetReadError(ReadError),
}

impl std::error::Error for TinkError {}

pub struct TinkConfig {}

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

pub trait KeyTypeManager {
    fn key_type(&self) -> &'static str;
    fn version(&self) -> i32;
    fn key_material_type(&self) -> KeyMaterialType;

    fn parse_key<B>(byte_buffer: B) -> Self
    where
        B: prost::bytes::Buf;

    fn validate_key(key: &Self) -> Result<(), TinkError>;
}

pub struct KeyManager(&'static str, i32, KeyMaterialType);

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
