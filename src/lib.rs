use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::keysets::ReadError;
use crate::protos::tink::key_data::KeyMaterialType;

#[derive(Debug)]
pub enum TinkError {
    DecryptionError,
    KeysetReadError(ReadError),
    ProtobufError,
    UnspecifiedError(Box<dyn Error>),
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
            TinkError::ProtobufError => write!(f, "ProtobufError"),
            TinkError::UnspecifiedError(error) => write!(f, "{}", error),
        }
    }
}

pub trait KeyTypeManager {
    fn key_type(&self) -> &'static str;
    fn version(&self) -> i32;
    fn key_material_type(&self) -> KeyMaterialType;
}

pub struct KeyManager {
    type_url: &'static str,
    version: i32,
    key_material_type: KeyMaterialType,
}

impl KeyTypeManager for KeyManager {
    fn key_type(&self) -> &'static str {
        self.type_url
    }

    fn version(&self) -> i32 {
        self.version
    }

    fn key_material_type(&self) -> KeyMaterialType {
        self.key_material_type.clone()
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
