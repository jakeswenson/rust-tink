pub(crate) use prost::bytes::Buf;
use prost::Message;

pub use errors::TinkError;

use crate::protos::tink::key_data::KeyMaterialType;

pub mod errors;

pub struct TinkConfig {}

mod random {
  fn rand_bytes(_num_bytes: usize) -> Vec<u8> {
    unimplemented!();
  }
}

pub trait KeyFactory {
  type Key: Message;
  type KeyFormat: Message;

  fn validate_key_format(key_format: &Self::KeyFormat) -> Result<(), TinkError>;
  fn parse_key_format<B: Buf>(bytes: B) -> Result<Self::KeyFormat, TinkError>;
  fn create_key(key_format: &Self::KeyFormat) -> Self::Key;
}

pub trait KeyTypeManager {
  type Factory: KeyFactory<Key = Self::Key, KeyFormat = Self::KeyFormat>;
  type Key: Message;
  type KeyFormat: Message;

  const KEY_TYPE: &'static str;

  const VERSION: i32;

  const KEY_MATERIAL_TYPE: KeyMaterialType;

  fn validate_key(key: &Self::Key) -> Result<(), TinkError>;
  fn parse_key<B: Buf>(bytes: B) -> Result<Self::Key, TinkError>;
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
