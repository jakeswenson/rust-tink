use crate::protos::tink::key_data::KeyMaterialType;
use crate::protos::tink::{AesGcmKey, AesGcmKeyFormat};
use crate::protos::TinkProtoParse;
use crate::{Buf, KeyFactory, KeyTypeManager, TinkError};

#[derive(Clone, Copy)]
pub struct AesGcm;

#[derive(Clone, Copy)]
pub struct AesGcmFactory;

impl AesGcmFactory {
  pub const AES_256: AesGcmKeyFormat = AesGcmKeyFormat {
    key_size: 256 / 8,
    version: 0,
  };
}

impl KeyFactory for AesGcmFactory {
  type Key = AesGcmKey;
  type KeyFormat = AesGcmKeyFormat;

  fn validate_key_format(key_format: &Self::KeyFormat) -> Result<(), TinkError> {
    match key_format.key_size {
      16 | 32 => Ok(()),
      _ => Err(TinkError::ValidationError),
    }
  }

  fn parse_key_format<B: Buf>(bytes: B) -> Result<Self::KeyFormat, TinkError> {
    TinkProtoParse::parse_proto(bytes)
  }

  fn create_key(_key_format: &Self::KeyFormat) -> Self::Key {
    unimplemented!()
  }
}

impl KeyTypeManager for AesGcm {
  type Factory = AesGcmFactory;
  type Key = <AesGcmFactory as KeyFactory>::Key;
  type KeyFormat = <AesGcmFactory as KeyFactory>::KeyFormat;
  const KEY_TYPE: &'static str = "type.googleapis.com/google.crypto.tink.AesGcmKey";
  const VERSION: i32 = 0;
  const KEY_MATERIAL_TYPE: KeyMaterialType = KeyMaterialType::Symmetric;

  fn validate_key(_key: &Self::Key) -> Result<(), TinkError> {
    unimplemented!()
  }

  fn parse_key<B: Buf>(bytes: B) -> Result<Self::Key, TinkError> {
    TinkProtoParse::parse_proto(bytes)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn basics() {
    use super::{AesGcm, KeyTypeManager};
    assert_eq!(
      AesGcm::KEY_TYPE,
      "type.googleapis.com/google.crypto.tink.AesGcmKey"
    );
    assert_eq!(AesGcm::VERSION, 0);
    assert_eq!(AesGcm::KEY_MATERIAL_TYPE, KeyMaterialType::Symmetric);
  }

  #[test]
  fn validate_key_format_empty() {
    assert!(AesGcmFactory::validate_key_format(&AesGcmKeyFormat {
      key_size: 0,
      version: 0
    })
    .is_err())
  }

  #[test]
  fn validate_key_format_valid() {
    assert!(AesGcmFactory::validate_key_format(&AesGcmFactory::AES_256).is_ok())
  }
}
