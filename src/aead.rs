//! AEAD primitive (Authenticated Encryption with Associated Data) provides functionality of symmetric authenticated encryption. Implementations of this primitive are secure against adaptive chosen ciphertext attacks.
//!
//!  When encrypting a plaintext one can optionally provide associated data that should be authenticated but not encrypted. That is, the encryption with associated data ensures authenticity (ie. who the sender is) and integrity (ie. data has not been tampered with) of that data, but not its secrecy (see RFC 5116). This is often used for binding encryptions to a context. For example, in a banking database the contents of a row (e.g. bank account balance) can be encrypted using the customer's id as associated data. This would prevent swapping encrypted data between customers' records.
//!
//! Minimal properties:
//!
//! - plaintext and associated data can have arbitrary length (within the range 0..232 bytes)
//! - CCA2 security
//! - at least 80-bit authentication strength
//! - there are no secrecy or knowledge guarantees wrt. to the value of associated data
//! - can encrypt at least 232 messages with a total of 250 bytes so that no attack has success probability larger than 2-32
use prost::Message;

use crate::errors::TinkError;
use crate::protos::tink::{KeyTemplate, OutputPrefixType};
use crate::KeyTypeManager;

pub struct AeadCiphertext(Vec<u8>);

pub struct AeadPlaintext(Vec<u8>);

impl AeadPlaintext {
  pub fn bytes(&self) -> &[u8] {
    &self.0
  }
}

impl AeadCiphertext {
  pub fn bytes(&self) -> &[u8] {
    &self.0
  }
}

pub type AeadResult<T> = Result<T, TinkError>;

pub trait Aead {
  fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> AeadResult<AeadCiphertext>;
  fn decrypt(&self, ciphertext: &[u8], associated_data: &[u8]) -> AeadResult<AeadPlaintext>;
}

mod rust_crypto_aead;

pub mod key_managers;

struct AeadKeyTemplates<KM>
where
  KM: KeyTypeManager,
{
  key_manager: KM,
  format: KM::KeyFormat,
}
#[cfg(target_feature = "rfc#2632")]
impl<KM: KeyTypeManager> AeadKeyTemplates<KM> {
  pub const fn for_latest(key_manager: KM) -> Self {
    Self {
      key_manager,
      format: KM::Factory::LATEST_KEY_FORMAT,
    }
  }
}
use key_managers::aes_gcm::{AesGcm, AesGcmFactory};

impl<KM> AeadKeyTemplates<KM>
where
  KM: KeyTypeManager,
{
  pub const AES_256_GCM: AeadKeyTemplates<AesGcm> = AeadKeyTemplates {
    key_manager: AesGcm,
    format: AesGcmFactory::AES_256,
  };

  fn template(&self) -> KeyTemplate {
    let capacity = Message::encoded_len(&self.format);
    let mut bytes = prost::bytes::BytesMut::with_capacity(capacity);

    Message::encode(&self.format, &mut bytes)
      .expect("This should never error since we compute the exact capacity");

    KeyTemplate {
      type_url: KM::KEY_TYPE.to_string(),
      value: bytes.to_vec(),
      output_prefix_type: OutputPrefixType::Tink.into(),
    }
  }
}
