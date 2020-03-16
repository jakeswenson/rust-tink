use prost::Message;

use crate::protos::tink::{AesGcmKeyFormat, KeyTemplate, OutputPrefixType};
use crate::TinkError;

pub struct AeadCiphertext(Vec<u8>, [u8; 16]);

pub struct AeadPlaintext(Vec<u8>);

impl AeadPlaintext {
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

pub type AeadResult<T> = Result<T, TinkError>;

/// AEAD primitive (Authenticated Encryption with Associated Data) provides functionality of symmetric authenticated encryption. Implementations of this primitive are secure against adaptive chosen ciphertext attacks.
///
///  When encrypting a plaintext one can optionally provide associated data that should be authenticated but not encrypted. That is, the encryption with associated data ensures authenticity (ie. who the sender is) and integrity (ie. data has not been tampered with) of that data, but not its secrecy (see RFC 5116). This is often used for binding encryptions to a context. For example, in a banking database the contents of a row (e.g. bank account balance) can be encrypted using the customer's id as associated data. This would prevent swapping encrypted data between customers' records.
///
/// Minimal properties:
///
/// - plaintext and associated data can have arbitrary length (within the range 0..232 bytes)
/// - CCA2 security
/// - at least 80-bit authentication strength
/// - there are no secrecy or knowledge guarantees wrt. to the value of associated data
/// - can encrypt at least 232 messages with a total of 250 bytes so that no attack has success probability larger than 2-32
pub trait Aead {
    fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> AeadResult<AeadCiphertext>;
    fn decrypt(&self, ciphertext: &[u8], associated_data: &[u8]) -> AeadResult<AeadPlaintext>;
}

mod algo;

enum AeadKeyTemplates {
    Aes256Gcm,
}

impl AeadKeyTemplates {
    fn template(&self) -> Result<KeyTemplate, TinkError> {
        let aea_gcm_format = AesGcmKeyFormat {
            key_size: 32,
            version: 0,
        };

        let mut bytes =
            prost::bytes::BytesMut::with_capacity(Message::encoded_len(&aea_gcm_format));

        Message::encode(&aea_gcm_format, &mut bytes).map_err(|_| TinkError::DecryptionError)?;

        let key = KeyTemplate {
            type_url: "".to_string(),
            value: bytes.to_vec(),
            output_prefix_type: OutputPrefixType::Tink.into(),
        };

        Ok(key)
    }
}
