use prost::bytes::Buf;
use prost::{DecodeError, Message};

use crate::aead::Aead;
use crate::protos::tink::keyset_info::KeyInfo;
use crate::protos::tink::{EncryptedKeyset, Keyset, KeysetInfo};
use crate::TinkError;

pub trait KeysetReader {
    fn read(self) -> Result<Keyset, ReadError>;
    fn read_encrypted(self) -> Result<EncryptedKeyset, ReadError>;
}

pub trait KeysetWriter {
    fn write(&self, keyset: Keyset) -> Result<(), ReadError>;
    fn write_encrypted(&self, keyset: EncryptedKeyset) -> Result<(), ReadError>;
}

#[derive(Debug)]
pub struct ReadError(DecodeError);

impl From<ReadError> for TinkError {
    fn from(read_error: ReadError) -> Self {
        TinkError::KeysetReadError(read_error)
    }
}

impl From<DecodeError> for ReadError {
    fn from(decode_error: DecodeError) -> Self {
        ReadError(decode_error)
    }
}

pub struct BinaryKeysetReader<T>(T)
where
    T: Buf;

impl<T: Buf> KeysetReader for BinaryKeysetReader<T> {
    fn read(self) -> Result<Keyset, ReadError> {
        Ok(Keyset::decode(self.0)?)
    }

    fn read_encrypted(self) -> Result<EncryptedKeyset, ReadError> {
        Ok(EncryptedKeyset::decode(self.0)?)
    }
}

pub struct KeysetHandle {
    keyset: Keyset,
}

trait KeysetAssertions {
    fn assert_no_secret_key_material(&self) -> Result<(), TinkError>;
}

impl KeysetAssertions for Keyset {
    fn assert_no_secret_key_material(&self) -> Result<(), TinkError> {
        if self.key.iter().any(|key| {
            if key.key_data.as_ref().map(|d| d.key_material_type).is_some() {
                true
            } else {
                false
            }
        }) {
            return Err(TinkError::DecryptionError);
        }

        Ok(())
    }
}

impl KeysetHandle {
    pub fn new_no_secrets<T: KeysetReader>(reader: T) -> Result<Self, TinkError> {
        let keyset = reader.read()?;
        keyset.assert_no_secret_key_material()?;
        Ok(KeysetHandle { keyset })
    }

    pub fn new<T: KeysetReader, A: Aead>(reader: T, master_key: A) -> Result<Self, TinkError> {
        let encrypted_keyset = reader.read_encrypted()?;

        let keyset = KeysetHandle::decrypt(encrypted_keyset, &master_key)?;
        Ok(KeysetHandle { keyset })
    }

    fn decrypt(
        encrypted_keyset: EncryptedKeyset,
        master_key: &dyn Aead,
    ) -> Result<Keyset, TinkError> {
        let bytes = encrypted_keyset.encrypted_keyset.as_ref();
        let plaintext = master_key.decrypt(bytes, &[])?;
        Ok(Keyset::decode(plaintext.bytes()).map_err(ReadError)?)
    }

    /// Return the `KeysetInfo` that doesn't contain actual key material. This is safe for logging.
    pub fn keyset_info(&self) -> KeysetInfo {
        KeysetInfo {
            primary_key_id: self.keyset.primary_key_id,
            key_info: self
                .keyset
                .key
                .iter()
                .map(|key| KeyInfo {
                    type_url: key
                        .key_data
                        .as_ref()
                        .map(|data| data.type_url.clone())
                        .unwrap_or_else(String::default),
                    status: key.status,
                    output_prefix_type: key.output_prefix_type,
                    key_id: key.key_id,
                })
                .collect(),
        }
    }
}
