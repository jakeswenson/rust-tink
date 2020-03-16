use crate::TinkError;

pub struct AeadCiphertext(Vec<u8>, [u8; 16]);

pub struct AeadPlaintext(Vec<u8>);

impl AeadPlaintext {
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

pub type AeadResult<T> = Result<T, TinkError>;

pub trait Aead {
    fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> AeadResult<AeadCiphertext>;
    fn decrypt(&self, ciphertext: &[u8], associated_data: &[u8]) -> AeadResult<AeadPlaintext>;
}

mod algo;
