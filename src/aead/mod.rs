use crate::TinkError;

pub struct AeadCiphertext(Vec<u8>, [u8; 16]);

pub struct AeadPlaintext(Vec<u8>);

pub type AeadResult<T> = Result<T, TinkError>;

pub trait AeadPrimative {
    fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> AeadResult<AeadCiphertext>;
    fn decrypt(&self, ciphertext: &[u8], associated_data: &[u8]) -> AeadResult<AeadPlaintext>;
}

mod algo {
    use crypto;
    use crypto::aead::{AeadDecryptor, AeadEncryptor};
    use crypto::aes::KeySize::KeySize256;

    use crate::aead::{AeadCiphertext, AeadPrimative};
    use crate::TinkError;

    struct RustCryptoAead;

    impl AeadPrimative for RustCryptoAead {
        fn encrypt(
            &self,
            plaintext: &[u8],
            associated_data: &[u8],
        ) -> Result<AeadCiphertext, TinkError> {
            let key = vec![];
            let nonce = vec![];
            let aad = vec![];
            let mut gcm = crypto::aes_gcm::AesGcm::new(KeySize256, &key, &nonce, &aad);
            let mut result = Vec::new();
            let mut tag = [0u8; 16];
            gcm.encrypt(&vec![], &mut result, &mut tag);
            Ok(AeadCiphertext(result, tag))
        }

        fn decrypt(&self, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, TinkError> {
            unimplemented!()
        }
    }

    impl RustCryptoAead {
        fn create() -> impl AeadPrimative {
            RustCryptoAead
        }
    }
}
