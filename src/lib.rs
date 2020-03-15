use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
pub enum TinkError {
    DecryptionError,
}

impl std::error::Error for TinkError {}

pub struct TinkConfige {}

pub trait TinkProvider {
    fn aeads() -> Vec<Box<dyn aead::AeadPrimative>>;
}

impl Display for TinkError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TinkError::DecryptionError => write!(f, "DecryptionError"),
        }
    }
}

pub mod aead;
pub mod mac;
pub mod sign;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
