use core::fmt;
use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::keysets::ReadError;

#[derive(Debug)]
pub enum TinkError {
  DecryptionError,
  KeysetReadError(ReadError),
  ProtobufError,
  UnspecifiedError(Box<dyn Error>),
  ValidationError,
}

impl std::error::Error for TinkError {}

impl Display for TinkError {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    match self {
      TinkError::DecryptionError => write!(f, "DecryptionError"),
      TinkError::KeysetReadError(read_error) => write!(f, "{:?}", read_error),
      TinkError::ProtobufError => write!(f, "ProtobufError"),
      TinkError::ValidationError => write!(f, "ValidationError"),
      TinkError::UnspecifiedError(error) => write!(f, "{}", error),
    }
  }
}
