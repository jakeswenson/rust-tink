use crate::TinkError;

pub trait Mac {
  fn compute_mac(data: &[u8]) -> Result<Vec<u8>, TinkError>;

  fn verify_mac(mac: &[u8], data: &[u8]) -> Result<(), TinkError>;
}
