use prost::{bytes::Buf, Message};

use crate::TinkError;

#[path = "protos/google.crypto.tink.rs"]
pub(crate) mod tink;

pub(crate) trait TinkProtoParse {
    fn parse_proto<B: Buf>(input: B) -> Result<Self, TinkError>
    where
        Self: std::marker::Sized;
}

impl<T> TinkProtoParse for T
where
    T: Message + Default,
{
    fn parse_proto<B: Buf>(input: B) -> Result<Self, TinkError>
    where
        Self: std::marker::Sized,
    {
        T::decode(input).map_err(|_| TinkError::ProtobufError)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn testing() {}
}
