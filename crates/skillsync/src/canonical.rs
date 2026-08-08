use thiserror::Error;

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum CanonicalError {
    #[error("canonical value is truncated")]
    Truncated,
    #[error("canonical value has trailing bytes")]
    TrailingBytes,
    #[error("canonical string is not valid UTF-8")]
    InvalidUtf8,
    #[error("canonical length does not fit in u32")]
    LengthOverflow,
    #[error("canonical value has an unknown tag")]
    UnknownTag,
    #[error("canonical map keys are not strictly ordered")]
    UnorderedKeys,
    #[error("canonical value is invalid: {0}")]
    Invalid(&'static str),
}

#[derive(Default)]
pub(crate) struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub(crate) fn new(domain: &[u8]) -> Self {
        Self {
            bytes: domain.to_vec(),
        }
    }

    pub(crate) fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    pub(crate) fn string(&mut self, value: &str) -> Result<(), CanonicalError> {
        let length = u32::try_from(value.len()).map_err(|_| CanonicalError::LengthOverflow)?;
        self.u32(length);
        self.fixed(value.as_bytes());
        Ok(())
    }

    pub(crate) fn sized_bytes(&mut self, value: &[u8]) -> Result<(), CanonicalError> {
        let length = u32::try_from(value.len()).map_err(|_| CanonicalError::LengthOverflow)?;
        self.u32(length);
        self.fixed(value);
        Ok(())
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(bytes: &'a [u8], domain: &[u8]) -> Result<Self, CanonicalError> {
        if !bytes.starts_with(domain) {
            return Err(CanonicalError::Invalid("wrong domain or version"));
        }
        Ok(Self {
            bytes,
            position: domain.len(),
        })
    }

    pub(crate) fn u8(&mut self) -> Result<u8, CanonicalError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32, CanonicalError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, CanonicalError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(crate) fn i64(&mut self) -> Result<i64, CanonicalError> {
        Ok(i64::from_be_bytes(self.array()?))
    }

    pub(crate) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], CanonicalError> {
        self.array()
    }

    pub(crate) fn string(&mut self) -> Result<String, CanonicalError> {
        let bytes = self.sized_bytes()?;
        String::from_utf8(bytes.to_vec()).map_err(|_| CanonicalError::InvalidUtf8)
    }

    pub(crate) fn sized_bytes(&mut self) -> Result<&'a [u8], CanonicalError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| CanonicalError::Invalid("length cannot be represented"))?;
        self.take(length)
    }

    pub(crate) fn finish(self) -> Result<(), CanonicalError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(CanonicalError::TrailingBytes)
        }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CanonicalError> {
        self.take(N)?
            .try_into()
            .map_err(|_| CanonicalError::Truncated)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CanonicalError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(CanonicalError::Truncated)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(CanonicalError::Truncated)?;
        self.position = end;
        Ok(value)
    }
}
