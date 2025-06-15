use crate::varint;
use std::fmt;

/// Errors that can occur during encoding/decoding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Zero tag and repeating tags are invalid
    InvalidTag,
    /// Invalid LEB128 encoding
    InvalidVarInt,
    /// Byte count exceeds 2^32 - 1
    InvalidByteCount,
    /// Final size byte must be zero
    InvalidFinalSizeByte,
    /// Variable-length encoding indicates bytes are missing
    MissingBytes,
}

/// Type representing a protocol tag
pub type Tag = u128;

/// Standard tag definitions
pub mod tags {
    use super::Tag;

    /// Reserved
    pub const RESERVED: Tag = 0;
}

/// A struct containing a tag and associated bytes
#[derive(Debug, Clone, PartialEq)]
pub struct TaggedData {
    /// A tag
    pub tag: Tag,
    /// A vector of bytes
    pub bytes: Vec<u8>,
    /// Private field to make struct not directly constructible
    _private: (),
}

impl TaggedData {
    /// Constructs a TaggedData struct. Throws an error if tag is zero or byte count
    /// exceeds 2^32 - 1.
    pub fn new(tag: u128, bytes: Vec<u8>) -> Result<Self, Error> {
        if tag == tags::RESERVED {
            return Err(Error::InvalidTag);
        }

        if bytes.len() > u32::MAX as usize {
            return Err(Error::InvalidByteCount);
        }

        Ok(Self {
            tag,
            bytes,
            _private: (),
        })
    }

    /// Encodes chunks of tagged data into an array of bytes.
    ///
    /// Details:
    /// - Tags are LEB128-encoded
    /// - Repeating tags are encoded using a tag of zero
    /// - Chunk lengths are LEB32-encoded, except for the final chunk
    /// - The final chunk length is encoded as zero
    pub fn encode(chunks: Vec<Self>) -> Vec<u8> {
        let mut bytes = Vec::new();
        let len = chunks.len();
        let mut last_tag = 0;

        for (i, chunk) in chunks.into_iter().enumerate() {
            if chunk.tag == last_tag {
                bytes.push(0);
            } else {
                bytes.extend(varint::encode(chunk.tag));
                last_tag = chunk.tag;
            }

            if i == len - 1 {
                bytes.extend(varint::encode(0));
            } else {
                bytes.extend(varint::encode(chunk.bytes.len() as u128));
            }

            bytes.extend(chunk.bytes);
        }

        bytes
    }

    /// Decodes chunks of tagged data from an array of bytes as [tag][length][data], repeating.
    /// Chunk lengths are LEB32-encoded, and a length of 0 indicates that the remaining array
    /// is the final chunk.
    ///
    /// Returns an empty array if an invalid LEB32-encoding or a chunk length that exceeds
    /// the remaining array length is encountered.
    pub fn decode(bytes: &[u8]) -> Result<Vec<Self>, Error> {
        let mut chunks = Vec::new();
        let mut index = 0;
        let mut last_tag = 0;

        while index < bytes.len() {
            let (tag, size) = varint::decode(&bytes[index..]).map_err(|_| Error::InvalidVarInt)?;
            index += size;

            if tag == last_tag {
                return Err(Error::InvalidTag);
            }

            let tag = if tag == tags::RESERVED {
                last_tag
            } else {
                last_tag = tag;
                tag
            };

            if index >= bytes.len() {
                return Err(Error::MissingBytes);
            }

            let (n, size) = varint::decode(&bytes[index..]).map_err(|_| Error::InvalidVarInt)?;
            index += size;

            let length: usize = if n == 0 {
                bytes.len() - index
            } else if n > u32::MAX.into() {
                return Err(Error::InvalidByteCount);
            } else {
                n.try_into().unwrap()
            };

            if index + length > bytes.len() {
                return Err(Error::MissingBytes);
            }

            if n > 0 && index + length == bytes.len() {
                return Err(Error::InvalidFinalSizeByte);
            }

            chunks.push(Self {
                tag,
                bytes: bytes[index..(index + length)].to_vec(),
                _private: (),
            });
            index += length;
        }

        Ok(chunks)
    }

    /// Encodes tagged data as LEB128-encoded tag followed by bytes
    pub fn encode_without_length(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(varint::encode(self.tag));
        bytes.extend(self.bytes.clone());
        bytes
    }

    /// Decodes tagged data that is not length-encoded
    pub fn decode_without_length(bytes: &[u8]) -> Result<Self, Error> {
        let (tag, size) = varint::decode(bytes).map_err(|_| Error::InvalidVarInt)?;
        Self::new(tag, bytes[size..].to_vec())
    }
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidTag => write!(f, "Invalid tag"),
            Error::InvalidVarInt => write!(f, "Invalid variable integer encoding"),
            Error::InvalidByteCount => write!(f, "Byte count exceeds 2^32 - 1"),
            Error::InvalidFinalSizeByte => write!(f, "Final size byte must be zero"),
            Error::MissingBytes => {
                write!(f, "Variable-length encoding indicates bytes are missing")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_valid() {
        let data = TaggedData::new(123, vec![1, 2, 3]).unwrap();
        assert_eq!(data.tag, 123);
        assert_eq!(data.bytes, vec![1, 2, 3]);
    }

    #[test]
    fn test_new_invalid_tag() {
        let result = TaggedData::new(tags::RESERVED, vec![1, 2, 3]);
        assert_eq!(result.err(), Some(Error::InvalidTag));
    }

    #[test]
    fn test_new_invalid_byte_count() {
        // Can't create one that's too large in practice, but we can test the logic
        // by mocking the size check
        if u32::MAX as usize == usize::MAX {
            // Skip test on platforms where we can't exceed u32::MAX
            return;
        }

        let result = TaggedData::new(1, vec![0; (u32::MAX as usize) + 1]);
        assert_eq!(result.err(), Some(Error::InvalidByteCount));
    }

    #[test]
    fn test_encode_single_chunk() {
        let chunk = TaggedData::new(1, vec![5, 6, 7]).unwrap();
        let encoded = TaggedData::encode(vec![chunk]);

        // Tag(1) + Size(0) + [5,6,7]
        assert_eq!(encoded, vec![1, 0, 5, 6, 7]);
    }

    #[test]
    fn test_encode_multiple_chunks() {
        let chunk1 = TaggedData::new(1, vec![1, 2]).unwrap();
        let chunk2 = TaggedData::new(2, vec![3, 4, 5]).unwrap();
        let encoded = TaggedData::encode(vec![chunk1, chunk2]);

        // Tag(1) + Size(2) + [1,2] + Tag(2) + Size(0) + [3,4,5]
        assert_eq!(encoded, vec![1, 2, 1, 2, 2, 0, 3, 4, 5]);
    }

    #[test]
    fn test_encode_repeated_tag() {
        let chunk1 = TaggedData::new(1, vec![1, 2]).unwrap();
        let chunk2 = TaggedData::new(1, vec![3, 4]).unwrap();
        let chunk3 = TaggedData::new(2, vec![5, 6]).unwrap();
        let encoded = TaggedData::encode(vec![chunk1, chunk2, chunk3]);

        // Tag(1) + Size(2) + [1,2] + Tag(0) + Size(2) + [3,4] + Tag(2) + Size(0) + [5,6]
        assert_eq!(encoded, vec![1, 2, 1, 2, 0, 2, 3, 4, 2, 0, 5, 6]);
    }

    #[test]
    fn test_decode_valid() {
        // Tag(1) + Size(2) + [1,2] + Tag(2) + Size(0) + [3,4,5]
        let encoded = vec![1, 2, 1, 2, 2, 0, 3, 4, 5];
        let decoded = TaggedData::decode(&encoded).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].tag, 1);
        assert_eq!(decoded[0].bytes, vec![1, 2]);
        assert_eq!(decoded[1].tag, 2);
        assert_eq!(decoded[1].bytes, vec![3, 4, 5]);
    }

    #[test]
    fn test_decode_repeated_tag() {
        // Tag(1) + Size(2) + [1,2] + Tag(0) + Size(2) + [3,4] + Tag(2) + Size(0) + [5,6]
        let encoded = vec![1, 2, 1, 2, 0, 2, 3, 4, 2, 0, 5, 6];
        let decoded = TaggedData::decode(&encoded).unwrap();

        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].tag, 1);
        assert_eq!(decoded[0].bytes, vec![1, 2]);
        assert_eq!(decoded[1].tag, 1);
        assert_eq!(decoded[1].bytes, vec![3, 4]);
        assert_eq!(decoded[2].tag, 2);
        assert_eq!(decoded[2].bytes, vec![5, 6]);
    }

    #[test]
    fn test_decode_invalid_varint() {
        // Invalid VarInt (0xFF is not a complete encoding)
        let encoded = vec![0xFF];
        let result = TaggedData::decode(&encoded);

        assert_eq!(result.err(), Some(Error::InvalidVarInt));
    }

    #[test]
    fn test_decode_missing_bytes() {
        // Tag(1) + Size(10) but not enough bytes follow
        let encoded = vec![1, 10, 1, 2, 3];
        let result = TaggedData::decode(&encoded);

        assert_eq!(result.err(), Some(Error::MissingBytes));
    }

    #[test]
    fn test_decode_invalid_final_size_byte() {
        // Tag(1) + Size(3) + [1,2,3] (final size should be 0)
        let encoded = vec![1, 3, 1, 2, 3];
        let result = TaggedData::decode(&encoded);

        assert_eq!(result.err(), Some(Error::InvalidFinalSizeByte));
    }

    #[test]
    fn test_encode_without_length() {
        let data = TaggedData::new(123, vec![1, 2, 3]).unwrap();
        let encoded = data.encode_without_length();

        // Here 123 is encoded as a single byte in LEB128
        assert_eq!(encoded, vec![123, 1, 2, 3]);
    }

    #[test]
    fn test_decode_without_length() {
        // Tag(123) + [1,2,3]
        let encoded = vec![123, 1, 2, 3];
        let decoded = TaggedData::decode_without_length(&encoded).unwrap();

        assert_eq!(decoded.tag, 123);
        assert_eq!(decoded.bytes, vec![1, 2, 3]);
    }

    #[test]
    fn test_roundtrip_encode_decode() {
        let original = vec![
            TaggedData::new(1, vec![1, 2]).unwrap(),
            TaggedData::new(2, vec![3, 4, 5]).unwrap(),
        ];

        let encoded = TaggedData::encode(original.clone());
        let decoded = TaggedData::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_without_length() {
        let original = TaggedData::new(123, vec![1, 2, 3, 4, 5]).unwrap();

        let encoded = original.encode_without_length();
        let decoded = TaggedData::decode_without_length(&encoded).unwrap();

        assert_eq!(original.tag, decoded.tag);
        assert_eq!(original.bytes, decoded.bytes);
    }

    #[test]
    fn test_large_tag_values() {
        // Test encoding/decoding with large tag values that use multiple bytes in LEB128
        let large_tag = 12345678;
        let data = TaggedData::new(large_tag, vec![9, 8, 7]).unwrap();

        let encoded = data.encode_without_length();
        let decoded = TaggedData::decode_without_length(&encoded).unwrap();

        assert_eq!(decoded.tag, large_tag);
        assert_eq!(decoded.bytes, vec![9, 8, 7]);
    }

    #[test]
    fn test_error_display() {
        assert_eq!(format!("{}", Error::InvalidTag), "Invalid tag");
        assert_eq!(
            format!("{}", Error::InvalidVarInt),
            "Invalid variable integer encoding"
        );
        assert_eq!(
            format!("{}", Error::InvalidByteCount),
            "Byte count exceeds 2^32 - 1"
        );
        assert_eq!(
            format!("{}", Error::InvalidFinalSizeByte),
            "Final size byte must be zero"
        );
        assert_eq!(
            format!("{}", Error::MissingBytes),
            "Variable-length encoding indicates bytes are missing"
        );
    }
}
