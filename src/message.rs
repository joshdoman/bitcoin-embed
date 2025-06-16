//! # Tagged Message Encoding

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

    /// Repeat
    pub const REPEAT: Tag = 0;
}

/// A struct containing a tag and associated bytes
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    /// A tag
    tag: Tag,
    /// A vector of bytes
    body: Vec<u8>,
}

impl Message {
    /// Constructs a Message struct. Throws an error if tag is zero, tag
    /// exceeds 2^127 - 1, or byte count exceeds 2^32 - 1.
    pub fn new(tag: u128, body: Vec<u8>) -> Result<Self, Error> {
        if tag == tags::REPEAT || tag > ((1 << 127) - 1) {
            return Err(Error::InvalidTag);
        }

        if body.len() > u32::MAX as usize {
            return Err(Error::InvalidByteCount);
        }

        Ok(Self { tag, body })
    }

    /// Returns the message tag
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// Returns the message body
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Encodes messages as raw bytes.
    ///
    /// Details:
    /// - Tags are LEB128-encoded as 2 * tag + (1 if terminal tag else 0)
    /// - Repeating tags are encoded using a tag of zero
    /// - Chunk lengths are LEB32-encoded, except for the final chunk
    pub fn encode(messsages: Vec<Self>) -> Vec<u8> {
        let mut bytes = Vec::new();
        let len = messsages.len();
        let mut last_tag = 0;

        for (i, message) in messsages.into_iter().enumerate() {
            let is_last = i == len - 1;

            if message.tag() == last_tag {
                bytes.push(is_last as u8);
            } else {
                bytes.extend(varint::encode(2 * message.tag() + (is_last as u128)));
                last_tag = message.tag;
            }

            if !is_last {
                bytes.extend(varint::encode(message.body.len() as u128));
            }

            bytes.extend(message.body);
        }

        bytes
    }

    /// Decodes messages from raw bytes.
    ///
    /// Returns an empty array if an invalid varint encoding or a chunk length that exceeds
    /// the remaining array length is encountered.
    pub fn decode(bytes: &[u8]) -> Result<Vec<Self>, Error> {
        let mut messages = Vec::new();
        let mut index = 0;
        let mut last_tag = 0;

        while index < bytes.len() {
            let (value, size) =
                varint::decode(&bytes[index..]).map_err(|_| Error::InvalidVarInt)?;
            index += size;

            let is_last = value % 2 == 1;
            let tag = value / 2;

            if tag == last_tag {
                return Err(Error::InvalidTag);
            }

            let tag = if tag == tags::REPEAT {
                last_tag
            } else {
                last_tag = tag;
                tag
            };

            if is_last {
                messages.push(Self {
                    tag,
                    body: bytes[index..].to_vec(),
                });
                break;
            }

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

            messages.push(Self {
                tag,
                body: bytes[index..(index + length)].to_vec(),
            });
            index += length;
        }

        Ok(messages)
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
        let data = Message::new(123, vec![1, 2, 3]).unwrap();
        assert_eq!(data.tag(), 123);
        assert_eq!(data.body(), vec![1, 2, 3]);
    }

    #[test]
    fn test_new_invalid_tag() {
        let result = Message::new(tags::REPEAT, vec![1, 2, 3]);
        assert_eq!(result.err(), Some(Error::InvalidTag));

        let result = Message::new(1 << 127, vec![1, 2, 3]);
        assert_eq!(result.err(), Some(Error::InvalidTag));
    }

    #[test]
    fn test_new_invalid_byte_count() {
        if u32::MAX as usize == usize::MAX {
            // Skip test on platforms where we can't exceed u32::MAX
            return;
        }

        let result = Message::new(1, vec![0; (u32::MAX as usize) + 1]);
        assert_eq!(result.err(), Some(Error::InvalidByteCount));
    }

    #[test]
    fn test_encode_single_chunk() {
        let chunk = Message::new(1, vec![5, 6, 7]).unwrap();
        let encoded = Message::encode(vec![chunk]);

        // Tag (2*1+1=3 terminal) + body [5,6,7]
        assert_eq!(encoded, vec![3, 5, 6, 7]);
    }

    #[test]
    fn test_encode_multiple_chunks() {
        let chunk1 = Message::new(1, vec![1, 2]).unwrap();
        let chunk2 = Message::new(2, vec![3, 4, 5]).unwrap();
        let encoded = Message::encode(vec![chunk1, chunk2]);

        // Tag (2*1+0=2 non-terminal) + Size(2) + [1,2] + Tag (2*2+1=5 terminal) + [3,4,5]
        assert_eq!(encoded, vec![2, 2, 1, 2, 5, 3, 4, 5]);
    }

    #[test]
    fn test_encode_repeated_tag() {
        let chunk1 = Message::new(1, vec![1, 2]).unwrap();
        let chunk2 = Message::new(1, vec![3, 4]).unwrap();
        let chunk3 = Message::new(2, vec![5, 6]).unwrap();
        let encoded = Message::encode(vec![chunk1, chunk2, chunk3]);

        // Tag (2*1+0=2 non-terminal) + Size(2) + [1,2] +
        // Repeat tag (0) + Size(2) + [3,4] +
        // Tag (2*2+1=5 terminal) + [5,6]
        assert_eq!(encoded, vec![2, 2, 1, 2, 0, 2, 3, 4, 5, 5, 6]);
    }

    #[test]
    fn test_decode_valid() {
        // Tag (2*1+0=2 non-terminal) + Size(2) + [1,2] + Tag (2*2+1=5 terminal) + [3,4,5]
        let encoded = vec![2, 2, 1, 2, 5, 3, 4, 5];
        let decoded = Message::decode(&encoded).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].tag(), 1);
        assert_eq!(decoded[0].body(), vec![1, 2]);
        assert_eq!(decoded[1].tag(), 2);
        assert_eq!(decoded[1].body(), vec![3, 4, 5]);
    }

    #[test]
    fn test_decode_repeated_tag() {
        // Tag (2*1+0=2 non-terminal) + Size(2) + [1,2] +
        // Repeat tag (0) + Size(2) + [3,4] +
        // Tag (2*2+1=5 terminal) + [5,6]
        let encoded = vec![2, 2, 1, 2, 0, 2, 3, 4, 5, 5, 6];
        let decoded = Message::decode(&encoded).unwrap();

        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].tag(), 1);
        assert_eq!(decoded[0].body(), vec![1, 2]);
        assert_eq!(decoded[1].tag(), 1); // Repeated tag should be the same as previous
        assert_eq!(decoded[1].body(), vec![3, 4]);
        assert_eq!(decoded[2].tag(), 2);
        assert_eq!(decoded[2].body(), vec![5, 6]);
    }

    #[test]
    fn test_decode_invalid_varint() {
        // Invalid VarInt (0xFF is not a complete encoding)
        let encoded = vec![0xFF];
        let result = Message::decode(&encoded);

        assert_eq!(result.err(), Some(Error::InvalidVarInt));
    }

    #[test]
    fn test_decode_missing_bytes() {
        // Tag (2*1+0=2 non-terminal) + Size(10) but not enough bytes follow
        let encoded = vec![2, 10, 1, 2, 3];
        let result = Message::decode(&encoded);

        assert_eq!(result.err(), Some(Error::MissingBytes));
    }

    #[test]
    fn test_decode_invalid_final_size_byte() {
        // Tag (2*1+0=2 non-terminal) + Size(3) + [1,2,3] (should have terminal tag)
        let encoded = vec![2, 3, 1, 2, 3];
        let result = Message::decode(&encoded);

        assert_eq!(result.err(), Some(Error::InvalidFinalSizeByte));
    }

    #[test]
    fn test_empty_final_body() {
        // Test with a terminal tag and empty body
        let chunk = Message::new(3, vec![]).unwrap();
        let encoded = Message::encode(vec![chunk]);

        // Just the terminal tag (2*3+1=7)
        assert_eq!(encoded, vec![7]);

        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].tag(), 3);
        assert_eq!(decoded[0].body(), Vec::<u8>::new());
    }

    #[test]
    fn test_decode_with_termination_only() {
        // Just a terminal tag with no body (2*5+1=11)
        let encoded = vec![11];
        let decoded = Message::decode(&encoded).unwrap();

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].tag(), 5);
        assert_eq!(decoded[0].body(), Vec::<u8>::new());
    }

    #[test]
    fn test_roundtrip_encode_decode() {
        let original = vec![
            Message::new(1, vec![1, 2]).unwrap(),
            Message::new(2, vec![3, 4, 5]).unwrap(),
        ];

        let encoded = Message::encode(original.clone());
        let decoded = Message::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_large_tag_values() {
        // Test encoding/decoding with large tag values that use multiple bytes in LEB128
        let large_tag = (1 << 127) - 1;
        let data = Message::new(large_tag, vec![9, 8, 7]).unwrap();
        let encoded = Message::encode(vec![data]);
        let decoded = Message::decode(&encoded).unwrap();

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].tag(), large_tag);
        assert_eq!(decoded[0].body(), vec![9, 8, 7]);
    }

    #[test]
    fn test_multi_chunk_with_repeated_tag() {
        let chunks = vec![
            Message::new(10, vec![1, 2]).unwrap(),
            Message::new(10, vec![3, 4]).unwrap(),
            Message::new(10, vec![5, 6]).unwrap(),
            Message::new(20, vec![7, 8, 9]).unwrap(),
        ];

        let encoded = Message::encode(chunks.clone());
        let decoded = Message::decode(&encoded).unwrap();

        assert_eq!(chunks, decoded);
    }
}
