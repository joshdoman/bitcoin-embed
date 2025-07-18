//! # Bitcoin Embed
//!
//! A library for embedding arbitrary data and TLV-encoded messages in Bitcoin transactions. Supports
//! OP_RETURN outputs, witness script envelopes, and taproot annexes.
//!
//! See README.md for detailed documentation.

// Coding conventions
#![deny(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]

#[cfg(not(any(feature = "std")))]
compile_error!("`std` must be enabled");

use bitcoin::{Transaction, Txid, taproot::LeafVersion};
use std::fmt;
use std::str::FromStr;

pub mod envelope;
pub mod message;
pub mod varint;

/// The initial byte in a data-carrying taproot annex
pub const TAPROOT_ANNEX_DATA_TAG: u8 = 0;

/// The script type used by an envelope
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ScriptType {
    /// Legacy script (P2WSH)
    Legacy,
    /// Tapscript
    Tapscript,
}

/// The type of location where data may exist in a transaction
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum EmbeddingType {
    /// An `OP_RETURN`
    OpReturn,
    /// A taproot annex
    TaprootAnnex,
    /// An `OP_FALSE OP_IF <DATA> OP_ENDIF` envelope in witness script
    WitnessEnvelope(ScriptType),
    /// An `OP_FALSE OP_IF <DATA> OP_ENDIF` envelope in bare output script
    BareEnvelope,
}

/// The location where data exists in a transaction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbeddingLocation {
    /// An `OP_RETURN` with the output index
    OpReturn {
        /// The index of the transaction output
        output: usize,
    },

    /// A taproot annex with the input index
    TaprootAnnex {
        /// The index of the transaction input
        input: usize,
    },

    /// An `OP_FALSE OP_IF <DATA> OP_ENDIF` witness envelope with the input index, envelope index, and data push sizes
    ///
    /// Witness envelopes are found in the following contexts:
    /// 1. TapScript leaf scripts in Taproot script path spends (P2TR)
    /// 2. Witness scripts in P2WSH spends with at least 2 witness stack elements
    WitnessEnvelope {
        /// The index of the transaction input
        input: usize,
        /// The index of the envelope within the script
        index: usize,
        /// The sizes of individual data pushes within the envelope
        pushes: Vec<usize>,
        /// The script type
        script_type: ScriptType,
    },

    /// An `OP_FALSE OP_IF <DATA> OP_ENDIF` bare script envelope with the output index, envelope index, and data push sizes
    BareEnvelope {
        /// The index of the transaction output
        output: usize,
        /// The index of the envelope within the script
        index: usize,
        /// The sizes of individual data pushes within the envelope
        pushes: Vec<usize>,
    },
}

impl EmbeddingLocation {
    /// Returns the embedding type
    pub fn to_type(&self) -> EmbeddingType {
        match self {
            EmbeddingLocation::OpReturn { .. } => EmbeddingType::OpReturn,
            EmbeddingLocation::BareEnvelope { .. } => EmbeddingType::BareEnvelope,
            EmbeddingLocation::TaprootAnnex { .. } => EmbeddingType::TaprootAnnex,
            EmbeddingLocation::WitnessEnvelope { script_type, .. } => {
                EmbeddingType::WitnessEnvelope(*script_type)
            }
        }
    }
}

/// A unique identifier for an embedding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EmbeddingId {
    /// The transaction ID
    pub txid: Txid,
    /// The embedding type
    pub embedding_type: EmbeddingType,
    /// The input or output index
    pub index: usize,
    /// The sub-index (only for envelope embeddings)
    pub sub_index: Option<usize>,
    /// Private field to prevent direct construction
    _private: bool,
}

/// Error types for decoding an EmbeddingId
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbeddingIdError {
    /// Invalid format for embedding ID
    InvalidFormat,
    /// Invalid transaction ID
    InvalidTxid,
    /// Invalid embedding type
    InvalidType,
    /// Invalid index value
    InvalidIndex,
}

/// A struct containing data and its location in a transaction
#[derive(Debug, Clone, PartialEq)]
pub struct Embedding {
    /// The data
    pub bytes: Vec<u8>,
    /// The transaction ID
    pub txid: Txid,
    /// The location in the transaction
    pub location: EmbeddingLocation,
}

impl Embedding {
    /// Returns the embedding id
    pub fn id(&self) -> EmbeddingId {
        let embedding_type = self.location.to_type();

        let (index, sub_index) = match self.location {
            EmbeddingLocation::OpReturn { output } => (output, None),
            EmbeddingLocation::BareEnvelope { output, index, .. } => (output, Some(index)),
            EmbeddingLocation::TaprootAnnex { input } => (input, None),
            EmbeddingLocation::WitnessEnvelope { input, index, .. } => (input, Some(index)),
        };

        EmbeddingId {
            txid: self.txid,
            embedding_type,
            index,
            sub_index,
            _private: false,
        }
    }

    /// Returns the embedding type
    pub fn to_type(&self) -> EmbeddingType {
        self.location.to_type()
    }

    /// Extracts the tape in a transaction
    pub fn from_transaction(tx: &Transaction) -> Vec<Self> {
        let mut embeddings = Vec::new();
        let txid = tx.compute_txid();

        // OP_RETURN / Bare Envelope
        for (output, txout) in tx.output.iter().enumerate() {
            if txout.script_pubkey.is_op_return() {
                let location = EmbeddingLocation::OpReturn { output };

                embeddings.push(Self {
                    bytes: txout.script_pubkey.to_bytes()[1..].to_vec(),
                    txid,
                    location,
                });
            } else {
                let envelopes = envelope::from_script(&txout.script_pubkey);

                for (index, envelope) in envelopes.into_iter().enumerate() {
                    let mut bytes = Vec::new();
                    let mut pushes = Vec::new();

                    for chunk in envelope {
                        bytes.extend(chunk.clone());
                        pushes.push(chunk.len());
                    }

                    let location = EmbeddingLocation::BareEnvelope {
                        output,
                        index,
                        pushes,
                    };

                    embeddings.push(Self {
                        bytes,
                        txid,
                        location,
                    });
                }
            }
        }

        // Witness Envelope
        for (input, txin) in tx.input.iter().enumerate() {
            let mut script = None;
            let mut script_type = None;
            let witness = &txin.witness;

            // Tapscript
            if let Some(leaf_script) = witness.taproot_leaf_script() {
                if leaf_script.version == LeafVersion::TapScript {
                    script = Some(leaf_script.script);
                    script_type = Some(ScriptType::Tapscript);
                }
            }

            // P2WSH (no tapscript, no annex, and at least 2 elements)
            if script.is_none() && witness.taproot_annex().is_none() && witness.len() > 1 {
                if let Some(witness_script) = witness.witness_script() {
                    script = Some(witness_script);
                    script_type = Some(ScriptType::Legacy);
                }
            }

            let (Some(script), Some(script_type)) = (script, script_type) else {
                continue;
            };

            let envelopes = envelope::from_script(script);

            for (index, envelope) in envelopes.into_iter().enumerate() {
                let mut bytes = Vec::new();
                let mut pushes = Vec::new();

                for chunk in envelope {
                    bytes.extend(chunk.clone());
                    pushes.push(chunk.len());
                }

                let location = EmbeddingLocation::WitnessEnvelope {
                    input,
                    index,
                    pushes,
                    script_type,
                };

                embeddings.push(Self {
                    bytes,
                    txid,
                    location,
                });
            }
        }

        // Annex
        for (input, txin) in tx.input.iter().enumerate() {
            if let Some(annex) = txin.witness.taproot_annex() {
                if annex.len() > 2 && annex[1] == TAPROOT_ANNEX_DATA_TAG {
                    let location = EmbeddingLocation::TaprootAnnex { input };

                    embeddings.push(Self {
                        bytes: annex[2..].to_vec(),
                        txid,
                        location,
                    });
                }
            }
        }

        embeddings
    }
}

impl fmt::Display for ScriptType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ScriptType::Legacy => write!(f, "Legacy P2WSH"),
            ScriptType::Tapscript => write!(f, "Tapscript"),
        }
    }
}

impl fmt::Display for EmbeddingType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EmbeddingType::OpReturn => write!(f, "OP_RETURN"),
            EmbeddingType::BareEnvelope => write!(f, "Bare Envelope"),
            EmbeddingType::TaprootAnnex => write!(f, "Taproot Annex"),
            EmbeddingType::WitnessEnvelope(script_type) => write!(f, "{script_type} Envelope"),
        }
    }
}

impl fmt::Display for EmbeddingLocation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EmbeddingLocation::OpReturn { output } => {
                write!(f, "OP_RETURN at output {output}")
            }
            EmbeddingLocation::BareEnvelope { output, index, .. } => {
                write!(f, "Bare Envelope at output {} (index {})", output, index)
            }
            EmbeddingLocation::TaprootAnnex { input } => {
                write!(f, "Taproot Annex at input {input}")
            }
            EmbeddingLocation::WitnessEnvelope {
                input,
                index,
                script_type,
                ..
            } => {
                write!(f, "{script_type} Envelope at input {input} (index {index})",)
            }
        }
    }
}

impl fmt::Display for EmbeddingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.embedding_type {
            EmbeddingType::OpReturn => {
                write!(f, "{}:rt:{}", self.txid, self.index)
            }
            EmbeddingType::TaprootAnnex => {
                write!(f, "{}:ta:{}", self.txid, self.index)
            }
            EmbeddingType::WitnessEnvelope(script_type) => {
                let type_code = match script_type {
                    ScriptType::Legacy => "le",
                    ScriptType::Tapscript => "te",
                };

                if let Some(sub_index) = self.sub_index {
                    if sub_index > 0 {
                        return write!(
                            f,
                            "{}:{}:{}:{}",
                            self.txid, type_code, self.index, sub_index
                        );
                    }
                }

                write!(f, "{}:{}:{}", self.txid, type_code, self.index)
            }
            EmbeddingType::BareEnvelope => {
                let type_code = "be";
                if let Some(sub_index) = self.sub_index {
                    if sub_index > 0 {
                        return write!(
                            f,
                            "{}:{}:{}:{}",
                            self.txid, type_code, self.index, sub_index
                        );
                    }
                }

                write!(f, "{}:{}:{}", self.txid, type_code, self.index)
            }
        }
    }
}

impl FromStr for EmbeddingId {
    type Err = EmbeddingIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();

        if parts.len() < 3 || parts.len() > 4 {
            return Err(EmbeddingIdError::InvalidFormat);
        }

        let txid = Txid::from_str(parts[0]).map_err(|_| EmbeddingIdError::InvalidTxid)?;

        let embedding_type = match parts[1] {
            "rt" => EmbeddingType::OpReturn,
            "be" => EmbeddingType::BareEnvelope,
            "ta" => EmbeddingType::TaprootAnnex,
            "le" => EmbeddingType::WitnessEnvelope(ScriptType::Legacy),
            "te" => EmbeddingType::WitnessEnvelope(ScriptType::Tapscript),
            _ => return Err(EmbeddingIdError::InvalidType),
        };

        let index = parts[2]
            .parse::<usize>()
            .map_err(|_| EmbeddingIdError::InvalidIndex)?;

        let mut sub_index = if parts.len() == 4 {
            Some(
                parts[3]
                    .parse::<usize>()
                    .map_err(|_| EmbeddingIdError::InvalidIndex)?,
            )
        } else {
            None
        };

        // sub_index should only be present in witness and bare envelopes
        match embedding_type {
            EmbeddingType::WitnessEnvelope(_) => {
                if sub_index.is_none() {
                    sub_index = Some(0);
                }
            }
            EmbeddingType::BareEnvelope => {
                if sub_index.is_none() {
                    sub_index = Some(0);
                }
            }
            _ if sub_index.is_some() => return Err(EmbeddingIdError::InvalidFormat),
            _ => {}
        }

        Ok(Self {
            txid,
            embedding_type,
            index,
            sub_index,
            _private: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness,
        absolute::LockTime,
        hashes::Hash,
        script::Builder,
        taproot::{TAPROOT_ANNEX_PREFIX, TAPROOT_CONTROL_BASE_SIZE, TAPROOT_LEAF_TAPSCRIPT},
        transaction::Version,
    };

    #[test]
    fn test_embedding_to_type() {
        let op_return_loc = EmbeddingLocation::OpReturn { output: 0 };
        let annex_loc = EmbeddingLocation::TaprootAnnex { input: 1 };
        let legacy_loc = EmbeddingLocation::WitnessEnvelope {
            input: 2,
            index: 0,
            pushes: vec![4, 8],
            script_type: ScriptType::Legacy,
        };
        let tapscript_loc = EmbeddingLocation::WitnessEnvelope {
            input: 3,
            index: 0,
            pushes: vec![5, 10],
            script_type: ScriptType::Tapscript,
        };
        let bare_loc = EmbeddingLocation::BareEnvelope {
            output: 1,
            index: 0,
            pushes: vec![2, 4],
        };

        assert_eq!(op_return_loc.to_type(), EmbeddingType::OpReturn);
        assert_eq!(bare_loc.to_type(), EmbeddingType::BareEnvelope);
        assert_eq!(annex_loc.to_type(), EmbeddingType::TaprootAnnex);
        assert_eq!(
            legacy_loc.to_type(),
            EmbeddingType::WitnessEnvelope(ScriptType::Legacy)
        );
        assert_eq!(
            tapscript_loc.to_type(),
            EmbeddingType::WitnessEnvelope(ScriptType::Tapscript)
        );

        for loc in [op_return_loc, bare_loc, annex_loc, legacy_loc, tapscript_loc] {
            let embedding = Embedding {
                bytes: vec![1, 2, 3],
                txid: Txid::all_zeros(),
                location: loc.clone(),
            };

            assert_eq!(embedding.to_type(), loc.to_type());
        }
    }

    #[test]
    fn test_from_transaction_op_return() {
        // Create transaction with OP_RETURN output
        let mut tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_hex("6a48656c6c6f").unwrap(), // OP_RETURN "Hello"
            }],
        };

        let embeddings = Embedding::from_transaction(&tx);

        assert_eq!(embeddings.len(), 1);
        assert_eq!(embeddings[0].bytes, b"Hello");
        assert_eq!(embeddings[0].txid, tx.compute_txid());
        assert_eq!(
            embeddings[0].location,
            EmbeddingLocation::OpReturn { output: 0 }
        );

        // Test with multiple outputs including non-OP_RETURN
        tx.output.push(TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new(),
        });
        tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_hex("6a576f726c64").unwrap(), // OP_RETURN "World"
        });

        let embeddings = Embedding::from_transaction(&tx);

        assert_eq!(embeddings.len(), 2);
        assert_eq!(embeddings[0].bytes, b"Hello");
        assert_eq!(embeddings[0].txid, tx.compute_txid());
        assert_eq!(
            embeddings[0].location,
            EmbeddingLocation::OpReturn { output: 0 }
        );
        assert_eq!(embeddings[1].bytes, b"World");
        assert_eq!(embeddings[1].txid, tx.compute_txid());
        assert_eq!(
            embeddings[1].location,
            EmbeddingLocation::OpReturn { output: 2 }
        );
    }

    #[test]
    fn test_from_transaction_bare_envelope() {
        let mut builder = envelope::append_bytes_to_builder(b"data1", Builder::new());
        builder = envelope::append_bytes_to_builder(b"data2", builder);
        let script0 = builder.into_script();

        let builder =
            envelope::append_to_builder(vec![b"data3".to_vec(), b"data4".to_vec()], Builder::new());
        let script1 = builder.into_script();

        let tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![
                TxOut { value: Amount::from_sat(1000), script_pubkey: script0 },
                TxOut { value: Amount::from_sat(2000), script_pubkey: script1 },
            ],
        };

        let embeddings = Embedding::from_transaction(&tx);

        assert_eq!(embeddings.len(), 3);
        assert_eq!(embeddings[0].bytes, b"data1");
        assert_eq!(
            embeddings[0].location,
            EmbeddingLocation::BareEnvelope { output: 0, index: 0, pushes: vec![5] }
        );
        assert_eq!(embeddings[1].bytes, b"data2");
        assert_eq!(
            embeddings[1].location,
            EmbeddingLocation::BareEnvelope { output: 0, index: 1, pushes: vec![5] }
        );
        assert_eq!(embeddings[2].bytes, b"data3data4");
        assert_eq!(
            embeddings[2].location,
            EmbeddingLocation::BareEnvelope { output: 1, index: 0, pushes: vec![5, 5] }
        );
    }

    #[test]
    fn test_from_transaction_p2wsh_envelope() {
        // Create a transaction with p2wsh envelopes
        let mut builder = envelope::append_bytes_to_builder(b"data", Builder::new());
        builder = envelope::append_bytes_to_builder(b"data-two", builder);
        let witness0 = Witness::from_slice(&[vec![1], builder.into_bytes()]);

        let builder = envelope::append_to_builder(
            vec![b"data-three".to_vec(), b"<extension>".to_vec()],
            Builder::new(),
        );
        let witness1 = Witness::from_slice(&[vec![1], builder.into_bytes()]);

        let tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ZERO,
                    witness: witness0,
                },
                TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ZERO,
                    witness: witness1,
                },
            ],
            output: vec![],
        };

        let embeddings = Embedding::from_transaction(&tx);

        assert_eq!(embeddings.len(), 3);

        assert_eq!(embeddings[0].bytes, b"data");
        assert_eq!(embeddings[0].txid, tx.compute_txid());
        assert_eq!(
            embeddings[0].location,
            EmbeddingLocation::WitnessEnvelope {
                input: 0,
                index: 0,
                pushes: vec![4],
                script_type: ScriptType::Legacy,
            }
        );

        assert_eq!(embeddings[1].bytes, b"data-two");
        assert_eq!(embeddings[1].txid, tx.compute_txid());
        assert_eq!(
            embeddings[1].location,
            EmbeddingLocation::WitnessEnvelope {
                input: 0,
                index: 1,
                pushes: vec![8],
                script_type: ScriptType::Legacy,
            }
        );

        assert_eq!(embeddings[2].bytes, b"data-three<extension>");
        assert_eq!(embeddings[2].txid, tx.compute_txid());
        assert_eq!(
            embeddings[2].location,
            EmbeddingLocation::WitnessEnvelope {
                input: 1,
                index: 0,
                pushes: vec![10, 11],
                script_type: ScriptType::Legacy,
            }
        );
    }

    #[test]
    fn test_from_transaction_tapscript_envelope() {
        // Create transaction with a tapscript envelope
        let builder = envelope::append_bytes_to_builder(b"data", Builder::new());
        let witness = Witness::from_slice(&[
            builder.into_bytes(),
            vec![TAPROOT_LEAF_TAPSCRIPT; TAPROOT_CONTROL_BASE_SIZE],
        ]);

        let tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness,
            }],
            output: vec![],
        };

        let embeddings = Embedding::from_transaction(&tx);

        assert_eq!(embeddings.len(), 1);

        assert_eq!(embeddings[0].bytes, b"data");
        assert_eq!(embeddings[0].txid, tx.compute_txid());
        assert_eq!(
            embeddings[0].location,
            EmbeddingLocation::WitnessEnvelope {
                input: 0,
                index: 0,
                pushes: vec![4],
                script_type: ScriptType::Tapscript,
            }
        );
    }

    #[test]
    fn test_from_transaction_taproot_annex() {
        // Create transaction with an annex
        let witness0 = Witness::from_slice(&[
            vec![1],
            [
                vec![TAPROOT_ANNEX_PREFIX, TAPROOT_ANNEX_DATA_TAG],
                b"Hello".to_vec(),
            ]
            .concat(),
        ]);

        let witness1 = Witness::from_slice(&[
            vec![1],
            [
                vec![TAPROOT_ANNEX_PREFIX, TAPROOT_ANNEX_DATA_TAG],
                b"World".to_vec(),
            ]
            .concat(),
        ]);

        let tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ZERO,
                    witness: witness0,
                },
                TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ZERO,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ZERO,
                    witness: witness1,
                },
            ],
            output: vec![],
        };

        let embeddings = Embedding::from_transaction(&tx);

        assert_eq!(embeddings.len(), 2);
        assert_eq!(embeddings[0].bytes, b"Hello");
        assert_eq!(embeddings[0].txid, tx.compute_txid());
        assert_eq!(
            embeddings[0].location,
            EmbeddingLocation::TaprootAnnex { input: 0 }
        );
        assert_eq!(embeddings[1].bytes, b"World");
        assert_eq!(embeddings[1].txid, tx.compute_txid());
        assert_eq!(
            embeddings[1].location,
            EmbeddingLocation::TaprootAnnex { input: 2 }
        );
    }

    #[test]
    fn test_from_transaction_complex() {
        // 1. Create OP_RETURN outputs
        let op_return_output0 = TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_hex("6a48656c6c6f").unwrap(), // OP_RETURN "Hello"
        };

        let op_return_output1 = TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_hex("6a576f726c64").unwrap(), // OP_RETURN "World"
        };

        // 2. Create P2WSH input with envelope data
        let p2wsh_builder = envelope::append_bytes_to_builder(b"p2wsh-data", Builder::new());
        let p2wsh_witness = Witness::from_slice(&[vec![1], p2wsh_builder.into_bytes()]);

        // 3. Create Tapscript input with envelope data
        let mut tapscript_builder =
            envelope::append_bytes_to_builder(b"tapscript-data1", Builder::new());
        tapscript_builder = envelope::append_to_builder(
            vec![b"multi".to_vec(), b"part".to_vec(), b"data".to_vec()],
            tapscript_builder,
        );
        let tapscript_witness = Witness::from_slice(&[
            tapscript_builder.into_bytes(),
            vec![TAPROOT_LEAF_TAPSCRIPT; TAPROOT_CONTROL_BASE_SIZE],
        ]);

        // 4. Create Taproot Annex input
        let annex_witness = Witness::from_slice(&[
            vec![1],
            [
                vec![TAPROOT_ANNEX_PREFIX, TAPROOT_ANNEX_DATA_TAG],
                b"annex-data".to_vec(),
            ]
            .concat(),
        ]);

        // 5. Create bare envelope output
        let bare_builder = envelope::append_bytes_to_builder(b"bare-data", Builder::new());
        let bare_output =
            TxOut { value: Amount::from_sat(5000), script_pubkey: bare_builder.into_script() };

        // Create the transaction
        let tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![
                // Empty witness
                TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ZERO,
                    witness: Witness::new(),
                },
                // P2WSH input with envelope
                TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ZERO,
                    witness: p2wsh_witness,
                },
                // Tapscript input with envelopes
                TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ZERO,
                    witness: tapscript_witness,
                },
                // Taproot annex input
                TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ZERO,
                    witness: annex_witness,
                },
            ],
            output: vec![
                op_return_output0,
                TxOut {
                    value: Amount::from_sat(10000),
                    script_pubkey: ScriptBuf::new(),
                },
                op_return_output1,
                bare_output,
            ],
        };

        let embeddings = Embedding::from_transaction(&tx);

        assert_eq!(embeddings.len(), 7);

        assert_eq!(embeddings[0].bytes, b"Hello");
        assert_eq!(
            embeddings[0].location,
            EmbeddingLocation::OpReturn { output: 0 }
        );

        assert_eq!(embeddings[1].bytes, b"World");
        assert_eq!(
            embeddings[1].location,
            EmbeddingLocation::OpReturn { output: 2 }
        );

        assert_eq!(embeddings[2].bytes, b"bare-data");
        assert_eq!(
            embeddings[2].location,
            EmbeddingLocation::BareEnvelope { output: 3, index: 0, pushes: vec![9] }
        );

        assert_eq!(embeddings[3].bytes, b"p2wsh-data");
        assert_eq!(
            embeddings[3].location,
            EmbeddingLocation::WitnessEnvelope {
                input: 1,
                index: 0,
                pushes: vec![10],
                script_type: ScriptType::Legacy,
            }
        );

        assert_eq!(embeddings[4].bytes, b"tapscript-data1");
        assert_eq!(
            embeddings[4].location,
            EmbeddingLocation::WitnessEnvelope {
                input: 2,
                index: 0,
                pushes: vec![15],
                script_type: ScriptType::Tapscript,
            }
        );

        assert_eq!(embeddings[5].bytes, b"multipartdata");
        assert_eq!(
            embeddings[5].location,
            EmbeddingLocation::WitnessEnvelope {
                input: 2,
                index: 1,
                pushes: vec![5, 4, 4],
                script_type: ScriptType::Tapscript,
            }
        );

        assert_eq!(embeddings[6].bytes, b"annex-data");
        assert_eq!(
            embeddings[6].location,
            EmbeddingLocation::TaprootAnnex { input: 3 }
        );

        for embedding in &embeddings {
            assert_eq!(embedding.txid, tx.compute_txid());
        }
    }

    #[test]
    fn test_embedding_id_from_str() {
        let txid_str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        // OP_RETURN
        let op_return_id = EmbeddingId::from_str(&format!("{txid_str}:rt:2")).unwrap();
        assert_eq!(op_return_id.embedding_type, EmbeddingType::OpReturn);
        assert_eq!(op_return_id.index, 2);
        assert_eq!(op_return_id.sub_index, None);

        // Bare envelope with explicit sub_index
        let bare_id = EmbeddingId::from_str(&format!("{}:be:0:3", txid_str)).unwrap();
        assert_eq!(bare_id.embedding_type, EmbeddingType::BareEnvelope);
        assert_eq!(bare_id.index, 0);
        assert_eq!(bare_id.sub_index, Some(3));

        // Bare envelope without sub_index (defaults to 0)
        let bare_id2 = EmbeddingId::from_str(&format!("{}:be:0", txid_str)).unwrap();
        assert_eq!(bare_id2.embedding_type, EmbeddingType::BareEnvelope);
        assert_eq!(bare_id2.index, 0);
        assert_eq!(bare_id2.sub_index, Some(0));

        // TaprootAnnex
        let annex_id = EmbeddingId::from_str(&format!("{txid_str}:ta:1")).unwrap();
        assert_eq!(annex_id.embedding_type, EmbeddingType::TaprootAnnex);
        assert_eq!(annex_id.index, 1);
        assert_eq!(annex_id.sub_index, None);

        // Legacy envelope with explicit sub_index
        let legacy_id = EmbeddingId::from_str(&format!("{txid_str}:le:0:3")).unwrap();
        assert_eq!(
            legacy_id.embedding_type,
            EmbeddingType::WitnessEnvelope(ScriptType::Legacy)
        );
        assert_eq!(legacy_id.index, 0);
        assert_eq!(legacy_id.sub_index, Some(3));

        // Legacy envelope without sub_index (defaults to 0)
        let legacy_id2 = EmbeddingId::from_str(&format!("{txid_str}:le:0")).unwrap();
        assert_eq!(
            legacy_id2.embedding_type,
            EmbeddingType::WitnessEnvelope(ScriptType::Legacy)
        );
        assert_eq!(legacy_id2.index, 0);
        assert_eq!(legacy_id2.sub_index, Some(0));

        // Tapscript envelope with explicit sub_index
        let tapscript_id = EmbeddingId::from_str(&format!("{txid_str}:te:2:1")).unwrap();
        assert_eq!(
            tapscript_id.embedding_type,
            EmbeddingType::WitnessEnvelope(ScriptType::Tapscript)
        );
        assert_eq!(tapscript_id.index, 2);
        assert_eq!(tapscript_id.sub_index, Some(1));
    }

    #[test]
    fn test_embedding_id_to_string() {
        let txid = Txid::all_zeros();

        // OP_RETURN id
        let op_return_id = EmbeddingId {
            txid,
            embedding_type: EmbeddingType::OpReturn,
            index: 2,
            sub_index: None,
            _private: false,
        };

        // Bare envelope id
        let bare_id = EmbeddingId {
            txid,
            embedding_type: EmbeddingType::BareEnvelope,
            index: 0,
            sub_index: Some(3),
            _private: false,
        };

        // Bare envelope id with index 0
        let bare_id2 = EmbeddingId {
            txid,
            embedding_type: EmbeddingType::BareEnvelope,
            index: 2,
            sub_index: Some(0),
            _private: false,
        };

        // TaprootAnnex id
        let annex_id = EmbeddingId {
            txid,
            embedding_type: EmbeddingType::TaprootAnnex,
            index: 1,
            sub_index: None,
            _private: false,
        };

        // Legacy envelope id
        let legacy_id = EmbeddingId {
            txid,
            embedding_type: EmbeddingType::WitnessEnvelope(ScriptType::Legacy),
            index: 0,
            sub_index: Some(3),
            _private: false,
        };

        // Tapscript envelope id with index 0 (should not show sub_index)
        let tapscript_id = EmbeddingId {
            txid,
            embedding_type: EmbeddingType::WitnessEnvelope(ScriptType::Tapscript),
            index: 2,
            sub_index: Some(0),
            _private: false,
        };

        let txid_str = txid.to_string();

        assert_eq!(op_return_id.to_string(), format!("{}:rt:2", txid_str));
        assert_eq!(bare_id.to_string(), format!("{}:be:0:3", txid_str));
        assert_eq!(bare_id2.to_string(), format!("{}:be:2", txid_str));
        assert_eq!(annex_id.to_string(), format!("{}:ta:1", txid_str));
        assert_eq!(legacy_id.to_string(), format!("{}:le:0:3", txid_str));
        assert_eq!(tapscript_id.to_string(), format!("{}:te:2", txid_str));
    }

    #[test]
    fn test_embedding_id_invalid_parsing() {
        let txid_str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        // Too few parts
        let err = EmbeddingId::from_str(txid_str).unwrap_err();
        assert_eq!(err, EmbeddingIdError::InvalidFormat);

        // Too many parts
        let err = EmbeddingId::from_str(&format!("{txid_str}:rt:2:3:extra")).unwrap_err();
        assert_eq!(err, EmbeddingIdError::InvalidFormat);

        // Invalid txid
        let err = EmbeddingId::from_str("invalid:rt:2").unwrap_err();
        assert_eq!(err, EmbeddingIdError::InvalidTxid);

        // Invalid type
        let err = EmbeddingId::from_str(&format!("{txid_str}:invalid:2")).unwrap_err();
        assert_eq!(err, EmbeddingIdError::InvalidType);

        // Invalid index (not a number)
        let err = EmbeddingId::from_str(&format!("{txid_str}:rt:abc")).unwrap_err();
        assert_eq!(err, EmbeddingIdError::InvalidIndex);

        // Invalid sub_index (not a number)
        let err = EmbeddingId::from_str(&format!("{txid_str}:te:2:abc")).unwrap_err();
        assert_eq!(err, EmbeddingIdError::InvalidIndex);

        // Sub_index not allowed for OP_RETURN
        let err = EmbeddingId::from_str(&format!("{txid_str}:rt:2:1")).unwrap_err();
        assert_eq!(err, EmbeddingIdError::InvalidFormat);

        // Sub_index not allowed for TaprootAnnex
        let err = EmbeddingId::from_str(&format!("{txid_str}:ta:1:2")).unwrap_err();
        assert_eq!(err, EmbeddingIdError::InvalidFormat);
    }

    #[test]
    fn test_embedding_id_from_embedding() {
        let txid = Txid::all_zeros();

        // OP_RETURN embedding
        let op_return_embedding = Embedding {
            bytes: vec![1, 2, 3],
            txid,
            location: EmbeddingLocation::OpReturn { output: 2 },
        };

        let op_return_id = op_return_embedding.id();
        assert_eq!(op_return_id.txid, txid);
        assert_eq!(op_return_id.embedding_type, EmbeddingType::OpReturn);
        assert_eq!(op_return_id.index, 2);
        assert_eq!(op_return_id.sub_index, None);

        // BareEnvelope embedding
        let bare_embedding = Embedding {
            bytes: vec![1, 2, 3],
            txid,
            location: EmbeddingLocation::BareEnvelope { output: 0, index: 1, pushes: vec![] },
        };
        let bare_id = bare_embedding.id();
        assert_eq!(bare_id.txid, txid);
        assert_eq!(bare_id.embedding_type, EmbeddingType::BareEnvelope);
        assert_eq!(bare_id.index, 0);
        assert_eq!(bare_id.sub_index, Some(1));

        // TaprootAnnex embedding
        let annex_embedding = Embedding {
            bytes: vec![4, 5, 6],
            txid,
            location: EmbeddingLocation::TaprootAnnex { input: 1 },
        };

        let annex_id = annex_embedding.id();
        assert_eq!(annex_id.txid, txid);
        assert_eq!(annex_id.embedding_type, EmbeddingType::TaprootAnnex);
        assert_eq!(annex_id.index, 1);
        assert_eq!(annex_id.sub_index, None);

        // WitnessEnvelope (Legacy) with index 0 (no sub_index)
        let legacy_embedding0 = Embedding {
            bytes: vec![7, 8, 9],
            txid,
            location: EmbeddingLocation::WitnessEnvelope {
                input: 3,
                index: 0,
                pushes: vec![3],
                script_type: ScriptType::Legacy,
            },
        };

        let legacy_id0 = legacy_embedding0.id();
        assert_eq!(legacy_id0.txid, txid);
        assert_eq!(
            legacy_id0.embedding_type,
            EmbeddingType::WitnessEnvelope(ScriptType::Legacy)
        );
        assert_eq!(legacy_id0.index, 3);
        assert_eq!(legacy_id0.sub_index, Some(0));

        // WitnessEnvelope (Legacy) with index > 0 (has sub_index)
        let legacy_embedding1 = Embedding {
            bytes: vec![7, 8, 9],
            txid,
            location: EmbeddingLocation::WitnessEnvelope {
                input: 3,
                index: 2,
                pushes: vec![3],
                script_type: ScriptType::Legacy,
            },
        };

        let legacy_id1 = legacy_embedding1.id();
        assert_eq!(legacy_id1.txid, txid);
        assert_eq!(
            legacy_id1.embedding_type,
            EmbeddingType::WitnessEnvelope(ScriptType::Legacy)
        );
        assert_eq!(legacy_id1.index, 3);
        assert_eq!(legacy_id1.sub_index, Some(2));

        // WitnessEnvelope (Tapscript)
        let tapscript_embedding = Embedding {
            bytes: vec![10, 11, 12],
            txid,
            location: EmbeddingLocation::WitnessEnvelope {
                input: 4,
                index: 1,
                pushes: vec![3],
                script_type: ScriptType::Tapscript,
            },
        };

        let tapscript_id = tapscript_embedding.id();
        assert_eq!(tapscript_id.txid, txid);
        assert_eq!(
            tapscript_id.embedding_type,
            EmbeddingType::WitnessEnvelope(ScriptType::Tapscript)
        );
        assert_eq!(tapscript_id.index, 4);
        assert_eq!(tapscript_id.sub_index, Some(1));
    }

    #[test]
    fn test_embedding_id_roundtrip() {
        let txid = Txid::all_zeros();

        // OP_RETURN id
        let op_return_id = EmbeddingId {
            txid,
            embedding_type: EmbeddingType::OpReturn,
            index: 2,
            sub_index: None,
            _private: false,
        };

        let op_return_str = op_return_id.to_string();
        let op_return_id2 = EmbeddingId::from_str(&op_return_str).unwrap();
        assert_eq!(op_return_id.txid, op_return_id2.txid);
        assert_eq!(op_return_id.embedding_type, op_return_id2.embedding_type);
        assert_eq!(op_return_id.index, op_return_id2.index);
        assert_eq!(op_return_id.sub_index, op_return_id2.sub_index);

        // Bare Envelope id
        let bare_id = EmbeddingId {
            txid,
            embedding_type: EmbeddingType::BareEnvelope,
            index: 0,
            sub_index: Some(3),
            _private: false,
        };

        let bare_str = bare_id.to_string();
        let bare_id2 = EmbeddingId::from_str(&bare_str).unwrap();
        assert_eq!(bare_id.txid, bare_id2.txid);
        assert_eq!(bare_id.embedding_type, bare_id2.embedding_type);
        assert_eq!(bare_id.index, bare_id2.index);
        assert_eq!(bare_id.sub_index, bare_id2.sub_index);

        // TaprootAnnex id
        let annex_id = EmbeddingId {
            txid,
            embedding_type: EmbeddingType::TaprootAnnex,
            index: 1,
            sub_index: None,
            _private: false,
        };

        let annex_str = annex_id.to_string();
        let annex_id2 = EmbeddingId::from_str(&annex_str).unwrap();
        assert_eq!(annex_id.txid, annex_id2.txid);
        assert_eq!(annex_id.embedding_type, annex_id2.embedding_type);
        assert_eq!(annex_id.index, annex_id2.index);
        assert_eq!(annex_id.sub_index, annex_id2.sub_index);

        // Legacy envelope id
        let legacy_id = EmbeddingId {
            txid,
            embedding_type: EmbeddingType::WitnessEnvelope(ScriptType::Legacy),
            index: 0,
            sub_index: Some(3),
            _private: false,
        };

        let legacy_str = legacy_id.to_string();
        let legacy_id2 = EmbeddingId::from_str(&legacy_str).unwrap();
        assert_eq!(legacy_id.txid, legacy_id2.txid);
        assert_eq!(legacy_id.embedding_type, legacy_id2.embedding_type);
        assert_eq!(legacy_id.index, legacy_id2.index);
        assert_eq!(legacy_id.sub_index, legacy_id2.sub_index);

        // Tapscript envelope id
        let tapscript_id = EmbeddingId {
            txid,
            embedding_type: EmbeddingType::WitnessEnvelope(ScriptType::Tapscript),
            index: 2,
            sub_index: Some(0),
            _private: false,
        };

        let tapscript_str = tapscript_id.to_string();
        let tapscript_id2 = EmbeddingId::from_str(&tapscript_str).unwrap();
        assert_eq!(tapscript_id.txid, tapscript_id2.txid);
        assert_eq!(tapscript_id.embedding_type, tapscript_id2.embedding_type);
        assert_eq!(tapscript_id.index, tapscript_id2.index);
        assert_eq!(Some(0), tapscript_id2.sub_index);
    }
}