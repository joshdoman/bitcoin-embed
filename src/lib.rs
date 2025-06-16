//! # Bitcoin Embed
//!
//! This library supports embedding arbitrary data and TLV-encoded messages in Bitcoin transactions. Supports
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

pub mod envelope;
pub mod message;
pub mod varint;

/// The initial byte in a data-carrying taproot annex
pub const TAPROOT_ANNEX_DATA_TAG: u8 = 0;

/// The script type used by an envelope
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ScriptType {
    /// Legacy script (P2WSH)
    Legacy,
    /// Tapscript
    Tapscript,
}

/// The type of location where data may exist in a transaction
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EmbeddingType {
    /// An `OP_RETURN`
    OpReturn,
    /// A taproot annex
    TaprootAnnex,
    /// An `OP_FALSE OP_IF <DATA> OP_ENDIF` envelope
    WitnessEnvelope(ScriptType),
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

    /// An `OP_FALSE OP_IF <DATA> OP_ENDIF` envelope with the input index, envelope index, and data push sizes
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
}

impl EmbeddingLocation {
    /// Returns the embedding type
    pub fn to_type(&self) -> EmbeddingType {
        match self {
            EmbeddingLocation::OpReturn { .. } => EmbeddingType::OpReturn,
            EmbeddingLocation::TaprootAnnex { .. } => EmbeddingType::TaprootAnnex,
            EmbeddingLocation::WitnessEnvelope { script_type, .. } => {
                EmbeddingType::WitnessEnvelope(*script_type)
            }
        }
    }
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
    /// Returns the embedding type
    pub fn to_type(&self) -> EmbeddingType {
        self.location.to_type()
    }

    /// Extracts the tape in a transaction
    pub fn from_transaction(tx: &Transaction) -> Vec<Self> {
        let mut embeddings = Vec::new();
        let txid = tx.compute_txid();

        // OP_RETURN
        for (output, txout) in tx.output.iter().enumerate() {
            if !txout.script_pubkey.is_op_return() {
                continue;
            }

            let location = EmbeddingLocation::OpReturn { output };

            embeddings.push(Self {
                bytes: txout.script_pubkey.to_bytes()[1..].to_vec(),
                txid,
                location,
            });
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
            EmbeddingType::TaprootAnnex => write!(f, "Taproot Annex"),
            EmbeddingType::WitnessEnvelope(script_type) => write!(f, "{} Envelope", script_type),
        }
    }
}

impl fmt::Display for EmbeddingLocation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EmbeddingLocation::OpReturn { output } => {
                write!(f, "OP_RETURN at output {}", output)
            }
            EmbeddingLocation::TaprootAnnex { input } => {
                write!(f, "Taproot Annex at input {}", input)
            }
            EmbeddingLocation::WitnessEnvelope {
                input,
                index,
                script_type,
                ..
            } => {
                write!(
                    f,
                    "{} Envelope at input {} (index {})",
                    script_type, input, index
                )
            }
        }
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

        assert_eq!(op_return_loc.to_type(), EmbeddingType::OpReturn);
        assert_eq!(annex_loc.to_type(), EmbeddingType::TaprootAnnex);
        assert_eq!(
            legacy_loc.to_type(),
            EmbeddingType::WitnessEnvelope(ScriptType::Legacy)
        );
        assert_eq!(
            tapscript_loc.to_type(),
            EmbeddingType::WitnessEnvelope(ScriptType::Tapscript)
        );

        for loc in [op_return_loc, annex_loc, legacy_loc, tapscript_loc] {
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
            ],
        };

        let embeddings = Embedding::from_transaction(&tx);

        assert_eq!(embeddings.len(), 6);

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

        assert_eq!(embeddings[2].bytes, b"p2wsh-data");
        assert_eq!(embeddings[2].txid, tx.compute_txid());
        assert_eq!(
            embeddings[2].location,
            EmbeddingLocation::WitnessEnvelope {
                input: 1,
                index: 0,
                pushes: vec![10],
                script_type: ScriptType::Legacy,
            }
        );

        assert_eq!(embeddings[3].bytes, b"tapscript-data1");
        assert_eq!(embeddings[3].txid, tx.compute_txid());
        assert_eq!(
            embeddings[3].location,
            EmbeddingLocation::WitnessEnvelope {
                input: 2,
                index: 0,
                pushes: vec![15],
                script_type: ScriptType::Tapscript,
            }
        );

        assert_eq!(embeddings[4].bytes, b"multipartdata");
        assert_eq!(embeddings[4].txid, tx.compute_txid());
        assert_eq!(
            embeddings[4].location,
            EmbeddingLocation::WitnessEnvelope {
                input: 2,
                index: 1,
                pushes: vec![5, 4, 4],
                script_type: ScriptType::Tapscript,
            }
        );

        assert_eq!(embeddings[5].bytes, b"annex-data");
        assert_eq!(embeddings[5].txid, tx.compute_txid());
        assert_eq!(
            embeddings[5].location,
            EmbeddingLocation::TaprootAnnex { input: 3 }
        );

        for embedding in &embeddings {
            assert_eq!(embedding.txid, tx.compute_txid());
        }
    }
}
