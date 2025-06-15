use bitcoin::{Script, Transaction, Txid, taproot::LeafVersion};

pub mod envelope;
mod tagged_data;
mod varint;

pub use tagged_data::{Error, Tag, TaggedData};

/// A location where data may exist in a transaction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapeLocation {
    /// An `OP_RETURN`
    OpReturn { output: usize, index: usize },
    /// A taproot annex
    TaprootAnnex { input: usize, index: usize },
    /// An `OP_FALSE OP_IF <DATA> OP_ENDIF`
    WitnessEnvelope {
        input: usize,
        index: usize,
        pushes: Vec<usize>,
    },
}

/// Represents data in a transaction that may or may not conform to TLV encoding
#[derive(Debug, Clone, PartialEq)]
pub enum TapeData {
    /// Tagged data that successfully parsed with a valid tag and bytes.
    Tagged(TaggedData),
    /// Raw data that could not be parsed as valid TaggedData
    Raw(Vec<u8>),
}

/// A struct containing data and its location in a transaction
#[derive(Debug, Clone, PartialEq)]
pub struct Tape {
    /// The data
    pub data: TapeData,
    /// The transaction ID
    pub txid: Txid,
    /// The location in the transaction
    pub location: TapeLocation,
}

impl Tape {
    /// Attempts to get the tagged data if a tag exists.
    pub fn as_tagged(&self) -> Option<TaggedData> {
        match &self.data {
            TapeData::Tagged(data) => Some(data.clone()),
            TapeData::Raw(_) => None,
        }
    }

    /// Extracts the tape in a transaction
    pub fn from_transaction(tx: &Transaction) -> Vec<Self> {
        let mut tape = Vec::new();
        let txid = tx.compute_txid();

        // OP_RETURN
        for (i, txout) in tx.output.iter().enumerate() {
            if !txout.script_pubkey.is_op_return() {
                continue;
            }

            let bytes = &txout.script_pubkey.to_bytes()[1..];

            if let Ok(items) = TaggedData::decode(bytes) {
                for (k, data) in items.into_iter().enumerate() {
                    let location = TapeLocation::OpReturn {
                        output: i,
                        index: k,
                    };

                    tape.push(Tape {
                        data: TapeData::Tagged(data),
                        txid,
                        location,
                    });
                }
            } else {
                let location = TapeLocation::OpReturn {
                    output: i,
                    index: 0,
                };

                tape.push(Tape {
                    data: TapeData::Raw(bytes.to_vec()),
                    txid,
                    location,
                });
            }
        }

        // Witness Envelope
        for (i, txin) in tx.input.iter().enumerate() {
            let mut script = Script::new();

            if let Some(witness_script) = txin.witness.witness_script() {
                // Ensure last element isn't an annex
                if txin.witness.taproot_annex().is_none() {
                    script = witness_script;
                }
            } else if let Some(leaf_script) = txin.witness.taproot_leaf_script() {
                if leaf_script.version == LeafVersion::TapScript {
                    script = leaf_script.script;
                }
            }

            let envelopes = envelope::from_script(script);

            for (k, envelope) in envelopes.into_iter().enumerate() {
                let mut bytes = Vec::new();
                let mut pushes = Vec::new();

                for chunk in envelope {
                    bytes.extend(chunk.clone());
                    pushes.push(chunk.len());
                }

                let location = TapeLocation::WitnessEnvelope {
                    input: i,
                    index: k,
                    pushes,
                };

                if let Ok(data) = TaggedData::decode_without_length(&bytes) {
                    tape.push(Tape {
                        data: TapeData::Tagged(data),
                        txid,
                        location,
                    });
                } else {
                    tape.push(Tape {
                        data: TapeData::Raw(bytes.to_vec()),
                        txid,
                        location,
                    });
                }
            }
        }

        // Annex
        for (i, txin) in tx.input.iter().enumerate() {
            if let Some(annex) = txin.witness.taproot_annex() {
                if annex.len() > 2 && annex[1] == 0 {
                    let bytes = &annex[2..];
                    if let Ok(items) = TaggedData::decode(bytes) {
                        for (k, data) in items.into_iter().enumerate() {
                            let location = TapeLocation::TaprootAnnex { input: i, index: k };

                            tape.push(Tape {
                                data: TapeData::Tagged(data),
                                txid,
                                location,
                            });
                        }
                    } else {
                        let location = TapeLocation::TaprootAnnex { input: i, index: 0 };

                        tape.push(Tape {
                            data: TapeData::Raw(bytes.to_vec()),
                            txid,
                            location,
                        });
                    }
                }
            }
        }

        tape
    }
}
