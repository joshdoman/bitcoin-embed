// Based on ordinals/inscriptions/envelope.rs

use {
    bitcoin::{
        Script,
        blockdata::{
            constants::MAX_SCRIPT_ELEMENT_SIZE,
            opcodes,
            script::{
                Instruction::{self, Op, PushBytes},
                Instructions,
            },
        },
        script::{Builder, Error, PushBytes as ScriptPushBytes},
    },
    std::iter::Peekable,
};

type Result<T> = std::result::Result<T, Error>;
pub type Envelope = Vec<Vec<u8>>;

/// Adds envelope to a Bitcoin script using the envelope pattern (OP_FALSE OP_IF ... OP_ENDIF)
pub fn append_to_builder(envelope: Envelope, mut builder: Builder) -> Builder {
    builder = builder
        .push_opcode(opcodes::OP_FALSE)
        .push_opcode(opcodes::all::OP_IF);

    for bytes in envelope {
        for chunk in bytes.chunks(MAX_SCRIPT_ELEMENT_SIZE) {
            builder = builder.push_slice::<&ScriptPushBytes>(chunk.try_into().unwrap());
        }
    }

    builder.push_opcode(opcodes::all::OP_ENDIF)
}

/// Adds bytes to a Bitcoin script using the envelope pattern (OP_FALSE OP_IF ... OP_ENDIF)
pub fn append_bytes_to_builder(bytes: &[u8], builder: Builder) -> Builder {
    append_to_builder(vec![bytes.to_vec()], builder)
}

/// Extracts envelopes from Bitcoin script
pub fn from_script(script: &Script) -> Vec<Envelope> {
    let mut envelopes = Vec::new();

    let mut instructions = script.instructions().peekable();

    while let Ok(Some(instruction)) = instructions.next().transpose() {
        if instruction == PushBytes((&[]).into()) {
            if let Ok(Some(envelope)) = from_instructions(&mut instructions) {
                envelopes.push(envelope);
            }
        }
    }

    envelopes
}

fn accept(instructions: &mut Peekable<Instructions>, instruction: Instruction) -> Result<bool> {
    if instructions.peek() == Some(&Ok(instruction)) {
        instructions.next().transpose()?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn from_instructions(instructions: &mut Peekable<Instructions>) -> Result<Option<Envelope>> {
    if !accept(instructions, Op(opcodes::all::OP_IF))? {
        return Ok(None);
    }

    let mut payload = Vec::new();

    loop {
        match instructions.next().transpose()? {
            None => return Ok(None),
            Some(Op(opcodes::all::OP_ENDIF)) => {
                return Ok(Some(payload));
            }
            Some(Op(opcodes::all::OP_PUSHNUM_NEG1)) => {
                payload.push(vec![0x81]);
            }
            Some(Op(opcodes::all::OP_PUSHNUM_1)) => {
                payload.push(vec![1]);
            }
            Some(Op(opcodes::all::OP_PUSHNUM_2)) => {
                payload.push(vec![2]);
            }
            Some(Op(opcodes::all::OP_PUSHNUM_3)) => {
                payload.push(vec![3]);
            }
            Some(Op(opcodes::all::OP_PUSHNUM_4)) => {
                payload.push(vec![4]);
            }
            Some(Op(opcodes::all::OP_PUSHNUM_5)) => {
                payload.push(vec![5]);
            }
            Some(Op(opcodes::all::OP_PUSHNUM_6)) => {
                payload.push(vec![6]);
            }
            Some(Op(opcodes::all::OP_PUSHNUM_7)) => {
                payload.push(vec![7]);
            }
            Some(Op(opcodes::all::OP_PUSHNUM_8)) => {
                payload.push(vec![8]);
            }
            Some(Op(opcodes::all::OP_PUSHNUM_9)) => {
                payload.push(vec![9]);
            }
            Some(Op(opcodes::all::OP_PUSHNUM_10)) => {
                payload.push(vec![10]);
            }
            Some(Op(opcodes::all::OP_PUSHNUM_11)) => {
                payload.push(vec![11]);
            }
            Some(Op(opcodes::all::OP_PUSHNUM_12)) => {
                payload.push(vec![12]);
            }
            Some(Op(opcodes::all::OP_PUSHNUM_13)) => {
                payload.push(vec![13]);
            }
            Some(Op(opcodes::all::OP_PUSHNUM_14)) => {
                payload.push(vec![14]);
            }
            Some(Op(opcodes::all::OP_PUSHNUM_15)) => {
                payload.push(vec![15]);
            }
            Some(Op(opcodes::all::OP_PUSHNUM_16)) => {
                payload.push(vec![16]);
            }
            Some(PushBytes(push)) => {
                payload.push(push.as_bytes().to_vec());
            }
            Some(_) => return Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_script() {
        let script = Script::new();
        assert_eq!(from_script(&script), Vec::<Envelope>::new());
    }

    #[test]
    fn test_script_without_envelopes() {
        let script = Builder::new()
            .push_opcode(opcodes::OP_FALSE)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();

        assert_eq!(from_script(&script), Vec::<Envelope>::new());
    }

    #[test]
    fn test_single_empty_envelope() {
        let script = Builder::new()
            .push_opcode(opcodes::OP_FALSE)
            .push_opcode(opcodes::all::OP_IF)
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script();

        assert_eq!(from_script(&script), vec![Vec::<Vec<u8>>::new()]);
    }

    #[test]
    fn test_envelope_with_single_push() {
        let data = b"test data";

        let script = Builder::new()
            .push_opcode(opcodes::OP_FALSE)
            .push_opcode(opcodes::all::OP_IF)
            .push_slice(data)
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script();

        assert_eq!(from_script(&script), vec![vec![data.to_vec()]]);
    }

    #[test]
    fn test_envelope_with_multiple_pushes() {
        let data1 = b"first";
        let data2 = b"second";

        let script = Builder::new()
            .push_opcode(opcodes::OP_FALSE)
            .push_opcode(opcodes::all::OP_IF)
            .push_slice(data1)
            .push_slice(data2)
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script();

        assert_eq!(
            from_script(&script),
            vec![vec![data1.to_vec(), data2.to_vec()]]
        );
    }

    #[test]
    fn test_multiple_envelopes() {
        let data1 = b"envelope1";
        let data2 = b"envelope2";

        let mut builder = Builder::new();

        builder = builder
            // First envelope
            .push_opcode(opcodes::OP_FALSE)
            .push_opcode(opcodes::all::OP_IF)
            .push_slice(data1)
            .push_opcode(opcodes::all::OP_ENDIF)
            // Second envelope
            .push_opcode(opcodes::OP_FALSE)
            .push_opcode(opcodes::all::OP_IF)
            .push_slice(data2)
            .push_opcode(opcodes::all::OP_ENDIF);

        let script = builder.into_script();

        assert_eq!(
            from_script(&script),
            vec![vec![data1.to_vec()], vec![data2.to_vec()]]
        );
    }

    #[test]
    fn test_pushnum_opcodes() {
        let pushnums = [
            (opcodes::all::OP_PUSHNUM_NEG1, vec![0x81]),
            (opcodes::all::OP_PUSHNUM_1, vec![1]),
            (opcodes::all::OP_PUSHNUM_2, vec![2]),
            (opcodes::all::OP_PUSHNUM_16, vec![16]),
        ];

        for (opcode, expected) in pushnums {
            let script = Builder::new()
                .push_opcode(opcodes::OP_FALSE)
                .push_opcode(opcodes::all::OP_IF)
                .push_opcode(opcode)
                .push_opcode(opcodes::all::OP_ENDIF)
                .into_script();

            assert_eq!(from_script(&script), vec![vec![expected]]);
        }
    }

    #[test]
    fn test_large_data_chunking() {
        let large_data = vec![0xaa; 100_000];

        let builder = Builder::new();
        let builder = append_bytes_to_builder(&large_data, builder);
        let script = builder.into_script();

        let extracted = from_script(&script);
        assert_eq!(extracted.len(), 1);

        let flattened: Vec<u8> = extracted[0].iter().flatten().cloned().collect();
        assert_eq!(flattened, large_data);
    }

    #[test]
    fn test_append_to_builder() {
        let envelope = vec![vec![1, 2, 3], vec![4, 5, 6]];

        let builder = Builder::new();
        let builder = append_to_builder(envelope.clone(), builder);
        let script = builder.into_script();

        assert_eq!(from_script(&script), vec![envelope]);
    }

    #[test]
    fn test_append_bytes_to_builder() {
        let data = b"test data";

        let builder = Builder::new();
        let builder = append_bytes_to_builder(data, builder);
        let script = builder.into_script();

        assert_eq!(from_script(&script), vec![vec![data.to_vec()]]);
    }

    #[test]
    fn test_nested_invalid_instructions() {
        let script = Builder::new()
            .push_opcode(opcodes::OP_FALSE)
            .push_opcode(opcodes::all::OP_IF)
            .push_slice(&[0x01]) // Valid push
            .push_opcode(opcodes::all::OP_IF) // Invalid opcode
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script();

        assert_eq!(from_script(&script), Vec::<Envelope>::new());
    }

    #[test]
    fn test_incomplete_envelope() {
        let script = Builder::new()
            .push_opcode(opcodes::OP_FALSE)
            .push_opcode(opcodes::all::OP_IF)
            .push_slice(b"data")
            // Missing OP_ENDIF
            .into_script();

        assert_eq!(from_script(&script), Vec::<Envelope>::new());
    }

    #[test]
    fn test_surrounding_opcodes() {
        let data = b"test data";

        let script = Builder::new()
            .push_opcode(opcodes::all::OP_DUP)
            .push_opcode(opcodes::OP_FALSE)
            .push_opcode(opcodes::all::OP_IF)
            .push_slice(data)
            .push_opcode(opcodes::all::OP_ENDIF)
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .into_script();

        assert_eq!(from_script(&script), vec![vec![data.to_vec()]]);
    }

    #[test]
    fn test_roundtrip() {
        let original_data = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];

        let builder = Builder::new();
        let builder = append_to_builder(original_data.clone(), builder);
        let script = builder.into_script();

        let extracted = from_script(&script);
        assert_eq!(extracted, vec![original_data]);
    }
}
