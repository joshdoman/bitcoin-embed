# bitcoin-embed

A library for embedding arbitrary data and TLV-encoded messages in Bitcoin transactions. Supports OP_RETURN outputs, witness script envelopes, and taproot annexes.

## Installation

```toml
[dependencies]
bitcoin-embed = "0.1.0"
```

## Features

- **Embedding Extraction**: Extract data from Bitcoin transactions with detailed location information. Supports:
  - `OP_RETURN` outputs
  - Taproot annexes
  - `OP_FALSE OP_IF ... OP_ENDIF` witness envelopes (supports P2TR and P2WSH)
  - Bare output script envelopes
  
  *Note: P2WSH envelopes require an input with at least 2 witness elements*

- **TLV Message Encoding**: Efficiently encode and decode a series of tagged messages

- **Script Embedding**: Embed arbitrary data in Bitcoin script using an `OP_FALSE OP_IF ... OP_ENDIF` script envelope

## Message Encoding Scheme

The library implements an efficient binary encoding scheme for tagged messages:

- **Space-Efficient**: Tags and message lengths are encoded as LEB128 variable-length integers to minimize bytes
- **Tag Deduplication**: Repeated consecutive tags use a special marker (0) instead of repeating the full tag
- **Explicit Termination**: The initial LEB128 integer represents `2 * tag + (1 if terminal tag else 0)` to efficiently encode the tag and indicate termination
- **Compact Format**: The final message doesn't include an explicit length, saving bytes

This encoding scheme is valuable for embedding data in Bitcoin transactions where multiple messages must be encoded in the same location. It allows for up to $2^{127}-1$ unique tags while minimizing the overhead needed to encode.

## Basic Usage

### Embedding Data

```rust
use bitcoin::{Transaction, script::Builder};
use bitcoin_embed::envelope;

// Create an envelope with data
let builder = Builder::new();
let builder_with_data = envelope::append_bytes_to_builder(b"Hello, Bitcoin!", builder);
```

### Extracting Embedded Data

```rust
use bitcoin_embed::Embedding;

// Extract all embedded data from a transaction
let tx = /* A Transaction object */;
let embeddings = Embedding::from_transaction(&tx);

for embed in embeddings {
    match embed.location {
        // Handle OP_RETURN data
        EmbeddingLocation::OpReturn { output } => {
            println!("Found OP_RETURN data at output {}: {:?}", output, embed.bytes);
        },
        
        // Handle taproot annex data
        EmbeddingLocation::TaprootAnnex { input } => {
            println!("Found taproot annex data at input {}: {:?}", input, embed.bytes);
        },
        
        // Handle witness envelope data (P2WSH or Tapscript)
        EmbeddingLocation::WitnessEnvelope { input, index, script_type, .. } => {
            println!("Found witness envelope data at input {} (index {}): {:?}", 
                     input, index, embed.bytes);
            println!("Script type: {:?}", script_type);
        }

        // Handle bare output envelope data
        EmbeddingLocation::BareEnvelope { output, index, .. } => {
            println!("Found bare envelope data at output {} (index {}): {:?}", 
                     input, index, embed.bytes);
        }
    }
}
```

### Working with Tagged Messages

```rust
use bitcoin_embed::message::Message;

// Create a message with a tag and data
let msg = Message::new(42, b"Tagged data".to_vec()).unwrap();

// Encode multiple messages
let msg2 = /** A second message */
let encoded = Message::encode(vec![msg, msg2]);

// Decode messages from bytes
let decoded = Message::decode(&encoded).unwrap();
```

## License
This project is licensed under the CC0-1.0 License.

## Author
Joshua Doman <joshsdoman@gmail.com>