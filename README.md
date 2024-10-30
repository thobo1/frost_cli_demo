# FROST Threshold Signature CLI

This project is a CLI-based application that generates public and private keys, shares secret keys, and signs messages using the FROST (Flexible Round-Optimized Schnorr Threshold Signatures) protocol. FROST is a threshold signature scheme that enables secure distributed key generation and signing. This CLI tool allows you to configure participant and threshold parameters to create signatures that require a subset of participants to sign a message successfully.

## Features

- Generate threshold keypairs (group public key and individual participant keys)
- Support for signing messages with threshold participants
- Threshold signature verification
- Saving of public keys, private keys, and signatures to files

## Requirements

- Rust programming language installed (version 1.56 or later is recommended)
- Dependencies managed with [Cargo](https://doc.rust-lang.org/cargo/)

### Key Dependencies

- `frost-dalek`: Provides the core FROST protocol functionality.
- `rand`: Used for generating random values for cryptographic operations.
- `clap`: Command-line argument parser for Rust.

## Installation

Clone this repository, navigate to the project directory, and install the dependencies.

```bash
git clone https://github.com/username/frost-cli-demo.git
cd frost-cli-demo
cargo build --release
```

## Usage

### Step 1: Generating Keypairs

To run the program, use the following command:

```bash
cargo run -- <message> [--output-key <output_key>] [--output-signature <output_signature>] [--participants <number_of_participants>] [--threshold <threshold>]
```

## Arguments

- `<message>`: The message to be signed.
- `--output-key <output_key>`: Output file for the group public key (default: `public_key.txt`).
- `--output-signature <output_signature>`: Output file for the signature (default: `signature.txt`).
- `--participants <number_of_participants>`: Total number of participants in the threshold scheme (minimum 3, default: 3).
- `--threshold <threshold>`: Number of participants required for a successful signature (default: 2).

## Examples

To sign a message with 5 participants and a threshold of 3:

```bash
cargo run -- "My secret message" --participants 5 --threshold 3
```
