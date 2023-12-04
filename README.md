# Optrand-PVSS

A library implementing the [Optrand](https://eprint.iacr.org/2022/193.pdf)-based publicly verifiable secret sharing (PVSS) scheme forming the core cryptographic component of the upcoming GRandLine Distributed Randomness Beacon Protocol. Written purely in Rust, this crate harnesses the power of real-world Crypto such as the [Arkworks](https://github.com/arkworks-rs) ecosystem for elliptic curve arithmetic and [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek) from the dalek cryptography suite for efficiently signing and verifying NIZK proofs. While the library is designed with the BLS12-381 curve in mind, its core components are implemented in a generic manner to enable experimentation with other curves as well.

This library is released under the Apache v2 License (see License).

**WARNING:** This is an academic proof-of-concept prototype, and in particular has not beed audited yet - please use it at your own risk.

## Installation
Install a recent stable Rust toolchain using rustup.

## Testing
Run cargo test to test both simple signing and aggregation.
