# Optrand-PVSS

A library supporting the operations from the publicly verifiable secret sharing (PVSS) scheme from the [Optrand](https://eprint.iacr.org/2022/193.pdf) protocol.
Written purely in Rust and intended to be used as a core cryptographic component of the upcoming GRandLine Distributed Randomness Beacon Protocol.

This library is released under the Apache v2 License (see License).

**WARNING:** This is an academic proof-of-concept prototype, and in particular has not beed audited yet - please use it at your own risk.

## Installation
Install a recent stable Rust toolchain using rustup.

## Testing
Run cargo test to test both simple signing and aggregation.
