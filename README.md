# merkle-tree-rs

> ⚠️ **Early placeholder release.** The public API is not available yet — these
> first versions reserve the crate names and validate the release pipeline.

Merkle tree utilities for the EVM, written in Rust.

This repository is a Cargo workspace with two crates:

| Crate | Description | crates.io |
|-------|-------------|-----------|
| [`mriynyk-merkle`](crates/core) | Core library for building and verifying Merkle trees | [![crates.io](https://img.shields.io/crates/v/mriynyk-merkle.svg)](https://crates.io/crates/mriynyk-merkle) |
| [`mriynyk-merkle-cli`](crates/cli) | Command-line interface (the `merkle` binary) | [![crates.io](https://img.shields.io/crates/v/mriynyk-merkle-cli.svg)](https://crates.io/crates/mriynyk-merkle-cli) |

## Status

Work in progress. Solana VM support is planned for a later release.

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at
your option.
