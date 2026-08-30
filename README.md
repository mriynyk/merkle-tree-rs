# mriynyk-merkle

[<img alt="github" src="https://img.shields.io/badge/github-mriynyk/merkle--tree--rs-7F77DD?style=for-the-badge&labelColor=555555&logo=github&logoColor=white" height="20">](https://github.com/mriynyk/merkle-tree-rs)
[<img alt="crates.io" src="https://img.shields.io/badge/crates.io-mriynyk--merkle-D85A30?style=for-the-badge&labelColor=555555&logo=rust&logoColor=white" height="20">](https://crates.io/crates/mriynyk-merkle)
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-mriynyk--merkle-1D9E75?style=for-the-badge&labelColor=555555&logo=docs.rs&logoColor=white" height="20">](https://docs.rs/mriynyk-merkle)
[<img alt="ci" src="https://img.shields.io/github/actions/workflow/status/mriynyk/merkle-tree-rs/ci.yml?branch=main&style=for-the-badge&label=ci&labelColor=555555" height="20">](https://github.com/mriynyk/merkle-tree-rs/actions?query=branch%3Amain)

Minimal Merkle tree utilities, generic over any hasher.

The crate computes a root, builds a proof, reconstructs a root from a proof, and verifies
a proof against a root. It builds the tree on the fly without storing it, and takes the
leaves as given.

The crate ships no hasher and is agnostic to the underlying hash function, so it works
with SHA-256, Keccak, Poseidon, or any other. Reference hashers live in the [`examples/`]
directory.

**`no_std`**, **no dependencies**, and the core runs **without an allocator**; the owning
wrappers live behind the `alloc` feature.

[`examples/`]: examples

## The tree

The tree is a [perfect] binary tree: the leaf count is padded up to a power of two with a
value the caller supplies, and the height is `ceil(log2(n))` for `n` leaves. It can be
built with a positional or a commutative hasher.

[perfect]: https://xlinux.nist.gov/dads/HTML/perfectBinaryTree.html

## Features

- `default` — the core, which never allocates.
- `alloc` — owning wrappers over the in-place functions.
- `std` — the same as `alloc`.

## Example

```rust
use mriynyk_merkle::{self as merkle, Hasher};

let hasher = Sha256Hasher;
let padding = [0u8; 32];
let leaves = ["alice:100", "bob:50", "carol:75", "dave:25", "erin:200"].map(leaf_hash);
let leaf_idx = 2;

// Both functions consume the buffer they reduce, so each one gets its own copy.
let mut buffer = leaves;
let root = merkle::root_in_place(&hasher, &mut buffer, padding).unwrap();

let mut buffer = leaves;
let proof = merkle::proof_in_place(&hasher, &mut buffer, leaf_idx, padding).unwrap();

merkle::verify(&hasher, leaves[leaf_idx], leaf_idx, proof, root).unwrap();
```

A complete, compiling example is in the [documentation].

[documentation]: https://docs.rs/mriynyk-merkle

## Compatibility

The same hasher has to be used on both sides. Beyond that:

- [`OpenZeppelin/contracts/MerkleProof.sol`] — a proof from this crate verifies, if the
  hasher is commutative.
- [`OpenZeppelin/contracts/MerkleTree.sol`] — roots agree, if its zero value is the
  padding and its depth is `ceil(log2(n))`.
- [`OpenZeppelin/merkle-tree`] — roots and proofs agree, if the hasher is commutative, `n
= 2^k`, leaves are double-hashed as the library does, and `sortLeaves: false`.
- [`merkletreejs`] — roots and proofs agree, if `fillDefaultHash` is the padding value and
  the other options are left at their defaults.

These claims come from cross-checking the implementations by hand. Tests that check this
automatically are on the roadmap.

[`OpenZeppelin/contracts/MerkleProof.sol`]: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/MerkleProof.sol
[`OpenZeppelin/contracts/MerkleTree.sol`]: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/structs/MerkleTree.sol
[`OpenZeppelin/merkle-tree`]: https://github.com/OpenZeppelin/merkle-tree
[`merkletreejs`]: https://github.com/merkletreejs/merkletreejs

## Roadmap

### Features

- **Multiproof** — building and verifying one proof for several leaves at once.
- **Incremental Merkle tree** — a fixed-depth tree that keeps only what it takes to append
  a leaf and to update one already there. [`MerkleTree.sol`] is a good example of the
  design.
- **In-memory tree** — a tree that keeps every node after the build, and from it serves a
  proof for a single leaf, a multiproof for several, an update of a leaf and an append of
  a new one.

### Assurance

Work that adds confidence in what already exists, rather than adding to it.

- **Formal verification** — proving with Kani that the crate cannot panic, overflow or
  index out of bounds.
- **Cross-implementation tests** — checking byte equality against the implementations
  named under Compatibility.
- **Property-based tests** — checking the invariants over generated inputs rather than
  chosen ones.
- **Benchmarks** — measuring the work around the hashing.

[`MerkleTree.sol`]: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/structs/MerkleTree.sol

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE] or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT] or <http://opensource.org/licenses/MIT>)

at your option.

[LICENSE-APACHE]: LICENSE-APACHE
[LICENSE-MIT]: LICENSE-MIT

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed
as above, without any additional terms or conditions.
