//! # Positional Keccak-256 hasher
//!
//! This example implements the `Hasher` trait with **positional Keccak-256** and uses it
//! to build a Merkle root, produce an inclusion proof, and verify that proof.
//!
//! ## What "positional" means here
//!
//! The core of this crate is agnostic to pair ordering: it always calls
//! `hash(left, right)` in a fixed argument order and lets the `Hasher` decide whether
//! that order matters. This example connects a hasher that **hashes the pair in order,
//! without sorting**, so `hash(a, b) != hash(b, a)`. That choice is what makes the tree
//! *positional*.
//!
//! ## What verification proves here: membership at a specific position
//!
//! Under a positional hasher the argument order matters, so the bits of `leaf_idx`
//! cryptographically bind the leaf to its position. `verify` therefore proves
//! **position**: the leaf sits at exactly `leaf_idx`, and a wrong (but in-range) index
//! folds the siblings in the wrong order, reconstructs a different root, and is rejected.
//! An out-of-range index — one that needs more bits than the proof has depth
//! (`>= 2^proof.len()`) — is rejected as malformed, regardless of the hasher.
//!
//! Run with:
//!
//! ```text
//! cargo run --example keccak256_positional --features alloc
//! ```
//!
//! (The owning `root` / `proof` functions live behind the `alloc` feature. In no-alloc
//! builds, use `root_in_place` / `proof_in_place` instead.)

use mriynyk_merkle::{self as merkle, Hasher};
use sha3::{Digest, Keccak256};

/// Positional Keccak-256 pair hasher.
///
/// Hashes the two inputs in order — `keccak256(left ‖ right)`, no sorting — so
/// `hash(a, b) != hash(b, a)` and the side each child sits on is significant.
struct PositionalKeccak256;

impl Hasher for PositionalKeccak256 {
    type Hash = [u8; 32];

    fn hash(&self, left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        let mut h = Keccak256::new();

        h.update(left);
        h.update(right);
        h.finalize().into()
    }
}

/// Hash raw application bytes into a leaf digest.
///
/// WARNING: example only, not production-safe. Single-hash leaves are open to the 64-byte
/// second-preimage; use domain separation / double-hash in production.
fn leaf_hash(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

fn main() {
    let hasher = PositionalKeccak256;

    // `padding` is the empty-leaf value used to pad the leaf count up to a power of two.
    // It must not be a valid leaf value.
    let padding = [0u8; 32];

    // Build the leaves. Five records -> odd count -> the tree is lazily padded up to a
    // perfect 8-leaf tree.
    let records: [&str; 5] = ["alice:100", "bob:50", "carol:75", "dave:25", "erin:200"];
    let leaves: Vec<[u8; 32]> = records.iter().map(|d| leaf_hash(d.as_bytes())).collect();

    println!("leaves ({}):", leaves.len());
    leaves.iter().enumerate().for_each(|(i, leaf)| {
        println!("  [{i}] {:<10} 0x{}", records[i], hex(leaf));
    });
    println!();

    // Build the root. `root` and `proof` each *consume* the vector they are given,
    // reusing it as in-place scratch buffer — that is how the library stays
    // allocation-free internally.
    let root = merkle::root(&hasher, leaves.clone(), padding).expect("leaves are non-empty");

    println!("root:");
    println!("  0x{}", hex(&root));
    println!();

    // Prove that leaf #2 ("carol:75") is in the tree at index 2. The proof is the list of
    // sibling hashes on the path from the leaf up to the root, ordered leaf -> root.
    let leaf_idx = 2;
    let proof = merkle::proof(&hasher, leaves.clone(), leaf_idx, padding).expect("index is in range");

    println!("proof for leaf [{leaf_idx}] ({}) — {} siblings:", records[leaf_idx], proof.len());
    proof.iter().enumerate().for_each(|(level, sibling)| {
        println!("  level {level}: 0x{}", hex(sibling));
    });
    println!();

    // Verification. Under a positional hasher `verify` binds the leaf to its position:
    // only the correct index reconstructs the root; a wrong (but in-range) index folds
    // the siblings in the wrong order and fails.
    println!("verification for leaf [{leaf_idx}] ({}):", records[leaf_idx]);

    let res = merkle::verify(&hasher, leaves[leaf_idx], leaf_idx, &proof, root);
    println!("  index {leaf_idx} (correct)        -> {res:?}");

    let res = merkle::verify(&hasher, leaves[leaf_idx], 0, &proof, root);
    println!("  index 0 (wrong position) -> {res:?}");

    let res = merkle::verify(&hasher, leaves[leaf_idx], 3, &proof, root);
    println!("  index 3 (also wrong) -> {res:?}");

    // The range-check stays active regardless of the hasher: an index that needs more
    // bits than the proof has depth (proof.len() == 3 -> range 0..8) is malformed and
    // reported distinctly from a mismatching proof.
    let res = merkle::verify(&hasher, leaves[leaf_idx], 8, &proof, root);
    println!("  index 8 (out of range)   -> {res:?}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
