//! # Positional Keccak-256 hasher
//!
//! This example implements the `Hasher` trait with **positional Keccak-256** and uses it
//! to compute a root, build a proof, and verify that proof against the root.
//!
//! ## What "positional" means here
//!
//! The crate always calls `hash(left, right)` in a fixed argument order and lets the
//! `Hasher` decide whether that order matters. This example's hasher combines the two
//! child hashes in the given order, so the tree is built positionally and a leaf's
//! position is committed.
//!
//! ## What verification shows here: membership at a specific position
//!
//! Under a positional hasher the argument order matters. The bits of `leaf_idx` choose
//! which side the running hash goes on at each level, and the root commits to those
//! sides, so `verify` shows **position**: the leaf sits at exactly `leaf_idx`. A wrong
//! but in-range index combines the siblings on the wrong sides, reconstructs a different
//! root, and is rejected. An index that does not fit in a tree of height `proof.len()` is
//! rejected as malformed, whichever hasher is used.
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

/// Positional Keccak-256 node hasher.
///
/// Combines the two child hashes in order — `keccak256(left ‖ right)`; the side each
/// child sits on is significant.
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

/// Leaf hasher.
///
/// **WARNING:** example only, not production-safe. Hashing leaves with no domain
/// separation opens a second-preimage attack; see the `domain_separated` example.
fn leaf_hash(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

fn main() {
    let hasher = PositionalKeccak256;

    // The padding must not be a valid leaf value.
    let padding = [0u8; 32];

    // Build the leaves.
    let records: [&str; 5] = ["alice:100", "bob:50", "carol:75", "dave:25", "erin:200"];
    let leaves: Vec<[u8; 32]> = records.iter().map(|d| leaf_hash(d.as_bytes())).collect();

    println!("leaves ({}):", leaves.len());
    leaves.iter().enumerate().for_each(|(i, leaf)| {
        println!("  [{i}] {:<10} 0x{}", records[i], hex(leaf));
    });
    println!();

    // Compute the root.
    let root = merkle::root(&hasher, leaves.clone(), padding).expect("leaves are non-empty");

    println!("root:");
    println!("  0x{}", hex(&root));
    println!();

    // Build the proof.
    let leaf_idx = 2;
    let proof = merkle::proof(&hasher, leaves.clone(), leaf_idx, padding).expect("index is in range");

    println!("proof for leaf [{leaf_idx}] ({}) — {} siblings:", records[leaf_idx], proof.len());
    proof.iter().enumerate().for_each(|(level, sibling)| {
        println!("  level {level}: 0x{}", hex(sibling));
    });
    println!();

    // Verify the proof against the root.
    println!("verification for leaf [{leaf_idx}] ({}):", records[leaf_idx]);

    let res = merkle::verify(&hasher, leaves[leaf_idx], leaf_idx, &proof, root);
    println!("  index {leaf_idx} (as built)        -> {res:?}");

    let res = merkle::verify(&hasher, leaves[leaf_idx], 0, &proof, root);
    println!("  index 0 (wrong position)  -> {res:?}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
