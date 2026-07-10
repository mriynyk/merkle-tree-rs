//! # SHA-256 hasher
//!
//! This example implements the `Hasher` trait with **SHA-256** and uses it to build a
//! Merkle root, produce an inclusion proof, and verify that proof.
//!
//! The tree is positional — pairs are hashed in order, without sorting, so a leaf's
//! position is committed by its proof.
//!
//! Run with:
//!
//! ```text
//! cargo run --example sha256 --features alloc
//! ```
//!
//! (The owning `root` / `proof` functions live behind the `alloc` feature. In no-alloc
//! builds, use `root_in_place` / `proof_in_place` instead.)

use mriynyk_merkle::{self as merkle, Hasher};
use sha2::{Digest, Sha256};

/// SHA-256 pair hasher.
///
/// Hashes the two inputs in order — `sha256(left ‖ right)`, no sorting.
struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    type Hash = [u8; 32];

    fn hash(&self, left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        let mut h = Sha256::new();

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
    Sha256::digest(data).into()
}

fn main() {
    let hasher = Sha256Hasher;

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

    // Verify the proof against the root.
    println!("verification for leaf [{leaf_idx}] ({}):", records[leaf_idx]);
    match merkle::verify(&hasher, leaves[leaf_idx], leaf_idx, &proof, root) {
        Ok(()) => println!("  OK — leaf is in the tree"),
        Err(e) => println!("  unexpected error — {e}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
