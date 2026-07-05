//! Build a Merkle root and an inclusion proof using Keccak-256 (the EVM hash).
//!
//! Run with: `cargo run --example keccak`

use mriynyk_merkle as merkle;
use sha3::{Digest, Keccak256};

/// Wraps Keccak-256 so it can be used as the tree's hash function.
struct Keccak;

impl merkle::Hasher for Keccak {
    type Hash = [u8; 32];

    fn hash(&self, left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        let mut hasher = Keccak256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let hasher = Keccak;

    // Hash used to pad an odd number of nodes up to a power of two.
    let padding = [0u8; 32];

    // Merkle root over five leaves. `root_in_place` needs no allocator.
    let mut leaves = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]];
    let root = merkle::root_in_place(&hasher, &mut leaves, padding).unwrap();
    println!("Merkle root: 0x{}", hex(&root));

    // Inclusion proof for the first leaf (index 0).
    let mut leaves = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]];

    let proof = merkle::proof_in_place(&hasher, &mut leaves, 0, padding).unwrap();

    println!("Proof for leaf 0 ({} nodes):", proof.len());

    for node in proof {
        println!("  0x{}", hex(node));
    }
}
