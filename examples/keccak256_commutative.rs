//! # Commutative Keccak-256 hasher (OpenZeppelin compatible)
//!
//! This example implements the `Hasher` trait with **commutative Keccak-256** and uses it
//! to compute a root, build a proof, and verify that proof against the root.
//!
//! The node hasher matches OpenZeppelin's `commutativeKeccak256` — the commutative hasher
//! behind `MerkleProof.sol`'s default `verify` — so a tree built with it produces proofs
//! that `MerkleProof.sol` accepts.
//!
//! ## What "commutative" means here
//!
//! The crate always calls `hash(left, right)` in a fixed argument order and lets the
//! `Hasher` decide whether that order matters. This example's hasher sorts the two child
//! hashes before hashing them, so `hash(a, b) == hash(b, a)`: the tree is built
//! commutatively and a leaf's position is not committed.
//!
//! ## What verification shows here: membership, not position
//!
//! Under a commutative hasher the argument order is irrelevant. The bits of `leaf_idx`
//! still choose which side the running hash goes on at each level, but the hasher ignores
//! that choice, so the sides no longer affect the root. `verify` therefore shows
//! **membership** ("this leaf is somewhere in the tree"), not location: any index that
//! fits in a tree of height `proof.len()` verifies, and `0` is the canonical choice. An
//! index that does not fit is rejected as malformed, whichever hasher is used.
//!
//! Run with:
//!
//! ```text
//! cargo run --example keccak256_commutative --features alloc
//! ```
//!
//! (The owning `root` / `proof` functions live behind the `alloc` feature. In no-alloc
//! builds, use `root_in_place` / `proof_in_place` instead.)

use mriynyk_merkle::{self as merkle, Hasher};
use sha3::{Digest, Keccak256};

/// Commutative Keccak-256 node hasher.
///
/// Sorts the two child hashes, then `keccak256(low ‖ high)`. Equal inputs hash the same
/// either way, so the sort makes `hash(a, b) == hash(b, a)`.
struct CommutativeKeccak256;

impl Hasher for CommutativeKeccak256 {
    type Hash = [u8; 32];

    fn hash(&self, left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        let (low, high) = if left <= right {
            (left, right)
        } else {
            (right, left)
        };

        let mut h = Keccak256::new();

        h.update(low);
        h.update(high);
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
    let hasher = CommutativeKeccak256;

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
    println!("  index {leaf_idx} (as built)       -> {res:?}");

    let res = merkle::verify(&hasher, leaves[leaf_idx], 0, &proof, root);
    println!("  index 0 (canonical)      -> {res:?}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
