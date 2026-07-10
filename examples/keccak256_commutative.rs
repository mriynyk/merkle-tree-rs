//! # Commutative Keccak-256 hasher (OpenZeppelin compatible)
//!
//! This example implements the `Hasher` trait with **commutative Keccak-256** and uses it
//! to build a Merkle root, produce an inclusion proof, and verify that proof.
//!
//! The example's node hasher matches OpenZeppelin's `commutativeKeccak256` — the
//! commutative hash behind `MerkleProof.sol`'s default `verify`. Any commutative-hasher
//! tree verifies under `MerkleProof.sol`, as long as the same hasher is used on both
//! sides.
//!
//! ## What "commutative" means here
//!
//! The core of this crate is agnostic to pair ordering: it always calls
//! `hash(left, right)` in a fixed argument order and lets the `Hasher` decide whether
//! that order matters. This example connects a hasher that **sorts the pair before
//! hashing**, so `hash(a, b) == hash(b, a)`. That choice is what turns the tree
//! *commutative*.
//!
//! ## What verification proves here: membership, not position
//!
//! Under a commutative hasher the argument order is irrelevant, so the bits of `leaf_idx`
//! no longer bind the leaf to a position. `verify` therefore proves **membership** ("this
//! leaf is somewhere in the tree"), not location. Any in-range index verifies — `0` is
//! the canonical choice. The one thing the index still controls is the range-check: an
//! index that needs more bits than the proof has depth (`>= 2^proof.len()`) is rejected
//! as malformed, regardless of the hasher.
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

/// Commutative Keccak-256 pair hasher.
///
/// Sorts the two inputs, then `keccak256(low ‖ high)`. Equal inputs hash the same either
/// way, so the sort makes `hash(a, b) == hash(b, a)`.
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

/// Hash raw application bytes into a leaf digest.
///
/// WARNING: example only, not production-safe. Single-hash leaves are open to the 64-byte
/// second-preimage; use domain separation / double-hash in production.
fn leaf_hash(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

fn main() {
    let hasher = CommutativeKeccak256;

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

    // Prove that leaf #2 ("carol:75") is a member of the tree. The proof is the list of
    // sibling hashes on the path from the leaf up to the root, ordered leaf -> root.
    let leaf_idx = 2;
    let proof = merkle::proof(&hasher, leaves.clone(), leaf_idx, padding).expect("index is in range");

    println!("proof for leaf [{leaf_idx}] ({}) — {} siblings:", records[leaf_idx], proof.len());
    proof.iter().enumerate().for_each(|(level, sibling)| {
        println!("  level {level}: 0x{}", hex(sibling));
    });
    println!();

    // Verification. Under a commutative hasher `verify` proves membership, not position:
    // every in-range index reconstructs the same root.
    println!("verification for leaf [{leaf_idx}] ({}):", records[leaf_idx]);

    let res = merkle::verify(&hasher, leaves[leaf_idx], leaf_idx, &proof, root);
    println!("  index {leaf_idx} (correct)        -> {res:?}");

    let res = merkle::verify(&hasher, leaves[leaf_idx], 0, &proof, root);
    println!("  index 0 (canonical)      -> {res:?}");

    let res = merkle::verify(&hasher, leaves[leaf_idx], 3, &proof, root);
    println!("  index 3 (other in-range) -> {res:?}");

    // The range-check stays active regardless of the hasher: an index that needs more
    // bits than the proof has depth (proof.len() == 3 -> range 0..8) is malformed and
    // reported distinctly from a mismatching proof.
    let res = merkle::verify(&hasher, leaves[leaf_idx], 8, &proof, root);
    println!("  index 8 (out of range)   -> {res:?}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
