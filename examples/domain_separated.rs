//! # Domain-separated SHA-256 hasher
//!
//! This example implements the `Hasher` trait with **domain-separated SHA-256** and uses
//! it to compute a root, build a proof, and verify that proof against the root.
//!
//! ## Why domain separation
//!
//! A Merkle tree hashes two different kinds of value: **leaves** (application data) and
//! **internal nodes** (two child hashes). If both are hashed the same way, an internal
//! node can be replayed as if it were a leaf — a second-preimage attack. Concretely: an
//! internal node is `hash(left ‖ right)`, the hash of 64 bytes. If a leaf is also just
//! `hash(data)`, then a 64-byte leaf whose bytes happen to equal some `left ‖ right`
//! produces the *same* digest as that node. An attacker can then present an internal node
//! as a "leaf" and prove membership of something that was never a real leaf.
//!
//! The fix is **domain separation**: hash leaves and nodes over disjoint inputs, so no
//! choice of leaf data can reproduce a node's digest. This example prepends a one-byte
//! domain tag before hashing — `0x00` for a leaf, `0x01` for a node — so a node preimage
//! (`0x01 ‖ left ‖ right`) can never equal a leaf preimage (`0x00 ‖ data`).
//!
//! OpenZeppelin's `StandardMerkleTree` (the `@openzeppelin/merkle-tree` JS library) reaches
//! the same goal differently: it **double-hashes** leaves — `keccak256(keccak256(data))`
//! — so a leaf can never match a single-hashed internal node. A domain tag is just a more
//! explicit way to draw the same boundary.
//!
//! Run with:
//!
//! ```text
//! cargo run --example domain_separated --features alloc
//! ```
//!
//! (The owning `root` / `proof` functions live behind the `alloc` feature. In no-alloc
//! builds, use `root_in_place` / `proof_in_place` instead.)

use mriynyk_merkle::{self as merkle, Hasher};
use sha2::{Digest, Sha256};

/// Domain tag prepended before hashing a leaf.
const LEAF_DOMAIN: u8 = 0x00;

/// Domain tag prepended before hashing an internal node.
const NODE_DOMAIN: u8 = 0x01;

/// Domain-separated SHA-256 node hasher.
///
/// Combines the two child hashes in the internal-node domain —
/// `NODE_DOMAIN ‖ left ‖ right`.
struct DomainSeparatedSha256;

impl Hasher for DomainSeparatedSha256 {
    type Hash = [u8; 32];

    fn hash(&self, left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        let mut h = Sha256::new();

        h.update([NODE_DOMAIN]);
        h.update(left);
        h.update(right);
        h.finalize().into()
    }
}

/// Leaf hasher.
///
/// Hashes application data in the leaf domain — `LEAF_DOMAIN ‖ data`.
fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();

    h.update([LEAF_DOMAIN]);
    h.update(data);
    h.finalize().into()
}

fn main() {
    let hasher = DomainSeparatedSha256;

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
    match merkle::verify(&hasher, leaves[leaf_idx], leaf_idx, &proof, root) {
        Ok(()) => println!("  OK — leaf is in the tree"),
        Err(e) => println!("  unexpected error — {e}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
