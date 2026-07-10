//! # Domain-separated SHA-256 hasher
//!
//! A Merkle tree hashes three kinds of value: **leaves** (application data), **internal
//! nodes** (a pair of child hashes), and **padding** (the empty-leaf filler). If any two
//! share a hashing domain, one can be replayed as another — a second-preimage attack.
//!
//! The sharpest case is a node passed off as a leaf. An internal node is
//! `hash(left ‖ right)`, the hash of 64 bytes; if a leaf is also just `hash(data)`, a
//! 64-byte leaf whose bytes equal some `left ‖ right` produces the *same* digest as that
//! node, letting an attacker prove membership of something that was never a leaf. Padding
//! raises the same risk: it fills empty slots, so if its digest could equal a real
//! leaf's, an empty slot could be proven as a committed member.
//!
//! The fix is **domain separation**: hash each kind of value in its own domain so their
//! digests can never coincide. This example prepends a one-byte tag before hashing —
//! `0x00` for a leaf, `0x01` for a node, `0x02` for padding — keeping all three preimage
//! spaces disjoint by their first byte, even when the underlying bytes match.
//!
//! (OpenZeppelin's `StandardMerkleTree` reaches the same goal differently: it
//! **double-hashes** leaves — `keccak256(keccak256(data))` — so a leaf can never match a
//! single-hashed internal node. A domain tag is just a more explicit way to draw the same
//! boundary.)
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

/// Domain tag prepended before hashing padding.
const PADDING_DOMAIN: u8 = 0x02;

/// SHA-256 pair hasher with a domain tag for internal nodes.
///
/// Hashes `NODE_DOMAIN ‖ left ‖ right`.
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

/// Hash raw application bytes into a leaf digest, in the leaf domain.
///
/// Hashes `LEAF_DOMAIN ‖ data`. The leading tag keeps every leaf digest in a domain
/// disjoint from nodes and padding, so a 64-byte leaf can never hash to the same digest
/// as an internal node.
fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();

    h.update([LEAF_DOMAIN]);
    h.update(data);
    h.finalize().into()
}

/// Hash the empty-leaf into a digest, in the padding domain.
///
/// Hashes `PADDING_DOMAIN ‖ data`. The leading tag keeps padding in a domain disjoint
/// from leaves, so an empty slot can never match a committed leaf.
fn padding_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();

    h.update([PADDING_DOMAIN]);
    h.update(data);
    h.finalize().into()
}

fn main() {
    let hasher = DomainSeparatedSha256;

    // `padding` is used to pad the leaf count up to a power of two.
    let padding = padding_hash(b"");

    // Build the leaves.
    let records: [&str; 5] = ["alice:100", "bob:50", "carol:75", "dave:25", "erin:200"];
    let leaves: Vec<[u8; 32]> = records.iter().map(|d| leaf_hash(d.as_bytes())).collect();

    println!("leaves ({}):", leaves.len());
    leaves.iter().enumerate().for_each(|(i, leaf)| {
        println!("  [{i}] {:<10} 0x{}", records[i], hex(leaf));
    });
    println!();

    // Build the root.
    let root = merkle::root(&hasher, leaves.clone(), padding).expect("leaves are non-empty");

    println!("root:");
    println!("  0x{}", hex(&root));
    println!();

    // Build the proof for leaf #2 ("carol:75").
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
