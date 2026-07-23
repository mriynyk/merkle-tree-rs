//! # Poseidon (BN254) hasher
//!
//! This example implements the `Hasher` trait with **Poseidon over the BN254 scalar
//! field** and uses it to compute a root, build a proof, and verify that proof against
//! the root. Poseidon is commonly used in zero-knowledge systems.
//!
//! Poseidon has to be configured up front, so the hasher holds that configuration as a
//! `light_poseidon` sponge. The sponge mutates as it hashes, so it sits behind a
//! `RefCell` — the interior mutability the `Hasher` trait calls for.
//!
//! Run with:
//!
//! ```text
//! cargo run --example poseidon --features alloc
//! ```
//!
//! (The owning `root` / `proof` functions live behind the `alloc` feature. In no-alloc
//! builds, use `root_in_place` / `proof_in_place` instead.)

use core::cell::RefCell;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use mriynyk_merkle::{self as merkle, Hasher};

/// Stateful Poseidon (BN254) node hasher.
///
/// Holds a `light_poseidon` sponge configured for two inputs, behind a `RefCell` so that
/// hashing can mutate it.
struct PoseidonBn254 {
    sponge: RefCell<Poseidon<Fr>>,
}

impl PoseidonBn254 {
    fn new() -> Self {
        let sponge = Poseidon::<Fr>::new_circom(2).expect("valid Poseidon width");

        Self {
            sponge: RefCell::new(sponge),
        }
    }
}

impl Hasher for PoseidonBn254 {
    type Hash = Fr;

    fn hash(&self, left: &Fr, right: &Fr) -> Fr {
        self.sponge
            .borrow_mut()
            .hash(&[*left, *right])
            .expect("two inputs match the configured width")
    }
}

fn main() {
    let hasher = PoseidonBn254::new();

    // The padding must not be a valid leaf value. Leaves here are `u64` values, so any
    // field element beyond that range cannot be one.
    let padding = Fr::from(u128::MAX);

    // Build the leaves.
    let values: [u64; 5] = [100, 50, 75, 25, 200];
    let leaves: Vec<Fr> = values.iter().map(|&v| Fr::from(v)).collect();

    println!("leaves ({}):", leaves.len());
    leaves.iter().enumerate().for_each(|(i, leaf)| {
        println!("  [{i}]: 0x{}", fr_hex(*leaf));
    });
    println!();

    // Compute the root.
    let root = merkle::root(&hasher, leaves.clone(), padding).expect("leaves are non-empty");

    println!("root:");
    println!("  0x{}", fr_hex(root));
    println!();

    // Build the proof.
    let leaf_idx = 2;
    let proof = merkle::proof(&hasher, leaves.clone(), leaf_idx, padding).expect("index is in range");

    println!("proof for leaf [{leaf_idx}] (value {}) — {} siblings:", values[leaf_idx], proof.len());
    proof.iter().enumerate().for_each(|(level, sibling)| {
        println!("  level {level}: 0x{}", fr_hex(*sibling));
    });
    println!();

    // Verify the proof against the root.
    println!("verification for leaf [{leaf_idx}] (value {}):", values[leaf_idx]);
    match merkle::verify(&hasher, leaves[leaf_idx], leaf_idx, &proof, root) {
        Ok(()) => println!("  OK — leaf is in the tree"),
        Err(e) => println!("  unexpected error — {e}"),
    }
}

fn fr_hex(x: Fr) -> String {
    x.into_bigint()
        .to_bytes_be()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
