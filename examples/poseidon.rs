//! # Poseidon (BN254) hasher
//!
//! This example implements the `Hasher` trait with **Poseidon over the BN254 scalar
//! field** and uses it to build a Merkle root, produce an inclusion proof, and verify
//! that proof. Poseidon is commonly used in zero-knowledge systems, where it is far more
//! efficient than hashes like Keccak or SHA-256.
//!
//! Poseidon has to be configured up front, so the hasher holds that config. That is why
//! `Hasher::hash` takes `&self`, an instance, rather than being a free function: a
//! stateless trait couldn't carry it. The `light_poseidon` sponge hashes through
//! `&mut self`, so we bridge it to our `&self` method with a `RefCell` — interior
//! mutability.
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
use ark_ff::{BigInteger, PrimeField, Zero};
use light_poseidon::{Poseidon, PoseidonHasher};
use mriynyk_merkle::{self as merkle, Hasher};

/// Stateful Poseidon (BN254) pair hasher.
///
/// Holds a `light_poseidon` sponge configured for two inputs. The sponge hashes through
/// `&mut self`, so it lives behind a `RefCell` to fit our `&self` API.
struct PoseidonBn254 {
    sponge: RefCell<Poseidon<Fr>>,
}

impl PoseidonBn254 {
    fn new() -> Self {
        // `new_circom(2)` configures the sponge for exactly two field inputs — one binary
        // node (left, right).
        let sponge = Poseidon::<Fr>::new_circom(2).expect("valid Poseidon width");
        Self {
            sponge: RefCell::new(sponge),
        }
    }
}

impl Hasher for PoseidonBn254 {
    type Hash = Fr;

    fn hash(&self, left: &Fr, right: &Fr) -> Fr {
        // `borrow_mut` exposes the `&mut self` sponge under our `&self` method. The
        // sponge resets its state on each call, so reusing one instance across every pair
        // is correct; two inputs always match the configured width, so this never errors.
        self.sponge
            .borrow_mut()
            .hash(&[*left, *right])
            .expect("two inputs match the configured width")
    }
}

fn main() {
    let hasher = PoseidonBn254::new();

    // `padding` is the empty-leaf value used to pad the leaf count up to a power of two.
    // It must not be a valid leaf value.
    let padding = Fr::zero();

    // Build the leaves. Five values -> odd count -> the tree is lazily padded up to a
    // perfect 8-leaf tree.
    let values: [u64; 5] = [100, 50, 75, 25, 200];
    let leaves: Vec<Fr> = values.iter().map(|&v| Fr::from(v)).collect();

    println!("leaves ({}):", leaves.len());
    leaves.iter().enumerate().for_each(|(i, leaf)| {
        println!("  [{i}] value 0x{}", fr_hex(*leaf));
    });
    println!();

    // Build the root. `root` and `proof` each *consume* the vector they are given,
    // reusing it as in-place scratch buffer — that is how the library stays
    // allocation-free internally.
    let root = merkle::root(&hasher, leaves.clone(), padding).expect("leaves are non-empty");

    println!("root:");
    println!("  0x{}", fr_hex(root));
    println!();

    // Prove that leaf #2 (value 75) is in the tree at index 2. The proof is the list of
    // sibling hashes on the path from the leaf up to the root, ordered leaf -> root.
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
