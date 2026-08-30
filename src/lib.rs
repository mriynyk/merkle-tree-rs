#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Minimal Merkle tree utilities, generic over any hasher.
//!
//! The crate computes a root, builds a proof, reconstructs a root from a proof, and
//! verifies a proof against a root. It builds the tree on the fly without storing it, and
//! takes the leaves as given.
//!
//! The crate ships no hasher and is agnostic to the underlying hash function, so it works
//! with SHA-256, Keccak, Poseidon, or any other. Reference hashers live in the
//! [`examples/`] directory.
//!
//! **`no_std`**, **no dependencies**, and the core runs **without an allocator**; the
//! owning wrappers live behind the `alloc` feature.
//!
//! [`examples/`]: https://github.com/mriynyk/merkle-tree-rs/tree/main/examples
//!
//! ## The tree
//!
//! The tree is a binary [perfect] tree: the number of leaves is padded up to a power of
//! two, so all leaves sit on the same level. Its height — the number of levels from a
//! leaf up to the root — is `ceil(log2(n))` for `n` leaves, and a proof holds one entry
//! per level. The value used for the padding is supplied by the caller and stands in for
//! a missing sibling.
//!
//! The tree can be built with a positional or a commutative hasher. A positional hasher
//! combines the two child hashes in the given order, so the order matters and the
//! position is committed. A commutative hasher ignores the argument order, so `hash(a, b)
//! == hash(b, a)` and the position is not committed.
//!
//! [perfect]: https://xlinux.nist.gov/dads/HTML/perfectBinaryTree.html
//!
//! ## How it works
//!
//! - To compute a root, each level's nodes are hashed pairwise into their parents,
//!   starting from the leaves, until a single node — the root — is left.
//! - When a level has an odd number of nodes, the last one has no sibling, so it is
//!   hashed with the padding instead.
//! - The same padding value stands for the empty subtree at each level; hashing it with
//!   itself raises it one level up, so the empty subtrees are never materialized.
//! - To build a proof for a leaf, the path from the leaf to the root is walked, taking
//!   the sibling at every level.
//! - The leaf's index says which side each node is on, and hence which side its sibling
//!   is on.
//! - To verify a proof against a root, those siblings are folded with the leaf and the
//!   result is compared with the root.
//!
//! ## Hash count
//!
//! The number of hasher calls follows from the number of leaves alone.
//!
//! Computing a root takes `n - 1` calls to combine nodes into parents, one more for every
//! level holding an odd number of nodes, and one for every level the padding is raised
//! through. The last of these is the index of the highest level with an odd node count,
//! and none when no level is odd.
//!
//! Building a proof takes fewer calls, by the height of the tree, since the node on the
//! path to the leaf is left unhashed on every level.
//!
//! Reconstructing a root from a proof, and verifying one, take a call per proof entry.
//!
//! Hashing data into leaves happens before any of these functions is called and is not
//! counted.
//!
//! ## Features
//!
//! - **`default`** — the allocator-free API: [`root_in_place`], [`proof_in_place`],
//!   [`process_proof`], [`verify`].
//! - **`alloc`** — adds the owning [`root`] and [`proof`] functions.
//! - **`std`** — implies `alloc`.
//!
//! ## Usage
//!
//! - Each function returns a `Result` describing invalid input, except [`process_proof`],
//!   which cannot fail; see the per-function `# Errors` sections.
//! - [`root`], [`proof`], and [`verify`] must use the same hasher; [`root`] and [`proof`]
//!   must also use the same padding. Otherwise the roots will not agree.
//! - The padding must not be a valid leaf value. Otherwise it could be proven as a leaf
//!   in the tree.
//! - Under a commutative hasher the leaf's position is not committed, so [`verify`]
//!   accepts any index that fits in a tree of height `proof.len()`, and `0` always works.
//! - Keeping leaves and internal nodes in separate hashing domains is recommended as
//!   protection against second-preimage attacks; see the [`domain_separated`] example.
//! - A proof shows that a leaf is in the tree. Checking that the leaf itself is valid is
//!   up to the caller.
//!
//! [`domain_separated`]: https://github.com/mriynyk/merkle-tree-rs/blob/main/examples/domain_separated.rs
//!
//! ## Example
//!
//! ```
//! use mriynyk_merkle::{Hasher, proof_in_place, root_in_place, verify};
//! use sha2::{Digest, Sha256};
//!
//! const LEAF_DOMAIN: u8 = 0x00;
//! const NODE_DOMAIN: u8 = 0x01;
//!
//! struct Sha256Hasher;
//!
//! impl Hasher for Sha256Hasher {
//!     type Hash = [u8; 32];
//!
//!     fn hash(&self, left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
//!         let mut h = Sha256::new();
//!
//!         h.update([NODE_DOMAIN]);
//!         h.update(left);
//!         h.update(right);
//!         h.finalize().into()
//!     }
//! }
//!
//! let hasher = Sha256Hasher;
//! let padding = [0u8; 32];
//! let leaf_idx = 1;
//!
//! let leaves: [[u8; 32]; 3] = ["alice", "bob", "carol"].map(|data| {
//!     let mut h = Sha256::new();
//!
//!     h.update([LEAF_DOMAIN]);
//!     h.update(data);
//!     h.finalize().into()
//! });
//!
//! // Both functions consume the buffer they reduce, so each one gets its own copy.
//! let mut buffer = leaves;
//! let root = root_in_place(&hasher, &mut buffer, padding).unwrap();
//!
//! let mut buffer = leaves;
//! let proof = proof_in_place(&hasher, &mut buffer, leaf_idx, padding).unwrap();
//!
//! assert!(verify(&hasher, leaves[leaf_idx], leaf_idx, proof, root).is_ok());
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;

mod hasher;
mod process_proof;
mod proof;
mod root;
mod verify;

#[cfg(test)]
mod test_util;

pub use hasher::Hasher;
pub use process_proof::process_proof;
pub use proof::{ProofError, proof_in_place};
pub use root::{RootError, root_in_place};
pub use verify::{VerifyError, verify};

#[cfg(feature = "alloc")]
pub use proof::proof;
#[cfg(feature = "alloc")]
pub use root::root;
