#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Merkle tree utilities — build roots and inclusion proofs generic over any
//! hash function via the [`Hasher`] trait.
//!
//! The core API is `#![no_std]` and needs no allocator; owning convenience
//! wrappers live behind the `alloc` feature.
//!
//! ## Features
//!
//! - **default** — allocator-free API: [`root_in_place`], [`proof_in_place`],
//!   [`process_proof`], [`verify`].
//! - **`alloc`** — adds the owning [`root`] and [`proof`] functions (requires a
//!   global allocator).
//! - **`std`** — implies `alloc`.

#[cfg(feature = "alloc")]
extern crate alloc;

mod hasher;
mod process_proof;
mod proof;
mod root;
mod verify;

pub use hasher::Hasher;
pub use process_proof::process_proof;
#[cfg(feature = "alloc")]
pub use proof::proof;
pub use proof::{ProofError, proof_in_place};
#[cfg(feature = "alloc")]
pub use root::root;
pub use root::{RootError, root_in_place};
pub use verify::{VerifyError, verify};
