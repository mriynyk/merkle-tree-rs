use crate::{Hasher, process_proof};

/// Verifies a proof against a root.
///
/// Reconstructs a root from the leaf, index, and proof (via
/// [`process_proof`](crate::process_proof)) and compares it with `root`, returning
/// `Ok(())` on an exact match.
///
/// A match means only that the leaf and proof reconstruct this exact `root`. It does not
/// establish that `root` is authentic — the caller must obtain it from a trusted source —
/// nor that the leaf is a value worth trusting, nor, on its own, that the hasher resists
/// second-preimage attacks (hence the domain-separation guidance in the [crate
/// documentation](crate#usage)). Given a trusted root and a suitable hasher, a match
/// shows the leaf belongs to that tree.
///
/// With a positional hasher a match also binds the position: `leaf_idx` must be the index
/// the proof was built for, or verification fails. With a commutative hasher the side at
/// each level is not consulted (see [`process_proof`](crate::process_proof)), so the
/// position is not bound and any index that fits in the tree verifies equally; `0` always
/// works.
///
/// # Errors
///
/// - [`VerifyError::ProofTooLong`] if `proof` describes a tree with more leaves than
///   `usize` can count on this target.
/// - [`VerifyError::IndexOutOfRange`] if `leaf_idx` does not fit in a tree of height
///   `proof.len()`.
/// - [`VerifyError::InvalidProof`] if the reconstructed root does not equal `root`.
pub fn verify<H: Hasher>(
    hasher: &H,
    leaf: H::Hash,
    leaf_idx: usize,
    proof: &[H::Hash],
    root: H::Hash,
) -> Result<(), VerifyError> {
    if proof.len() >= usize::BITS as usize {
        return Err(VerifyError::ProofTooLong);
    }

    // The shift is well-defined now that the proof is shorter than `usize::BITS`. A
    // non-zero result means `leaf_idx` has a bit above the tree's height, so the index
    // does not fit in the tree.
    if (leaf_idx >> proof.len()) != 0 {
        return Err(VerifyError::IndexOutOfRange);
    }

    if process_proof(hasher, leaf, leaf_idx, proof) == root {
        Ok(())
    } else {
        Err(VerifyError::InvalidProof)
    }
}

/// The error returned by [`verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The proof describes a tree with more leaves than `usize` can count.
    ProofTooLong,
    /// The leaf index does not fit in a tree of the proof's height.
    IndexOutOfRange,
    /// The reconstructed root does not equal the expected root.
    InvalidProof,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            VerifyError::ProofTooLong => "proof is too long",
            VerifyError::IndexOutOfRange => "leaf index out of range",
            VerifyError::InvalidProof => "proof does not match root",
        })
    }
}

impl core::error::Error for VerifyError {}
