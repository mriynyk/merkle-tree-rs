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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;

    const TOO_LONG_PROOF: [Hash; usize::BITS as usize] = [PADDING; usize::BITS as usize];

    #[test]
    fn accepts_the_proof_of_every_leaf() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 8] = build_leaves();
        let tree: [Hash; 15] = build_tree(&hasher, leaves);

        for (leaf_idx, leaf) in leaves.into_iter().enumerate() {
            let proof: [Hash; 3] = build_proof(&tree, leaf_idx);
            let result = verify(&hasher, leaf, leaf_idx, &proof, root_of(&tree));

            assert_eq!(result, Ok(()), "leaf {leaf_idx}");
        }
    }

    #[test]
    fn rejects_a_wrong_index_as_an_invalid_proof() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 8] = build_leaves();
        let tree: [Hash; 15] = build_tree(&hasher, leaves);
        let leaf_idx = 2;
        let proof: [Hash; 3] = build_proof(&tree, leaf_idx);

        for wrong_idx in (0..leaves.len()).filter(|idx| *idx != leaf_idx) {
            let result = verify(&hasher, leaves[leaf_idx], wrong_idx, &proof, root_of(&tree));

            assert_eq!(result, Err(VerifyError::InvalidProof), "index {wrong_idx}");
        }
    }

    #[test]
    fn rejects_a_wrong_root_as_an_invalid_proof() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 8] = build_leaves();
        let tree: [Hash; 15] = build_tree(&hasher, leaves);
        let leaf_idx = 2;
        let proof: [Hash; 3] = build_proof(&tree, leaf_idx);
        let mut wrong_root = root_of(&tree);
        wrong_root[0] ^= 1;
        let result = verify(&hasher, leaves[leaf_idx], leaf_idx, &proof, wrong_root);

        assert_eq!(result, Err(VerifyError::InvalidProof));
    }

    #[test]
    fn rejects_a_wrong_proof_length_as_an_invalid_proof() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 8] = build_leaves();
        let tree: [Hash; 15] = build_tree(&hasher, leaves);
        let leaf_idx = 2;
        let proof: [Hash; 3] = build_proof(&tree, leaf_idx);
        let truncated = &proof[..2];
        let extended = [proof[0], proof[1], proof[2], PADDING];

        let result = verify(&hasher, leaves[leaf_idx], leaf_idx, truncated, root_of(&tree));

        assert_eq!(result, Err(VerifyError::InvalidProof), "truncated");

        let result = verify(&hasher, leaves[leaf_idx], leaf_idx, &extended, root_of(&tree));

        assert_eq!(result, Err(VerifyError::InvalidProof), "extended");
    }

    #[test]
    fn accepts_any_index_under_a_commutative_hasher() {
        let hasher = CommutativeSha256::new();
        let leaves: [Hash; 8] = build_leaves();
        let tree: [Hash; 15] = build_tree(&hasher, leaves);
        let leaf_idx = 2;
        let proof: [Hash; 3] = build_proof(&tree, leaf_idx);

        for any_idx in 0..leaves.len() {
            let result = verify(&hasher, leaves[leaf_idx], any_idx, &proof, root_of(&tree));

            assert_eq!(result, Ok(()), "index {any_idx}");
        }
    }

    #[test]
    fn accepts_an_empty_proof_only_at_index_zero() {
        let hasher = PositionalSha256::new();
        let leaf: Hash = [1; 32];
        let proof: [Hash; 0] = [];
        let result = verify(&hasher, leaf, 0, &proof, leaf);

        assert_eq!(result, Ok(()), "index 0");

        for above_the_tree_idx in 1..4 {
            let result = verify(&hasher, leaf, above_the_tree_idx, &proof, leaf);

            assert_eq!(result, Err(VerifyError::IndexOutOfRange), "index {above_the_tree_idx}");
        }
    }

    #[test]
    fn rejects_an_index_above_the_tree() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 8] = build_leaves();
        let tree: [Hash; 15] = build_tree(&hasher, leaves);
        let leaf_idx = 2;
        let proof: [Hash; 3] = build_proof(&tree, leaf_idx);

        for above_the_tree_idx in [8, 9, usize::MAX] {
            let result = verify(&hasher, leaves[leaf_idx], above_the_tree_idx, &proof, root_of(&tree));

            assert_eq!(result, Err(VerifyError::IndexOutOfRange), "index {above_the_tree_idx}");
        }
    }

    #[test]
    fn rejects_a_proof_too_long_to_index() {
        let hasher = PositionalSha256::new();
        let leaf: Hash = [1; 32];
        let result = verify(&hasher, leaf, 0, &TOO_LONG_PROOF, leaf);

        assert_eq!(result, Err(VerifyError::ProofTooLong));
    }

    #[test]
    fn checks_the_proof_length_before_the_index() {
        let hasher = PositionalSha256::new();
        let leaf: Hash = [1; 32];
        let result = verify(&hasher, leaf, usize::MAX, &TOO_LONG_PROOF, leaf);

        assert_eq!(result, Err(VerifyError::ProofTooLong));
    }

    #[test]
    fn folds_the_longest_accepted_proof() {
        let hasher = PositionalSha256::new();
        let leaf: Hash = [1; 32];
        let proof = [PADDING; usize::BITS as usize - 1];
        hasher.reset_hash_count();
        let result = verify(&hasher, leaf, 0, &proof, leaf);

        assert_eq!(result, Err(VerifyError::InvalidProof));
        assert_eq!(hasher.hash_count(), proof.len());
    }

    #[test]
    fn does_not_hash_rejected_input() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 8] = build_leaves();
        let tree: [Hash; 15] = build_tree(&hasher, leaves);
        let leaf_idx = 2;
        let proof: [Hash; 3] = build_proof(&tree, leaf_idx);

        hasher.reset_hash_count();
        let _ = verify(&hasher, leaves[leaf_idx], 1 << proof.len(), &proof, root_of(&tree));

        assert_eq!(hasher.hash_count(), 0, "index out of range");

        hasher.reset_hash_count();
        let _ = verify(&hasher, leaves[leaf_idx], 0, &TOO_LONG_PROOF, root_of(&tree));

        assert_eq!(hasher.hash_count(), 0, "proof too long");
    }
}
