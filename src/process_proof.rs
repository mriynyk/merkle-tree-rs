use crate::Hasher;

/// Reconstructs a root from a proof.
///
/// Folds the leaf together with each sibling hash in `proof`, from the bottom up, and
/// returns the resulting root. The entries of `proof` must be ordered as produced by
/// [`proof`](crate::proof): the sibling at the leaf level first, the one just below the
/// root last.
///
/// This is a low-level building block. It performs no validation and never compares the
/// result against anything, so it always returns some hash, even for a malformed or
/// unrelated proof — equality with a trusted root is what makes a proof meaningful, and
/// checking it is left to the caller. For a ready check, use [`verify`](crate::verify).
///
/// `leaf_idx` is consulted only to place the running hash on the correct side at each
/// level. Under a positional hasher it must be the index the proof was built for; under a
/// commutative hasher the argument order is ignored, so the side never matters and any
/// index yields the same root.
///
/// # Errors
///
/// This function cannot fail; it always returns a hash.
pub fn process_proof<H: Hasher>(
    hasher: &H,
    leaf: H::Hash,
    mut leaf_idx: usize,
    proof: &[H::Hash],
) -> H::Hash {
    let mut node = leaf;

    for sibling in proof {
        // An even index puts the running hash on the left, an odd one on the right.
        node = if (leaf_idx & 1) == 0 {
            hasher.hash(&node, sibling)
        } else {
            hasher.hash(sibling, &node)
        };

        // Climb one level: the parent's index is the child's halved.
        leaf_idx >>= 1;
    }

    node
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;

    #[test]
    fn reconstructs_the_root_for_every_leaf() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 8] = build_leaves();
        let tree: [Hash; 15] = build_tree(&hasher, leaves);

        for (leaf_idx, leaf) in leaves.into_iter().enumerate() {
            let proof: [Hash; 3] = build_proof(&tree, leaf_idx);
            let root = process_proof(&hasher, leaf, leaf_idx, &proof);

            assert_eq!(root, root_of(&tree), "leaf {leaf_idx}");
        }
    }

    #[test]
    fn treats_padding_as_an_ordinary_sibling() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 5] = build_leaves();
        let leaves_padded: [Hash; 8] = pad_leaves(&leaves, PADDING);
        let tree: [Hash; 15] = build_tree(&hasher, leaves_padded);

        for (leaf_idx, leaf) in leaves.into_iter().enumerate() {
            let proof: [Hash; 3] = build_proof(&tree, leaf_idx);
            let root = process_proof(&hasher, leaf, leaf_idx, &proof);

            assert_eq!(root, root_of(&tree), "leaf {leaf_idx}");
        }
    }

    #[test]
    fn with_an_empty_proof_returns_the_leaf() {
        let hasher = PositionalSha256::new();
        let leaf: Hash = [1; 32];
        let proof: [Hash; 0] = [];
        let root = process_proof(&hasher, leaf, 0, &proof);

        assert_eq!(root, leaf);
    }

    #[test]
    fn with_a_wrong_index_gives_a_different_root() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 8] = build_leaves();
        let tree: [Hash; 15] = build_tree(&hasher, leaves);
        let leaf_idx = 2;
        let proof: [Hash; 3] = build_proof(&tree, leaf_idx);

        for wrong_idx in (0..leaves.len()).filter(|idx| *idx != leaf_idx) {
            let root = process_proof(&hasher, leaves[leaf_idx], wrong_idx, &proof);

            assert_ne!(root, root_of(&tree), "index {wrong_idx}");
        }
    }

    #[test]
    fn ignores_the_index_under_a_commutative_hasher() {
        let hasher = CommutativeSha256::new();
        let leaves: [Hash; 8] = build_leaves();
        let tree: [Hash; 15] = build_tree(&hasher, leaves);
        let leaf_idx = 2;
        let proof: [Hash; 3] = build_proof(&tree, leaf_idx);

        for any_idx in 0..leaves.len() {
            let root = process_proof(&hasher, leaves[leaf_idx], any_idx, &proof);

            assert_eq!(root, root_of(&tree), "index {any_idx}");
        }
    }

    #[test]
    fn ignores_index_bits_above_the_proof() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 8] = build_leaves();
        let tree: [Hash; 15] = build_tree(&hasher, leaves);
        let leaf_idx = 2;
        let proof: [Hash; 3] = build_proof(&tree, leaf_idx);
        let above_the_tree_idx = leaf_idx + (1 << proof.len());
        let root = process_proof(&hasher, leaves[leaf_idx], above_the_tree_idx, &proof);

        assert_eq!(root, root_of(&tree));
    }

    #[test]
    fn hashes_once_per_proof_entry() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 8] = build_leaves();
        let tree: [Hash; 15] = build_tree(&hasher, leaves);
        let leaf_idx = 2;
        let proof: [Hash; 3] = build_proof(&tree, leaf_idx);
        let empty_proof: [Hash; 0] = [];

        hasher.reset_hash_count();
        process_proof(&hasher, leaves[leaf_idx], leaf_idx, &proof);

        assert_eq!(hasher.hash_count(), proof.len(), "three siblings");

        hasher.reset_hash_count();
        process_proof(&hasher, leaves[leaf_idx], leaf_idx, &empty_proof);

        assert_eq!(hasher.hash_count(), empty_proof.len(), "no siblings");
    }
}
