use crate::Hasher;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Builds a proof in place.
///
/// The proof is the sequence of sibling hashes along the path from the leaf to the root,
/// ordered bottom-up: the first entry is the sibling at the leaf level, the last the
/// sibling just below the root. Pass it back to [`verify`](crate::verify) or
/// [`process_proof`](crate::process_proof) with the same leaf and index.
///
/// Reduces the leaves level by level, hashing pairs of nodes into their parents with
/// `hasher` and padding the leaf count up to a power of two as the reduction proceeds.
/// Nothing is allocated. At each level it records the sibling of the node lying on the
/// path from the leaf to the root; that node is never part of the proof, so its parent
/// is left uncomputed. The recorded siblings, one per level, are the proof.
///
/// `buffer` holds the input leaves and doubles as scratch, so its contents are left
/// unspecified afterward; the returned slice borrows its front.
///
/// `leaf_idx` is the position of the target leaf among the original leaves, before any
/// padding. `padding` is hashed in place of a missing sibling and must not be a valid
/// leaf; see the [crate documentation](crate#usage).
///
/// Runs in `O(n)` time for `n` leaves.
///
/// # Errors
///
/// - [`ProofError::EmptyInput`] if the input contains no leaves.
/// - [`ProofError::IndexOutOfRange`] if `leaf_idx` is not below the number of leaves.
pub fn proof_in_place<'b, H: Hasher>(
    hasher: &H,
    buffer: &'b mut [H::Hash],
    mut leaf_idx: usize,
    mut padding: H::Hash,
) -> Result<&'b [H::Hash], ProofError> {
    if buffer.is_empty() {
        return Err(ProofError::EmptyInput);
    }

    if leaf_idx >= buffer.len() {
        return Err(ProofError::IndexOutOfRange);
    }

    let buffer_len = buffer.len();
    let mut level_len = buffer_len;
    let mut proof_len = 0;

    while level_len > 1 {
        // Read the sibling before the level is overwritten by the reduction.
        let sibling_idx = leaf_idx ^ 1;

        // The path node is the leftover one when its sibling falls past the level, so
        // `padding` takes the sibling's place.
        let sibling = if sibling_idx < level_len {
            buffer[sibling_idx]
        } else {
            padding
        };

        let mut read_idx = 0;
        let mut write_idx = 0;
        let path_parent_idx = leaf_idx >> 1;

        // `write_idx` stays behind `read_idx`, so each parent overwrites a slot whose
        // children were already read.
        while read_idx < level_len - 1 {
            // The parent lying on the path is skipped: the proof takes siblings, and no
            // later level reads it.
            if write_idx != path_parent_idx {
                buffer[write_idx] = hasher.hash(&buffer[read_idx], &buffer[read_idx + 1]);
            }

            write_idx += 1;
            read_idx += 2;
        }

        // A leftover node with no sibling is paired with `padding`.
        if read_idx < level_len {
            // Same skip for the leftover node's parent.
            if write_idx != path_parent_idx {
                buffer[write_idx] = hasher.hash(&buffer[read_idx], &padding);
            }

            write_idx += 1;
        }

        // Climb one level: the parent's index is the child's halved.
        leaf_idx >>= 1;
        level_len = write_idx;
        proof_len += 1;

        // The reduction fills the buffer from the front, so the proof grows from the
        // back; the two regions never overlap.
        buffer[buffer_len - proof_len] = sibling;

        // `padding` stands for the empty subtree at the current level; hashing it with
        // itself raises it one level up. Once `level_len` is a power of two the remaining
        // levels are even, so `padding` is no longer needed.
        if !level_len.is_power_of_two() {
            padding = hasher.hash(&padding, &padding);
        }
    }

    // Move the proof to the front. It is stored backwards at the end, so copying from the
    // back restores the correct order.
    for idx in 0..proof_len {
        buffer[idx] = buffer[buffer_len - idx - 1];
    }

    Ok(&buffer[..proof_len])
}

/// Builds a proof, consuming the leaves.
///
/// The counterpart to [`proof_in_place`] for callers holding an owned `Vec`. It reuses
/// the vector as scratch, then truncates and shrinks it to the proof, so the returned
/// `Vec` is exactly proof-sized; the shrink may reallocate. See [`proof_in_place`] for
/// the proof layout and the full contract.
///
/// # Errors
///
/// Same as [`proof_in_place`].
#[cfg(feature = "alloc")]
pub fn proof<H: Hasher>(
    hasher: &H,
    mut leaves: Vec<H::Hash>,
    leaf_idx: usize,
    padding: H::Hash,
) -> Result<Vec<H::Hash>, ProofError> {
    let proof_len = proof_in_place(hasher, &mut leaves, leaf_idx, padding)?.len();

    leaves.truncate(proof_len);
    leaves.shrink_to_fit();

    Ok(leaves)
}

/// The error returned by [`proof_in_place`] and [`proof`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    /// The input contains no leaves.
    EmptyInput,
    /// The leaf index is not below the number of leaves.
    IndexOutOfRange,
}

impl core::fmt::Display for ProofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ProofError::EmptyInput => "input is empty",
            ProofError::IndexOutOfRange => "leaf index out of range",
        })
    }
}

impl core::error::Error for ProofError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;

    #[test]
    fn with_one_leaf_is_empty() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 1] = build_leaves();
        let tree: [Hash; 1] = build_tree(&hasher, leaves);
        let mut buffer = leaves;
        let proof = proof_in_place(&hasher, &mut buffer, 0, PADDING).unwrap();
        let expected: [Hash; 0] = build_proof(&tree, 0);

        assert_eq!(proof, &expected[..]);
    }

    #[test]
    fn with_two_leaves_needs_no_padding() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 2] = build_leaves();
        let tree: [Hash; 3] = build_tree(&hasher, leaves);

        for leaf_idx in 0..leaves.len() {
            let mut buffer = leaves;
            let proof = proof_in_place(&hasher, &mut buffer, leaf_idx, PADDING).unwrap();
            let expected: [Hash; 1] = build_proof(&tree, leaf_idx);

            assert_eq!(proof, &expected[..], "leaf {leaf_idx}");
        }
    }

    #[test]
    fn with_three_leaves_pads_the_missing_sibling() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 3] = build_leaves();
        let leaves_padded: [Hash; 4] = pad_leaves(&leaves, PADDING);
        let tree: [Hash; 7] = build_tree(&hasher, leaves_padded);

        for leaf_idx in 0..leaves.len() {
            let mut buffer = leaves;
            let proof = proof_in_place(&hasher, &mut buffer, leaf_idx, PADDING).unwrap();
            let expected: [Hash; 2] = build_proof(&tree, leaf_idx);

            assert_eq!(proof, &expected[..], "leaf {leaf_idx}");
        }
    }

    #[test]
    fn with_four_leaves_needs_no_padding() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 4] = build_leaves();
        let tree: [Hash; 7] = build_tree(&hasher, leaves);

        for leaf_idx in 0..leaves.len() {
            let mut buffer = leaves;
            let proof = proof_in_place(&hasher, &mut buffer, leaf_idx, PADDING).unwrap();
            let expected: [Hash; 2] = build_proof(&tree, leaf_idx);

            assert_eq!(proof, &expected[..], "leaf {leaf_idx}");
        }
    }

    #[test]
    fn with_five_leaves_pads_on_two_levels() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 5] = build_leaves();
        let leaves_padded: [Hash; 8] = pad_leaves(&leaves, PADDING);
        let tree: [Hash; 15] = build_tree(&hasher, leaves_padded);

        for leaf_idx in 0..leaves.len() {
            let mut buffer = leaves;
            let proof = proof_in_place(&hasher, &mut buffer, leaf_idx, PADDING).unwrap();
            let expected: [Hash; 3] = build_proof(&tree, leaf_idx);

            assert_eq!(proof, &expected[..], "leaf {leaf_idx}");
        }
    }

    #[test]
    fn with_six_leaves_raises_the_padding_before_using_it() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 6] = build_leaves();
        let leaves_padded: [Hash; 8] = pad_leaves(&leaves, PADDING);
        let tree: [Hash; 15] = build_tree(&hasher, leaves_padded);

        for leaf_idx in 0..leaves.len() {
            let mut buffer = leaves;
            let proof = proof_in_place(&hasher, &mut buffer, leaf_idx, PADDING).unwrap();
            let expected: [Hash; 3] = build_proof(&tree, leaf_idx);

            assert_eq!(proof, &expected[..], "leaf {leaf_idx}");
        }
    }

    #[test]
    fn with_seven_leaves_uses_the_padding_without_raising_it() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 7] = build_leaves();
        let leaves_padded: [Hash; 8] = pad_leaves(&leaves, PADDING);
        let tree: [Hash; 15] = build_tree(&hasher, leaves_padded);

        for leaf_idx in 0..leaves.len() {
            let mut buffer = leaves;
            let proof = proof_in_place(&hasher, &mut buffer, leaf_idx, PADDING).unwrap();
            let expected: [Hash; 3] = build_proof(&tree, leaf_idx);

            assert_eq!(proof, &expected[..], "leaf {leaf_idx}");
        }
    }

    #[test]
    fn with_eight_leaves_needs_no_padding() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 8] = build_leaves();
        let tree: [Hash; 15] = build_tree(&hasher, leaves);

        for leaf_idx in 0..leaves.len() {
            let mut buffer = leaves;
            let proof = proof_in_place(&hasher, &mut buffer, leaf_idx, PADDING).unwrap();
            let expected: [Hash; 3] = build_proof(&tree, leaf_idx);

            assert_eq!(proof, &expected[..], "leaf {leaf_idx}");
        }
    }

    #[test]
    fn with_nine_leaves_raises_the_padding_twice() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 9] = build_leaves();
        let leaves_padded: [Hash; 16] = pad_leaves(&leaves, PADDING);
        let tree: [Hash; 31] = build_tree(&hasher, leaves_padded);

        for leaf_idx in 0..leaves.len() {
            let mut buffer = leaves;
            let proof = proof_in_place(&hasher, &mut buffer, leaf_idx, PADDING).unwrap();
            let expected: [Hash; 4] = build_proof(&tree, leaf_idx);

            assert_eq!(proof, &expected[..], "leaf {leaf_idx}");
        }
    }

    #[test]
    fn with_twenty_leaves_raises_the_padding_three_times() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 20] = build_leaves();
        let leaves_padded: [Hash; 32] = pad_leaves(&leaves, PADDING);
        let tree: [Hash; 63] = build_tree(&hasher, leaves_padded);

        for leaf_idx in 0..leaves.len() {
            let mut buffer = leaves;
            let proof = proof_in_place(&hasher, &mut buffer, leaf_idx, PADDING).unwrap();
            let expected: [Hash; 5] = build_proof(&tree, leaf_idx);

            assert_eq!(proof, &expected[..], "leaf {leaf_idx}");
        }
    }

    #[test]
    fn supports_a_commutative_hasher() {
        let hasher = CommutativeSha256::new();
        let leaves: [Hash; 5] = build_leaves();
        let leaves_padded: [Hash; 8] = pad_leaves(&leaves, PADDING);
        let tree: [Hash; 15] = build_tree(&hasher, leaves_padded);

        for leaf_idx in 0..leaves.len() {
            let mut buffer = leaves;
            let proof = proof_in_place(&hasher, &mut buffer, leaf_idx, PADDING).unwrap();
            let expected: [Hash; 3] = build_proof(&tree, leaf_idx);

            assert_eq!(proof, &expected[..], "leaf {leaf_idx}");
        }
    }

    #[test]
    fn hash_count_matches_the_tree_shape() {
        let hasher = PositionalSha256::new();
        let mut buffer: [Hash; 30] = build_leaves();

        // Leaf count and the hashes it takes, as pairs + tails + raises - skips. The
        // skipped node is the one on the path, one per level.
        let cases = [
            (1, 0),   // 0 + 0 + 0 - 0
            (2, 0),   // 1 + 0 + 0 - 1
            (3, 1),   // 2 + 1 + 0 - 2
            (4, 1),   // 3 + 0 + 0 - 2
            (5, 4),   // 4 + 2 + 1 - 3
            (6, 4),   // 5 + 1 + 1 - 3
            (7, 4),   // 6 + 1 + 0 - 3
            (8, 4),   // 7 + 0 + 0 - 3
            (20, 19), // 19 + 2 + 3 - 5
            (30, 26), // 29 + 1 + 1 - 5
        ];

        for (leaf_count, hashes) in cases {
            hasher.reset_hash_count();
            proof_in_place(&hasher, &mut buffer[..leaf_count], 0, PADDING).unwrap();

            assert_eq!(hasher.hash_count(), hashes, "{leaf_count} leaves");
        }
    }

    #[test]
    fn hash_count_ignores_the_leaf_index() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 20] = build_leaves();

        for leaf_idx in 0..leaves.len() {
            let mut buffer = leaves;
            hasher.reset_hash_count();
            proof_in_place(&hasher, &mut buffer, leaf_idx, PADDING).unwrap();

            assert_eq!(hasher.hash_count(), 19, "leaf {leaf_idx}");
        }
    }

    #[test]
    fn rejects_empty_input() {
        let hasher = PositionalSha256::new();
        let mut buffer: [Hash; 0] = [];
        let error = proof_in_place(&hasher, &mut buffer, 0, PADDING).unwrap_err();

        assert_eq!(error, ProofError::EmptyInput);
    }

    #[test]
    fn rejects_an_index_past_the_last_leaf() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 5] = build_leaves();
        let mut buffer = leaves;
        let error = proof_in_place(&hasher, &mut buffer, leaves.len(), PADDING).unwrap_err();

        assert_eq!(error, ProofError::IndexOutOfRange);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn owned_matches_in_place() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 5] = build_leaves();
        let leaf_idx = 2;
        let mut buffer = leaves;
        let expected = proof_in_place(&hasher, &mut buffer, leaf_idx, PADDING).unwrap();
        let proof = proof(&hasher, leaves.to_vec(), leaf_idx, PADDING).unwrap();

        assert_eq!(proof, expected);
    }
}
