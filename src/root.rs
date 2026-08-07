use crate::Hasher;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Computes a root in place.
///
/// Reduces the leaves stored in `buffer` level by level, hashing pairs of nodes into
/// their parents with `hasher` until a single node — the root — remains, padding the
/// leaf count up to a power of two as the reduction proceeds. Nothing is allocated.
///
/// `buffer` holds the input leaves and doubles as scratch, so its contents are left
/// unspecified once the function returns.
///
/// `padding` is hashed in place of a missing sibling whenever a level has an odd number
/// of nodes, and must not be a valid leaf; see the [crate documentation](crate#usage).
///
/// Runs in `O(n)` time for `n` leaves.
///
/// # Errors
///
/// Returns [`RootError::EmptyInput`] if the input contains no leaves.
pub fn root_in_place<H: Hasher>(
    hasher: &H,
    buffer: &mut [H::Hash],
    mut padding: H::Hash,
) -> Result<H::Hash, RootError> {
    if buffer.is_empty() {
        return Err(RootError::EmptyInput);
    }

    let mut level_len = buffer.len();

    while level_len > 1 {
        let mut read_idx = 0;
        let mut write_idx = 0;

        // `write_idx` stays behind `read_idx`, so each parent overwrites a slot whose
        // children were already read.
        while read_idx < level_len - 1 {
            buffer[write_idx] = hasher.hash(&buffer[read_idx], &buffer[read_idx + 1]);
            read_idx += 2;
            write_idx += 1;
        }

        // A leftover node with no sibling is paired with `padding`.
        if read_idx < level_len {
            buffer[write_idx] = hasher.hash(&buffer[read_idx], &padding);
            write_idx += 1;
        }

        // The parents just written form the next level.
        level_len = write_idx;

        // `padding` stands for the empty subtree at the current level; hashing it with
        // itself raises it one level up. Once `level_len` is a power of two the remaining
        // levels are even, so `padding` is no longer needed.
        if !level_len.is_power_of_two() {
            padding = hasher.hash(&padding, &padding);
        }
    }

    // The reduction leaves the root at the front. With a single leaf the loop never ran,
    // and that leaf is already the root.
    Ok(buffer[0])
}

/// Computes a root, consuming the leaves.
///
/// The counterpart to [`root_in_place`] for callers holding an owned `Vec`. It hands the
/// vector over as scratch and consumes it, so the unspecified-contents caveat never
/// applies. See [`root_in_place`] for the full contract.
///
/// # Errors
///
/// Same as [`root_in_place`].
#[cfg(feature = "alloc")]
pub fn root<H: Hasher>(hasher: &H, mut leaves: Vec<H::Hash>, padding: H::Hash) -> Result<H::Hash, RootError> {
    root_in_place(hasher, &mut leaves, padding)
}

/// The error returned by [`root_in_place`] and [`root`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootError {
    /// The input contains no leaves.
    EmptyInput,
}

impl core::fmt::Display for RootError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            RootError::EmptyInput => "input is empty",
        })
    }
}

impl core::error::Error for RootError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;

    #[test]
    fn with_one_leaf_returns_that_leaf() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 1] = build_leaves();
        let tree: [Hash; 1] = build_tree(&hasher, leaves);
        let mut buffer = leaves;
        let root = root_in_place(&hasher, &mut buffer, PADDING).unwrap();

        assert_eq!(root, root_of(&tree));
    }

    #[test]
    fn with_two_leaves_needs_no_padding() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 2] = build_leaves();
        let tree: [Hash; 3] = build_tree(&hasher, leaves);
        let mut buffer = leaves;
        let root = root_in_place(&hasher, &mut buffer, PADDING).unwrap();

        assert_eq!(root, root_of(&tree));
    }

    #[test]
    fn with_three_leaves_pads_the_odd_tail() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 3] = build_leaves();
        let leaves_padded: [Hash; 4] = pad_leaves(&leaves, PADDING);
        let tree: [Hash; 7] = build_tree(&hasher, leaves_padded);
        let mut buffer = leaves;
        let root = root_in_place(&hasher, &mut buffer, PADDING).unwrap();

        assert_eq!(root, root_of(&tree));
    }

    #[test]
    fn with_four_leaves_needs_no_padding() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 4] = build_leaves();
        let tree: [Hash; 7] = build_tree(&hasher, leaves);
        let mut buffer = leaves;
        let root = root_in_place(&hasher, &mut buffer, PADDING).unwrap();

        assert_eq!(root, root_of(&tree));
    }

    #[test]
    fn with_five_leaves_pads_on_two_levels() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 5] = build_leaves();
        let leaves_padded: [Hash; 8] = pad_leaves(&leaves, PADDING);
        let tree: [Hash; 15] = build_tree(&hasher, leaves_padded);
        let mut buffer = leaves;
        let root = root_in_place(&hasher, &mut buffer, PADDING).unwrap();

        assert_eq!(root, root_of(&tree));
    }

    #[test]
    fn with_six_leaves_raises_the_padding_before_using_it() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 6] = build_leaves();
        let leaves_padded: [Hash; 8] = pad_leaves(&leaves, PADDING);
        let tree: [Hash; 15] = build_tree(&hasher, leaves_padded);
        let mut buffer = leaves;
        let root = root_in_place(&hasher, &mut buffer, PADDING).unwrap();

        assert_eq!(root, root_of(&tree));
    }

    #[test]
    fn with_seven_leaves_uses_the_padding_without_raising_it() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 7] = build_leaves();
        let leaves_padded: [Hash; 8] = pad_leaves(&leaves, PADDING);
        let tree: [Hash; 15] = build_tree(&hasher, leaves_padded);
        let mut buffer = leaves;
        let root = root_in_place(&hasher, &mut buffer, PADDING).unwrap();

        assert_eq!(root, root_of(&tree));
    }

    #[test]
    fn with_eight_leaves_needs_no_padding() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 8] = build_leaves();
        let tree: [Hash; 15] = build_tree(&hasher, leaves);
        let mut buffer = leaves;
        let root = root_in_place(&hasher, &mut buffer, PADDING).unwrap();

        assert_eq!(root, root_of(&tree));
    }

    #[test]
    fn with_nine_leaves_raises_the_padding_twice() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 9] = build_leaves();
        let leaves_padded: [Hash; 16] = pad_leaves(&leaves, PADDING);
        let tree: [Hash; 31] = build_tree(&hasher, leaves_padded);
        let mut buffer = leaves;
        let root = root_in_place(&hasher, &mut buffer, PADDING).unwrap();

        assert_eq!(root, root_of(&tree));
    }

    #[test]
    fn with_twenty_leaves_raises_the_padding_three_times() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 20] = build_leaves();
        let leaves_padded: [Hash; 32] = pad_leaves(&leaves, PADDING);
        let tree: [Hash; 63] = build_tree(&hasher, leaves_padded);
        let mut buffer = leaves;
        let root = root_in_place(&hasher, &mut buffer, PADDING).unwrap();

        assert_eq!(root, root_of(&tree));
    }

    #[test]
    fn supports_a_commutative_hasher() {
        let hasher = CommutativeSha256::new();
        let leaves: [Hash; 5] = build_leaves();
        let leaves_padded: [Hash; 8] = pad_leaves(&leaves, PADDING);
        let tree: [Hash; 15] = build_tree(&hasher, leaves_padded);
        let mut buffer = leaves;
        let root = root_in_place(&hasher, &mut buffer, PADDING).unwrap();

        assert_eq!(root, root_of(&tree));
    }

    #[test]
    fn hash_count_matches_the_tree_shape() {
        let hasher = PositionalSha256::new();
        let mut buffer: [Hash; 30] = build_leaves();

        // Leaf count and the hashes it takes, as pairs + tails + raises.
        let cases = [
            (1, 0),   // 0 + 0 + 0
            (2, 1),   // 1 + 0 + 0
            (3, 3),   // 2 + 1 + 0
            (4, 3),   // 3 + 0 + 0
            (5, 7),   // 4 + 2 + 1
            (6, 7),   // 5 + 1 + 1
            (7, 7),   // 6 + 1 + 0
            (8, 7),   // 7 + 0 + 0
            (20, 24), // 19 + 2 + 3
            (30, 31), // 29 + 1 + 1
        ];

        for (leaf_count, hashes) in cases {
            hasher.reset_hash_count();
            root_in_place(&hasher, &mut buffer[..leaf_count], PADDING).unwrap();

            assert_eq!(hasher.hash_count(), hashes, "{leaf_count} leaves");
        }
    }

    #[test]
    fn rejects_empty_input() {
        let hasher = PositionalSha256::new();
        let mut buffer: [Hash; 0] = [];
        let error = root_in_place(&hasher, &mut buffer, PADDING).unwrap_err();

        assert_eq!(error, RootError::EmptyInput);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn owned_matches_in_place() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 5] = build_leaves();
        let mut buffer = leaves;
        let expected = root_in_place(&hasher, &mut buffer, PADDING).unwrap();
        let root = root(&hasher, leaves.to_vec(), PADDING).unwrap();

        assert_eq!(root, expected);
    }
}
