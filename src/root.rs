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
