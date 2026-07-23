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
/// - [`ProofError::IndexOutOfRange`] if `leaf_idx` is not below `buffer.len()`.
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
    /// `leaf_idx` is not a valid index into the leaves.
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
