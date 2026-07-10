use crate::Hasher;

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
        let sibling_idx = leaf_idx ^ 1;

        let sibling = if sibling_idx < level_len {
            buffer[sibling_idx]
        } else {
            padding
        };

        let mut read_idx = 0;
        let mut write_idx = 0;
        let path_parent_idx = leaf_idx >> 1;

        while read_idx < level_len - 1 {
            if write_idx != path_parent_idx {
                buffer[write_idx] = hasher.hash(&buffer[read_idx], &buffer[read_idx + 1]);
            }
            write_idx += 1;
            read_idx += 2;
        }

        if read_idx < level_len {
            if write_idx != path_parent_idx {
                buffer[write_idx] = hasher.hash(&buffer[read_idx], &padding);
            }
            write_idx += 1;
        }

        leaf_idx >>= 1;
        level_len = write_idx;
        proof_len += 1;

        buffer[buffer_len - proof_len] = sibling;

        if !level_len.is_power_of_two() {
            padding = hasher.hash(&padding, &padding);
        }
    }

    for idx in 0..proof_len {
        buffer[idx] = buffer[buffer_len - idx - 1];
    }

    Ok(&buffer[..proof_len])
}

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
pub fn proof<H: Hasher>(
    hasher: &H,
    mut leaves: Vec<H::Hash>,
    leaf_idx: usize,
    padding: H::Hash,
) -> Result<Vec<H::Hash>, ProofError> {
    let proof_len = proof_in_place(hasher, &mut leaves, leaf_idx, padding)?.len();

    leaves.truncate(proof_len);

    Ok(leaves)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    EmptyInput,
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
