use crate::Hasher;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootError {
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

        while read_idx < level_len - 1 {
            buffer[write_idx] = hasher.hash(&buffer[read_idx], &buffer[read_idx + 1]);
            read_idx += 2;
            write_idx += 1;
        }

        if read_idx < level_len {
            buffer[write_idx] = hasher.hash(&buffer[read_idx], &padding);
            write_idx += 1;
        }

        level_len = write_idx;

        if !level_len.is_power_of_two() {
            padding = hasher.hash(&padding, &padding);
        }
    }

    Ok(buffer[0])
}

#[cfg(feature = "alloc")]
pub fn root<H: Hasher>(
    hasher: &H,
    mut leaves: Vec<H::Hash>,
    padding: H::Hash,
) -> Result<H::Hash, RootError> {
    root_in_place(hasher, &mut leaves, padding)
}
