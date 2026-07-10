use crate::{Hasher, process_proof};

pub fn verify<H: Hasher>(
    hasher: &H,
    leaf: H::Hash,
    leaf_idx: usize,
    proof: &[H::Hash],
    root: H::Hash,
) -> Result<(), VerifyError> {
    let (node, residual) = process_proof(hasher, leaf, leaf_idx, proof);
    if residual != 0 {
        Err(VerifyError::IndexOutOfRange)
    } else if node == root {
        Ok(())
    } else {
        Err(VerifyError::InvalidProof)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    IndexOutOfRange,
    InvalidProof,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            VerifyError::IndexOutOfRange => "leaf index out of range",
            VerifyError::InvalidProof => "proof does not match root",
        })
    }
}

impl core::error::Error for VerifyError {}
