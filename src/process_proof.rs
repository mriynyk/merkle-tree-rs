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
