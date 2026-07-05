use crate::Hasher;

pub fn process_proof<H: Hasher>(
    hasher: &H,
    leaf: H::Hash,
    mut leaf_idx: usize,
    proof: &[H::Hash],
) -> (H::Hash, usize) {
    let mut node = leaf;

    for sibling in proof {
        node = if (leaf_idx & 1) == 0 {
            hasher.hash(&node, sibling)
        } else {
            hasher.hash(sibling, &node)
        };

        leaf_idx >>= 1;
    }

    (node, leaf_idx)
}
