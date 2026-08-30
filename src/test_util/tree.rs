use crate::Hasher;

use super::Hash;

pub(crate) const PADDING: Hash = [0; 32];

pub(crate) fn build_leaves<const LEAVES: usize>() -> [Hash; LEAVES] {
    const { assert!(LEAVES <= u8::MAX as usize, "LEAVES must fit in a byte to stay distinct") }

    core::array::from_fn(|idx| [idx as u8 + 1; 32])
}

pub(crate) fn pad_leaves<const LEAVES: usize, const PADDED: usize>(
    leaves: &[Hash; LEAVES],
    padding: Hash,
) -> [Hash; PADDED] {
    const {
        assert!(PADDED.is_power_of_two(), "PADDED must be a power of two");
        assert!(PADDED >= LEAVES, "PADDED must not be smaller than LEAVES");
        assert!(PADDED / 2 < LEAVES, "PADDED must be the next power of two after LEAVES");
    }

    let mut padded = [padding; PADDED];

    padded[..LEAVES].copy_from_slice(leaves);

    padded
}

pub(crate) fn build_tree<H: Hasher<Hash = Hash>, const LEAVES: usize, const NODES: usize>(
    hasher: &H,
    leaves: [Hash; LEAVES],
) -> [Hash; NODES] {
    const {
        assert!(LEAVES.is_power_of_two(), "LEAVES must be a power of two");
        assert!(NODES == 2 * LEAVES - 1, "NODES must be 2 * LEAVES - 1");
    }

    let mut tree = [Hash::default(); NODES];

    tree[..LEAVES].copy_from_slice(&leaves);

    for idx in LEAVES..NODES {
        let left_idx = (idx - LEAVES) * 2;

        let left = tree[left_idx];
        let right = tree[left_idx + 1];

        tree[idx] = hasher.hash(&left, &right);
    }

    tree
}

pub(crate) fn root_of<const NODES: usize>(tree: &[Hash; NODES]) -> Hash {
    const { assert!(NODES > 0, "NODES must not be zero") }

    tree[NODES - 1]
}

pub(crate) fn build_proof<const NODES: usize, const HEIGHT: usize>(
    tree: &[Hash; NODES],
    leaf_idx: usize,
) -> [Hash; HEIGHT] {
    const { assert!(NODES == 2 * (1 << HEIGHT) - 1, "NODES must be 2 * 2^HEIGHT - 1") }

    let leaf_count = 1 << HEIGHT;

    assert!(leaf_idx < leaf_count, "leaf_idx must be below the leaf count");

    let mut proof = [Hash::default(); HEIGHT];

    let mut offset = 0;
    let mut level_len = leaf_count;

    for (level, sibling) in proof.iter_mut().enumerate() {
        *sibling = tree[offset + ((leaf_idx >> level) ^ 1)];

        offset += level_len;
        level_len /= 2;
    }

    proof
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::PositionalSha256;

    #[test]
    fn build_tree_lays_the_levels_out_bottom_up() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 4] = build_leaves();
        let parent_01 = hasher.hash(&leaves[0], &leaves[1]);
        let parent_23 = hasher.hash(&leaves[2], &leaves[3]);
        let root = hasher.hash(&parent_01, &parent_23);

        #[rustfmt::skip]
        let expected = [
            leaves[0], leaves[1], leaves[2], leaves[3],
            parent_01, parent_23,
            root,
        ];

        let tree: [Hash; 7] = build_tree(&hasher, leaves);

        assert_eq!(tree, expected);
        assert_eq!(root_of(&tree), root);
    }

    #[test]
    fn build_tree_hashes_the_padding_like_a_leaf() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 3] = build_leaves();
        let leaves_padded: [Hash; 4] = pad_leaves(&leaves, PADDING);
        let parent_01 = hasher.hash(&leaves[0], &leaves[1]);
        let parent_2pad = hasher.hash(&leaves[2], &PADDING);
        let root = hasher.hash(&parent_01, &parent_2pad);

        #[rustfmt::skip]
        let expected = [
            leaves[0], leaves[1], leaves[2], PADDING,
            parent_01, parent_2pad,
            root,
        ];

        let tree: [Hash; 7] = build_tree(&hasher, leaves_padded);

        assert_eq!(tree, expected);
    }

    #[test]
    fn build_proof_takes_the_sibling_at_every_level() {
        let hasher = PositionalSha256::new();
        let leaves: [Hash; 8] = build_leaves();
        let tree: [Hash; 15] = build_tree(&hasher, leaves);

        let proof_for_leaf_0: [Hash; 3] = build_proof(&tree, 0);
        let proof_for_leaf_5: [Hash; 3] = build_proof(&tree, 5);

        assert_eq!(proof_for_leaf_0, [tree[1], tree[9], tree[13]], "leaf 0");
        assert_eq!(proof_for_leaf_5, [tree[4], tree[11], tree[12]], "leaf 5");
    }
}
