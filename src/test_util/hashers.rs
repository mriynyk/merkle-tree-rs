use core::cell::Cell;

use sha2::{Digest, Sha256};

use crate::Hasher;

pub(crate) struct PositionalSha256 {
    hash_count: Cell<usize>,
}

impl PositionalSha256 {
    pub(crate) fn new() -> Self {
        Self {
            hash_count: Cell::new(0),
        }
    }
}

impl Hasher for PositionalSha256 {
    type Hash = super::Hash;

    fn hash(&self, left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        self.record_hash();

        let mut h = Sha256::new();

        h.update(left);
        h.update(right);
        h.finalize().into()
    }
}

impl TrackHashes for PositionalSha256 {
    fn hash_counter(&self) -> &Cell<usize> {
        &self.hash_count
    }
}

pub(crate) struct CommutativeSha256 {
    hash_count: Cell<usize>,
}

impl CommutativeSha256 {
    pub(crate) fn new() -> Self {
        Self {
            hash_count: Cell::new(0),
        }
    }
}

impl Hasher for CommutativeSha256 {
    type Hash = super::Hash;

    fn hash(&self, left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        self.record_hash();

        let (low, high) = if left <= right {
            (left, right)
        } else {
            (right, left)
        };

        let mut h = Sha256::new();

        h.update(low);
        h.update(high);
        h.finalize().into()
    }
}

impl TrackHashes for CommutativeSha256 {
    fn hash_counter(&self) -> &Cell<usize> {
        &self.hash_count
    }
}

pub(crate) trait TrackHashes {
    fn hash_counter(&self) -> &Cell<usize>;

    fn record_hash(&self) {
        self.hash_counter().set(self.hash_count() + 1);
    }

    fn hash_count(&self) -> usize {
        self.hash_counter().get()
    }

    fn reset_hash_count(&self) {
        self.hash_counter().set(0);
    }
}
