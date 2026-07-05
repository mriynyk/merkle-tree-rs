pub trait Hasher {
    type Hash: Copy + PartialEq;
    fn hash(&self, left: &Self::Hash, right: &Self::Hash) -> Self::Hash;
}
