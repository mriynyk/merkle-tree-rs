/// Combines two child hashes into their parent hash.
///
/// An implementation may hold configuration or state; any state it mutates must sit
/// behind interior mutability.
///
/// An implementation may treat the two inputs *positionally* (argument order matters) or
/// *commutatively* (argument order is ignored, so `hash(a, b) == hash(b, a)`).
pub trait Hasher {
    /// The hash of a tree node, whether leaf or internal.
    ///
    /// `Copy` keeps hashes cheap to pass around; `Eq` lets them be compared when
    /// verifying the tree.
    type Hash: Copy + Eq;

    /// Combines the left and right child hashes into their parent hash.
    ///
    /// Must be deterministic: equal inputs always yield equal output. `left` is the hash
    /// of the lower-index child and `right` the hash of the higher-index child.
    fn hash(&self, left: &Self::Hash, right: &Self::Hash) -> Self::Hash;
}
