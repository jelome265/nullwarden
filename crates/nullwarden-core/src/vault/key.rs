use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultKey(pub [u8; 32]);

impl AsRef<[u8; 32]> for VaultKey {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}
