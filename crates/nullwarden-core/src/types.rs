use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(pub String);

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(pub Vec<u8>);
