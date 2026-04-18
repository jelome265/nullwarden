use crate::error::VaultError;
use crate::kdf::{derive_key, KdfParams, SALT_LEN};
use crate::types::VaultEncryptionKey;

pub struct VaultKeyDeriver;

impl VaultKeyDeriver {
    pub fn derive(
        password: &str,
        salt: &[u8; SALT_LEN],
        params: KdfParams,
    ) -> Result<VaultEncryptionKey, VaultError> {
        derive_key(password.as_bytes(), salt, params)
    }
}
