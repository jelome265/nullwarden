use crate::error::VaultError;
use crate::types::VaultEncryptionKey;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{rngs::OsRng, RngCore};

pub const SALT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 65_536,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

impl KdfParams {
    pub fn to_argon2(self) -> Result<Argon2<'static>, VaultError> {
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|e| VaultError::Serialization(e.to_string()))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0_u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn derive_key(password: &[u8], salt: &[u8; SALT_LEN], params: KdfParams) -> Result<VaultEncryptionKey, VaultError> {
    let argon2 = params.to_argon2()?;
    let mut key = [0_u8; KEY_LEN];
    argon2.hash_password_into(password, salt, &mut key)?;
    Ok(VaultEncryptionKey(key))
}
