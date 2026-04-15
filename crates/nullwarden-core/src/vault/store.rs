use crate::{
    crypto,
    error::VaultError,
    kdf::{derive_key, generate_salt, KdfParams},
    vault::{header::VaultHeader, VaultData, VaultKey},
};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub struct VaultStore {
    path: PathBuf,
    params: KdfParams,
}

impl VaultStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            params: KdfParams::default(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn init(&self, password: &str) -> Result<VaultData, VaultError> {
        let data = VaultData::default();
        self.save(password, &data)?;
        Ok(data)
    }

    pub fn unlock(&self, password: &str) -> Result<VaultData, VaultError> {
        let bytes = fs::read(&self.path)?;
        let (header, offset) = VaultHeader::decode(&bytes).ok_or(VaultError::InvalidFormat)?;
        let params = KdfParams {
            m_cost: header.m_cost,
            t_cost: header.t_cost,
            p_cost: header.p_cost,
        };
        let key = derive_key(password.as_bytes(), &header.salt, params)?;
        let plaintext = crypto::decrypt(&key, &header.nonce, &bytes[offset..])?;
        rmp_serde::from_slice(&plaintext).map_err(|e| VaultError::Serialization(e.to_string()))
    }

    pub fn save(&self, password: &str, data: &VaultData) -> Result<(), VaultError> {
        let salt = generate_salt();
        let key = VaultKey(derive_key(password.as_bytes(), &salt, self.params)?);
        let plaintext =
            rmp_serde::to_vec_named(data).map_err(|e| VaultError::Serialization(e.to_string()))?;
        let (nonce, ciphertext) = crypto::encrypt(key.as_ref(), &plaintext)?;
        let header = VaultHeader {
            format_version: VaultHeader::FORMAT_VERSION,
            m_cost: self.params.m_cost,
            t_cost: self.params.t_cost,
            p_cost: self.params.p_cost,
            salt,
            nonce,
        };
        let mut file = header.encode();
        file.extend_from_slice(&ciphertext);
        atomic_write(&self.path, &file)
    }
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, data)?;
    fs::rename(tmp_path, path)?;
    Ok(())
}
