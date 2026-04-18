use crate::{
    error::VaultError,
    kdf::{generate_salt, KdfParams},
    types::VaultNonce,
    vault::{header::VaultHeader, VaultCipher, VaultData, VaultKeyDeriver, VaultSerializer},
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
        self.unlock_bytes(password, &bytes)
    }

    pub fn unlock_bytes(&self, password: &str, bytes: &[u8]) -> Result<VaultData, VaultError> {
        let (header, offset) = VaultHeader::decode(bytes).ok_or(VaultError::InvalidFormat)?;
        let params = KdfParams {
            m_cost: header.m_cost,
            t_cost: header.t_cost,
            p_cost: header.p_cost,
        };
        let key = VaultKeyDeriver::derive(password, &header.salt, params)?;
        let nonce = VaultNonce(header.nonce);
        let plaintext = VaultCipher::decrypt(&key, &nonce, &bytes[offset..])?;
        VaultSerializer::deserialize(&plaintext)
    }

    pub fn save(&self, password: &str, data: &VaultData) -> Result<(), VaultError> {
        let salt = generate_salt();
        let key = VaultKeyDeriver::derive(password, &salt, self.params)?;
        let plaintext = VaultSerializer::serialize(data)?;
        let (nonce, ciphertext) = VaultCipher::encrypt(&key, &plaintext)?;

        let header = VaultHeader {
            format_version: VaultHeader::FORMAT_VERSION,
            m_cost: self.params.m_cost,
            t_cost: self.params.t_cost,
            p_cost: self.params.p_cost,
            salt,
            nonce: nonce.0,
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
    {
        use std::io::Write;
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
    }
    fs::rename(tmp_path, path)?;
    Ok(())
}
