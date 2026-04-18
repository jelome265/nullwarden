use crate::error::VaultError;
use crate::vault::data::VaultData;

pub struct VaultSerializer;

impl VaultSerializer {
    pub fn serialize(data: &VaultData) -> Result<Vec<u8>, VaultError> {
        rmp_serde::to_vec_named(data).map_err(|e| VaultError::Serialization(e.to_string()))
    }

    pub fn deserialize(bytes: &[u8]) -> Result<VaultData, VaultError> {
        rmp_serde::from_slice(bytes).map_err(|e| VaultError::Serialization(e.to_string()))
    }
}
