use crate::error::VaultError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: Uuid,
    pub title: String,
    pub username: String,
    pub password: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultData {
    pub version: u64,
    pub entries: Vec<VaultEntry>,
}

impl VaultData {
    pub fn add_entry(
        &mut self,
        title: String,
        username: String,
        password: String,
        notes: Option<String>,
    ) -> Result<Uuid, VaultError> {
        if self.entries.iter().any(|entry| entry.title == title) {
            return Err(VaultError::DuplicateEntry);
        }
        let id = Uuid::new_v4();
        self.entries.push(VaultEntry {
            id,
            title,
            username,
            password,
            notes,
        });
        self.version = self.version.saturating_add(1);
        Ok(id)
    }

    pub fn get_entry(&self, title: &str) -> Option<&VaultEntry> {
        self.entries.iter().find(|entry| entry.title == title)
    }

    pub fn delete_entry(&mut self, title: &str) -> Result<(), VaultError> {
        let before = self.entries.len();
        self.entries.retain(|entry| entry.title != title);
        if self.entries.len() == before {
            return Err(VaultError::EntryNotFound);
        }
        self.version = self.version.saturating_add(1);
        Ok(())
    }
}
