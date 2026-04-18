use crate::error::VaultError;
use crate::types::SecretString;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultEntry {
    #[zeroize(skip)]
    pub id: Uuid,
    #[zeroize(skip)]
    pub title: String,
    #[zeroize(skip)]
    pub username: String,
    pub password: SecretString,
    #[zeroize(skip)]
    pub notes: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultData {
    #[zeroize(skip)]
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
            password: SecretString(password),
            notes,
        });
        self.version = self.version.saturating_add(1);
        Ok(id)
    }

    pub fn get_entry(&self, title: &str) -> Option<&VaultEntry> {
        self.entries.iter().find(|entry| entry.title == title)
    }

    pub fn update_entry(
        &mut self,
        title: &str,
        username: Option<String>,
        password: Option<String>,
        notes: Option<Option<String>>,
    ) -> Result<(), VaultError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.title == title)
            .ok_or(VaultError::EntryNotFound)?;

        if let Some(u) = username {
            entry.username = u;
        }
        if let Some(p) = password {
            entry.password = SecretString(p);
        }
        if let Some(n) = notes {
            entry.notes = n;
        }
        self.version = self.version.saturating_add(1);
        Ok(())
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
