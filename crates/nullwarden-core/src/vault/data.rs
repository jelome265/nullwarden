use crate::error::VaultError;
use crate::types::{secret_string_wire, SecretString};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_TITLE_LEN: usize = 256;
const MAX_USERNAME_LEN: usize = 256;
const MAX_PASSWORD_LEN: usize = 1024;
const MAX_NOTES_LEN: usize = 8 * 1024;

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultEntry {
    #[zeroize(skip)]
    pub id: Uuid,
    pub title: String,
    pub username: String,
    #[serde(with = "secret_string_wire")]
    pub password: SecretString,
    pub notes: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultData {
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
        validate_entry_fields(&title, &username, &password, notes.as_deref())?;
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

        let next_username = username.as_deref().unwrap_or(entry.username.as_str());
        let next_password = password.as_deref().unwrap_or(entry.password.0.as_str());
        let next_notes = notes
            .as_ref()
            .map(|notes| notes.as_deref())
            .unwrap_or(entry.notes.as_deref());
        validate_entry_fields(title, next_username, next_password, next_notes)?;

        if let Some(u) = username {
            entry.username = u;
        }
        if let Some(p) = password {
            entry.password = SecretString(p);
        }
        if let Some(n) = notes {
            entry.notes = n;
        }
        Ok(())
    }

    pub fn delete_entry(&mut self, title: &str) -> Result<(), VaultError> {
        let before = self.entries.len();
        self.entries.retain(|entry| entry.title != title);
        if self.entries.len() == before {
            return Err(VaultError::EntryNotFound);
        }
        Ok(())
    }
}

fn validate_entry_fields(
    title: &str,
    username: &str,
    password: &str,
    notes: Option<&str>,
) -> Result<(), VaultError> {
    if title.is_empty() || title.chars().count() > MAX_TITLE_LEN {
        return Err(VaultError::Serialization(format!(
            "title must be between 1 and {MAX_TITLE_LEN} characters"
        )));
    }
    if username.is_empty() || username.chars().count() > MAX_USERNAME_LEN {
        return Err(VaultError::Serialization(format!(
            "username must be between 1 and {MAX_USERNAME_LEN} characters"
        )));
    }
    if password.is_empty() || password.chars().count() > MAX_PASSWORD_LEN {
        return Err(VaultError::Serialization(format!(
            "password must be between 1 and {MAX_PASSWORD_LEN} characters"
        )));
    }
    if let Some(notes) = notes {
        if notes.chars().count() > MAX_NOTES_LEN {
            return Err(VaultError::Serialization(format!(
                "notes must be at most {MAX_NOTES_LEN} characters"
            )));
        }
    }
    Ok(())
}
