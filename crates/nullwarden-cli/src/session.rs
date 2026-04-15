use anyhow::Context;
use std::{fs, path::PathBuf};

pub fn save_access_token(token: &str) -> anyhow::Result<()> {
    let path = session_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, token).context("failed to save access token")
}

pub fn load_access_token() -> anyhow::Result<Option<String>> {
    let path = session_path();
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(
        fs::read_to_string(path).context("failed to load access token")?,
    ))
}

fn session_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("nullwarden")
        .join("session.token")
}
