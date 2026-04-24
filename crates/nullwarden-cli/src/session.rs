use anyhow::Context;
use keyring::Entry;
use std::fs;
use std::path::PathBuf;
#[cfg(windows)]
use std::process::Command;

pub fn save_access_token(token: &str) -> anyhow::Result<()> {
    if let Err(e) = save_to_keyring("access_token", token) {
        eprintln!("Warning: failed to save to keyring, using file fallback: {e}");
        save_to_file("access_token", token)?;
    }
    Ok(())
}

pub fn load_access_token() -> anyhow::Result<String> {
    load_from_keyring("access_token")
        .or_else(|_| load_from_file("access_token"))
        .context("no active session. please login or register.")
}

pub fn clear_access_token() -> anyhow::Result<()> {
    let _ = clear_from_keyring("access_token");
    let _ = clear_from_file("access_token");
    Ok(())
}

pub fn save_refresh_token(token: &str) -> anyhow::Result<()> {
    if let Err(e) = save_to_keyring("refresh_token", token) {
        eprintln!("Warning: failed to save to keyring, using file fallback: {e}");
        save_to_file("refresh_token", token)?;
    }
    Ok(())
}

pub fn load_refresh_token() -> anyhow::Result<String> {
    load_from_keyring("refresh_token")
        .or_else(|_| load_from_file("refresh_token"))
        .context("no active session. please login or register.")
}

pub fn clear_refresh_token() -> anyhow::Result<()> {
    let _ = clear_from_keyring("refresh_token");
    let _ = clear_from_file("refresh_token");
    Ok(())
}

// Helpers

fn save_to_keyring(account: &str, secret: &str) -> anyhow::Result<()> {
    let entry = Entry::new("nullwarden", account).context("failed to create keyring entry")?;
    entry
        .set_password(secret)
        .context("failed to save to keyring")?;
    Ok(())
}

fn load_from_keyring(account: &str) -> anyhow::Result<String> {
    let entry = Entry::new("nullwarden", account).context("failed to create keyring entry")?;
    entry.get_password().context("not found in keyring")
}

fn clear_from_keyring(account: &str) -> anyhow::Result<()> {
    let entry = Entry::new("nullwarden", account).context("failed to create keyring entry")?;
    let _ = entry.delete_credential();
    Ok(())
}

fn session_file_path(account: &str) -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("nullwarden")
        .join(format!("{}.session", account))
}

fn save_to_file(account: &str, secret: &str) -> anyhow::Result<()> {
    let path = session_file_path(account);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::write(&path, secret)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&path, secret)?;
        #[cfg(windows)]
        tighten_windows_acl(&path)?;
    }

    Ok(())
}

fn load_from_file(account: &str) -> anyhow::Result<String> {
    let path = session_file_path(account);
    fs::read_to_string(path).context("failed to read session file")
}

fn clear_from_file(account: &str) -> anyhow::Result<()> {
    let path = session_file_path(account);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(windows)]
fn tighten_windows_acl(path: &std::path::Path) -> anyhow::Result<()> {
    let username = whoami::username();
    if username.trim().is_empty() {
        anyhow::bail!("failed to determine current username for session file ACL hardening");
    }

    let output = Command::new(r"C:\Windows\System32\icacls.exe")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{username}:F"))
        .output()
        .context("failed to invoke icacls for session file ACL hardening")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("icacls failed while securing session file permissions: {stderr}");
    }

    Ok(())
}
