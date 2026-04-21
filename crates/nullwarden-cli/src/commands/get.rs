use crate::{config::Config, input::prompt_password};
use anyhow::Context;
use nullwarden_core::vault::VaultStore;

pub async fn run(title: String, print: bool) -> anyhow::Result<()> {
    let config = Config::load()?;
    let password = prompt_password("Master password")?;
    let store = VaultStore::new(&config.vault_path);
    let vault = store.unlock(&password).context("failed to unlock vault")?;
    let entry = vault
        .get_entry(&title)
        .with_context(|| format!("entry `{title}` not found"))?;

    println!("title: {}", entry.title);
    println!("username: {}", entry.username);

    if print {
        println!("password: {}", entry.password.0);
    } else {
        use arboard::Clipboard;
        let mut cb = Clipboard::new().context("failed to access clipboard")?;
        cb.set_text(entry.password.0.clone())
            .context("failed to copy to clipboard")?;
        println!("Password copied to clipboard. If you use a clipboard manager, clear its history after use.");
    }

    if let Some(notes) = &entry.notes {
        println!("notes: {notes}");
    }
    Ok(())
}
