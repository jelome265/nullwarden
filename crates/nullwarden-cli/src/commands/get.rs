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
        println!("Password copied to clipboard. Clear it manually after use.");
    }


    if let Some(notes) = &entry.notes {
        println!("notes: {notes}");
    }

    // We need to wait a bit or the process might exit before the spawned task starts?
    // Actually, if the process exits, the clipboard content might remain depending on OS,
    // but the background clear task will die.
    // Password managers usually run a daemon or stay alive.
    // For now, I'll just print a message.

    Ok(())
}
