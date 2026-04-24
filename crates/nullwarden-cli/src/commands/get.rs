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
        use tokio::time::{sleep, Duration};
        let mut cb = Clipboard::new().context("failed to access clipboard")?;
        cb.set_text(entry.password.0.clone())
            .context("failed to copy to clipboard")?;
        println!("Password copied to clipboard. Clearing it in 30 seconds if unchanged.");
        sleep(Duration::from_secs(30)).await;
        let mut cb = Clipboard::new().context("failed to re-open clipboard")?;
        if cb.get_text().ok().as_deref() == Some(entry.password.0.as_str()) {
            cb.set_text(String::new())
                .context("failed to clear clipboard after timeout")?;
            println!("Clipboard cleared.");
        } else {
            println!(
                "Clipboard changed before timeout; leaving current clipboard contents intact."
            );
        }
    }

    if let Some(notes) = &entry.notes {
        println!("notes: {notes}");
    }
    Ok(())
}
