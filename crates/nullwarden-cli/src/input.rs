use anyhow::{anyhow, bail};
use std::io::{self, Write};
use zxcvbn::zxcvbn;

pub fn prompt_password(label: &str) -> anyhow::Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;
    let password = rpassword::read_password()?;
    if password.is_empty() {
        bail!("empty password is not allowed");
    }
    Ok(password)
}

pub fn validate_password_strength(password: &str) -> anyhow::Result<()> {
    let estimate = zxcvbn(password, &[]).map_err(|e| anyhow!(e.to_string()))?;
    if estimate.score() < 3 {
        bail!("password is too weak (score: {}/4). use a longer, more complex passphrase.", estimate.score());
    }
    Ok(())
}
