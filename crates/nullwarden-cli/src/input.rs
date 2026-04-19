use anyhow::bail;
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
    let estimate = zxcvbn(password, &[]);
    if (estimate.score() as u8) < 3 {
        bail!(
            "password is too weak (score: {}/4). use a longer, more complex passphrase.",
            estimate.score() as u8
        );
    }
    Ok(())
}

pub fn prompt_choice(prompt: &str, choices: &[&str]) -> anyhow::Result<usize> {
    loop {
        print!("{prompt} ({}): ", choices.join("/"));
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();
        for (i, choice) in choices.iter().enumerate() {
            if input == choice.to_lowercase() {
                return Ok(i);
            }
        }
        println!(
            "Invalid choice. Please choose one of: {}",
            choices.join(", ")
        );
    }
}
