pub async fn run() -> anyhow::Result<()> {
    println!("Vault lock is client-side only in the current prototype; secrets are dropped after each command.");
    Ok(())
}
