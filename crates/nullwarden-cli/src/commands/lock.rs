pub async fn run() -> anyhow::Result<()> {
    println!("NullWarden CLI uses a 'lock by exit' model.");
    println!("Since the CLI process terminates after each command, no key material persists in memory.");
    println!("The vault is implicitly locked upon command completion.");
    Ok(())
}
