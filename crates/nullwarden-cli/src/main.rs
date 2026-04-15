mod client;
mod commands;
mod config;
mod error;
mod input;
mod session;

use clap::{Parser, Subcommand};
use commands::{add, delete, get, init, list, lock, pull, push, register};

#[derive(Parser)]
#[command(name = "nullwarden")]
#[command(about = "Zero-knowledge password vault CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Init,
    Add {
        title: String,
        username: String,
        password: Option<String>,
        #[arg(long)]
        notes: Option<String>,
    },
    Get {
        title: String,
    },
    List,
    Delete {
        title: String,
    },
    Lock,
    Register {
        username: String,
        password: Option<String>,
    },
    Push,
    Pull,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init => init::run().await?,
        Command::Add {
            title,
            username,
            password,
            notes,
        } => add::run(title, username, password, notes).await?,
        Command::Get { title } => get::run(title).await?,
        Command::List => list::run().await?,
        Command::Delete { title } => delete::run(title).await?,
        Command::Lock => lock::run().await?,
        Command::Register { username, password } => register::run(username, password).await?,
        Command::Push => push::run().await?,
        Command::Pull => pull::run().await?,
    }
    Ok(())
}
