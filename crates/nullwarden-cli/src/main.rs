use clap::{Parser, Subcommand};
use nullwarden_cli::commands::{
    add, delete, export, get, init, list, lock, logout, migrate, pull, push, register, update,
};

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
    Update {
        title: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long)]
        clear_notes: bool,
    },
    Get {
        title: String,
        #[arg(long)]
        print: bool,
    },
    List,
    Delete {
        title: String,
    },
    Export {
        #[arg(long)]
        output: Option<std::path::PathBuf>,
    },
    Migrate {
        #[arg(long)]
        m_cost: Option<u32>,
        #[arg(long)]
        t_cost: Option<u32>,
        #[arg(long)]
        p_cost: Option<u32>,
    },
    Lock,
    Register {
        username: String,
        password: Option<String>,
    },
    Push,
    Pull,
    Logout,
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
        Command::Update {
            title,
            username,
            password,
            notes,
            clear_notes,
        } => update::run(title, username, password, notes, clear_notes).await?,
        Command::Get { title, print } => get::run(title, print).await?,
        Command::List => list::run().await?,
        Command::Delete { title } => delete::run(title).await?,
        Command::Export { output } => export::run(output).await?,
        Command::Migrate {
            m_cost,
            t_cost,
            p_cost,
        } => migrate::run(m_cost, t_cost, p_cost).await?,
        Command::Lock => lock::run().await?,
        Command::Register { username, password } => register::run(username, password).await?,
        Command::Push => push::run().await?,
        Command::Pull => pull::run().await?,
        Command::Logout => logout::run().await?,
    }
    Ok(())
}
