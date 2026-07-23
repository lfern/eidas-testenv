mod serve;
mod sign;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

const DEFAULT_CA_DIR: &str = "./data/ca";
const DEFAULT_PORT: u16 = 8090;

#[derive(Parser)]
#[command(
    name = "portal",
    about = "AdES signing demo portal: sign an uploaded file with a `ca bootstrap`-issued certificate"
)]
/// Top-level CLI parser (see the `Command` variants for what each
/// subcommand does).
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Starts a local browser UI (127.0.0.1-only) for CAdES B-B signing.
    Serve {
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
        #[arg(long, default_value = DEFAULT_CA_DIR)]
        ca_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { port, ca_dir } => serve::run(port, ca_dir).await,
    }
}
