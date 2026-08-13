mod serve;
mod sign;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

const DEFAULT_CA_DIR: &str = "./data/ca";
const DEFAULT_PORT: u16 = 8090;
// Matches `tsa`'s own DEFAULT_PORT (crates/tsa/src/main.rs) — the two
// crates aren't linked, so this is duplicated, not imported.
const DEFAULT_TSA_URL: &str = "http://127.0.0.1:2560/";

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
    /// Starts a local browser UI (127.0.0.1-only) for CAdES B-B/B-T signing.
    Serve {
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
        #[arg(long, default_value = DEFAULT_CA_DIR)]
        ca_dir: PathBuf,
        /// Base URL of a running `tsa serve`, used only for B-T signatures.
        #[arg(long, default_value = DEFAULT_TSA_URL)]
        tsa_url: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve {
            port,
            ca_dir,
            tsa_url,
        } => serve::run(port, ca_dir, tsa_url).await,
    }
}
