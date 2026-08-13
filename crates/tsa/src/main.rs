mod asn1;
mod serve;
mod token;

use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

const DEFAULT_CA_DIR: &str = "./data/ca";
const DEFAULT_PORT: u16 = 2560;
const DEFAULT_HOST: &str = "127.0.0.1";

#[derive(Parser)]
#[command(
    name = "tsa",
    about = "RFC 3161 timestamp authority responder, signing with the `tsa` identity `ca bootstrap` issues"
)]
/// Top-level CLI parser (see the `Command` variants for what each
/// subcommand does).
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Starts the TSA HTTP responder.
    Serve {
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
        /// Defaults to 127.0.0.1; pass 0.0.0.0 for Docker (see serve.rs).
        #[arg(long, default_value = DEFAULT_HOST)]
        host: IpAddr,
        #[arg(long, default_value = DEFAULT_CA_DIR)]
        ca_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { port, host, ca_dir } => serve::run(host, port, ca_dir).await,
    }
}
