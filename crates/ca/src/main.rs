mod bootstrap;
mod list;
mod storage;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

const DEFAULT_OUT_DIR: &str = "./data/ca";

#[derive(Parser)]
#[command(
    name = "ca",
    about = "Static test PKI generator: Root CA, Sub-CA, TSA, OCSP, and user (signing) certificates"
)]
/// Top-level CLI parser (see the `Command` variants for what each
/// subcommand does).
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate the full test PKI chain (root, sub-ca, tsa, ocsp, user
    /// certs) and write it to disk.
    Bootstrap {
        #[arg(long, default_value = DEFAULT_OUT_DIR)]
        out_dir: PathBuf,
        /// Overwrite an existing, non-empty out-dir instead of refusing.
        #[arg(long)]
        force: bool,
    },
    /// List the certificates already generated under out-dir.
    List {
        #[arg(long, default_value = DEFAULT_OUT_DIR)]
        out_dir: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Bootstrap { out_dir, force } => bootstrap::run(&out_dir, force),
        Command::List { out_dir } => list::run(&out_dir),
    }
}
