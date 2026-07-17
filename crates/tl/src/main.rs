mod bootstrap;
mod tsl;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

const DEFAULT_CA_DIR: &str = "./data/ca";
const DEFAULT_OUT_DIR: &str = "./data/tl";

#[derive(Parser)]
#[command(
    name = "tl",
    about = "ETSI TS 119 612 Trusted List XML generator, listing the test Root CA from `ca bootstrap`"
)]
/// Top-level CLI parser (see the `Command` variants for what each
/// subcommand does).
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate the Trusted List XML from the Root CA certificate.
    Bootstrap {
        #[arg(long, default_value = DEFAULT_CA_DIR)]
        ca_dir: PathBuf,
        #[arg(long, default_value = DEFAULT_OUT_DIR)]
        out_dir: PathBuf,
        /// Overwrite an existing tl.xml instead of refusing.
        #[arg(long)]
        force: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Bootstrap {
            ca_dir,
            out_dir,
            force,
        } => bootstrap::run(&ca_dir, &out_dir, force),
    }
}
