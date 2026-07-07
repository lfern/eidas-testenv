mod holder_key;
mod issue;
mod present;
mod sd_jwt;
mod serve;
mod storage;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "wallet",
    about = "EUDIW test wallet: OID4VCI issuance + OID4VP presentation"
)]
/// Top-level CLI parser (see the `Command` variants for what each
/// subcommand does).
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Obtain a credential from a pre-authorized OID4VCI credential offer.
    Issue {
        #[arg(long)]
        url: String,
    },
    /// Present a stored credential to an OID4VP verifier request.
    Present {
        #[arg(long)]
        url: String,
    },
    /// List credentials stored locally.
    List,
    /// Starts a local browser UI (127.0.0.1-only) mirroring
    /// issue/present/list, with server-side QR decoding of pasted images.
    Serve {
        #[arg(long, default_value_t = 7890)]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Dispatch straight to the module implementing each subcommand — no
    // shared setup needed here beyond clap's own parsing.
    match cli.command {
        Command::Issue { url } => issue::run(&url).await,
        Command::Present { url } => present::run(&url).await,
        Command::List => storage::list_and_print(),
        Command::Serve { port } => serve::run(port).await,
    }
}
