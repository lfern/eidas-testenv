mod identity;
mod jwe;
mod request;
mod response;
mod serve;

use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use url::Url;

const DEFAULT_PORT: u16 = 9090;
const DEFAULT_HOST: &str = "127.0.0.1";

#[derive(Parser)]
#[command(
    name = "verifier",
    about = "OID4VP verifier (relying party): requests a PID presentation and checks the response"
)]
/// Top-level CLI parser (see the `Command` variants for what each
/// subcommand does).
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Starts the verifier HTTP server.
    Serve {
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
        #[arg(long, default_value = DEFAULT_HOST)]
        host: IpAddr,
        /// Directory holding this verifier's self-signed identity
        /// (generated on first run). Defaults to
        /// `~/.eidas-testenv/verifier`.
        #[arg(long)]
        identity_dir: Option<PathBuf>,
        /// Base URL other processes (the wallet) reach this server at —
        /// used to build the absolute request/response-submission URLs
        /// embedded in the signed request. Defaults to
        /// `http://<host>:<port>/`.
        #[arg(long)]
        external_url: Option<Url>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve {
            port,
            host,
            identity_dir,
            external_url,
        } => {
            let identity_dir = match identity_dir {
                Some(dir) => dir,
                None => identity::default_dir()?,
            };
            let external_url = match external_url {
                Some(url) => url,
                None => Url::parse(&format!("http://{host}:{port}/"))?,
            };
            serve::run(host, port, identity_dir, external_url).await
        }
    }
}
