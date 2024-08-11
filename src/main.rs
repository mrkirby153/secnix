mod cli;
mod enc;
mod fs;
mod manifest;
mod sops;
mod ssh;

use clap::Parser;

use anyhow::Result;
use cli::{Cli, Commands};
use tracing_subscriber;

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Check) => cli::check(cli),
        Some(Commands::Install) => cli::install(cli),
        None => cli::install(cli),
    }
}
