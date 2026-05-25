//! lancer-mobsf
//! Rust clone of mobsf. See plan.md (local, gitignored) for the spec.

use clap::Parser;

pub mod api;
pub mod db;
pub mod dynamic;
pub mod masvs;
pub mod report;
pub mod scanner;
pub mod upload;
pub mod ws;

#[derive(Parser, Debug)]
#[command(name = "lancer-mobsf", version, about = "Rust clone of mobsf")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-mobsf - scaffold ready. Implement per plan.md.");
    Ok(())
}
