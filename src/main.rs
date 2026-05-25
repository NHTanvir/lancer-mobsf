//! lancer-mobsf
//! Rust clone of mobsf. See plan.md (local, gitignored) for the spec.

use clap::{Parser, Subcommand};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;

pub mod api;
pub mod db;
pub mod dynamic;
pub mod masvs;
pub mod report;
pub mod scanner;
pub mod upload;
pub mod ws;

/// Shared application state passed to all handlers.
pub struct AppState {
    pub db: db::DbPool,
    pub broadcast_tx: broadcast::Sender<String>,
}

#[derive(Parser, Debug)]
#[command(name = "lancer-mobsf", version, about = "Rust clone of mobsf")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the web server (default)
    Serve {
        /// Port to listen on
        #[arg(long, default_value_t = 7777)]
        port: u16,

        /// Path to the SQLite database file
        #[arg(long, default_value = "data/mobsf.db")]
        db: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Default to the Serve subcommand if none given
    let command = cli.command.unwrap_or(Commands::Serve {
        port: 7777,
        db: "data/mobsf.db".to_string(),
    });

    match command {
        Commands::Serve { port, db } => {
            run_server(port, &db).await?;
        }
    }

    Ok(())
}

async fn run_server(port: u16, db_path: &str) -> anyhow::Result<()> {
    info!("Initialising database at {}", db_path);
    let pool = db::init_db(db_path).await?;

    let (broadcast_tx, _) = broadcast::channel::<String>(256);

    let state = Arc::new(AppState {
        db: pool,
        broadcast_tx,
    });

    use axum::extract::DefaultBodyLimit;
    use axum::routing::{get, post};
    let router = axum::Router::new()
        // Upload
        .route("/api/upload", post(upload::upload_handler))
        // Scan queries
        .route("/api/scans", get(api::list_scans_handler))
        .route("/api/scan/:id", get(api::get_scan_handler))
        .route("/api/scan/:id/findings", get(api::get_findings_handler))
        // Reports
        .route("/api/scan/:id/report", get(api::get_report_html_handler))
        .route("/api/scan/:id/report.json", get(api::get_report_json_handler))
        .route("/api/scan/:id/report.pdf", get(api::get_report_pdf_handler))
        // WebSocket
        .route("/ws/scan/:scan_id", get(ws::ws_handler))
        .layer(DefaultBodyLimit::max(500 * 1024 * 1024))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("lancer-mobsf listening on http://{}", addr);

    axum::serve(listener, router).await?;

    Ok(())
}
