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

    /// Scan an APK or IPA file and print findings
    Scan {
        /// Path to the .apk or .ipa file
        file: String,

        /// Directory to write working files into (default: system temp dir)
        #[arg(long)]
        output_dir: Option<String>,

        /// Output format: json | html | text
        #[arg(long, default_value = "text")]
        format: String,

        /// Write output to this file instead of stdout
        #[arg(long)]
        out: Option<String>,
    },

    /// Retrieve and print a report for a completed scan
    Report {
        /// Scan UUID (as returned by the upload API)
        scan_id: String,

        /// Output format: json | html | pdf
        #[arg(long, default_value = "json")]
        format: String,

        /// Write output to this file instead of stdout
        #[arg(long)]
        out: Option<String>,

        /// Path to the SQLite database file
        #[arg(long, default_value = "data/mobsf.db")]
        db: String,
    },

    /// List recent scans stored in the database
    List {
        /// Path to the SQLite database file
        #[arg(long, default_value = "data/mobsf.db")]
        db: String,
    },

    /// Show version information
    Version,
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
        Commands::Scan {
            file,
            output_dir,
            format,
            out,
        } => {
            run_scan_cli(&file, output_dir.as_deref(), &format, out.as_deref()).await?;
        }
        Commands::Report {
            scan_id,
            format,
            out,
            db,
        } => {
            run_report_cli(&scan_id, &format, out.as_deref(), &db).await?;
        }
        Commands::List { db } => {
            run_list_cli(&db).await?;
        }
        Commands::Version => {
            println!("lancer-mobsf v{}", env!("CARGO_PKG_VERSION"));
            println!("Description: {}", env!("CARGO_PKG_DESCRIPTION"));
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
    use axum::routing::{delete, get, post};
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
        // AI triage + CVE
        .route("/api/scan/:id/triage", post(api::post_triage_handler))
        .route("/api/scan/:id/cves", get(api::get_cves_handler))
        // Frida script generation
        .route("/api/scan/:id/generate-frida", post(api::generate_frida_handler))
        .route("/api/scan/:id/frida-scripts", get(api::list_frida_scripts_handler))
        .route("/api/scan/:id/frida-scripts/:filename", get(api::get_frida_script_handler))
        // WebSocket
        .route("/ws/scan/:scan_id", get(ws::ws_handler))
        // Dynamic analysis
        .route("/api/devices", get(api::list_devices_handler))
        .route("/api/dynamic/start", post(api::start_dynamic_handler))
        .route("/api/dynamic/:scan_id/screenshot", get(api::get_screenshot_handler))
        .route("/api/dynamic/:scan_id/traffic", get(api::get_traffic_handler))
        .route("/api/dynamic/:scan_id/screenshots", get(api::list_screenshots_handler))
        .route("/api/dynamic/:scan_id/screenshots/:filename", get(api::get_named_screenshot_handler))
        // MobSF-compatible v1 API
        .route("/api/v1/upload", post(api::v1_upload_handler))
        .route("/api/v1/scan", post(api::v1_scan_handler))
        .route("/api/v1/report_json", get(api::v1_report_json_handler))
        .route("/api/v1/scorecard", get(api::v1_scorecard_handler))
        .route("/api/v1/scans", get(api::v1_list_scans_handler))
        .route("/api/v1/delete_scan", delete(api::v1_delete_scan_handler))
        .route("/api/v1/download_pdf", get(api::v1_download_pdf_handler))
        .layer(DefaultBodyLimit::max(500 * 1024 * 1024))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("lancer-mobsf listening on http://{}", addr);

    axum::serve(listener, router).await?;

    Ok(())
}

/// Run the `scan` CLI subcommand.
async fn run_scan_cli(
    file_path: &str,
    output_dir: Option<&str>,
    format: &str,
    out_path: Option<&str>,
) -> anyhow::Result<()> {
    use sha2::{Digest, Sha256};

    let path = std::path::Path::new(file_path);
    if !path.exists() {
        anyhow::bail!("File not found: {}", file_path);
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    if ext != "apk" && ext != "ipa" {
        anyhow::bail!("Only .apk and .ipa files are supported");
    }

    // Compute SHA-256
    let file_bytes = tokio::fs::read(file_path).await?;
    let sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(&file_bytes);
        hex::encode(hasher.finalize())
    };

    // Generate scan ID
    let scan_id = uuid::Uuid::new_v4().to_string();

    // Set up a temporary working directory
    let work_base = if let Some(dir) = output_dir {
        std::path::PathBuf::from(dir)
    } else {
        std::env::temp_dir().join(format!("lancer-mobsf-{}", scan_id))
    };
    tokio::fs::create_dir_all(&work_base).await?;

    // Copy the file into the work dir so scanners can find it
    let dest_file = work_base.join(path.file_name().unwrap_or_default());
    tokio::fs::copy(file_path, &dest_file).await?;

    // Initialise a temporary DB
    let db_path = work_base.join("scan.db");
    let db_path_str = db_path.to_string_lossy().to_string();
    let pool = db::init_db(&db_path_str).await?;

    // Insert scan row
    let now = chrono::Utc::now().to_rfc3339();
    let scan_row = db::Scan {
        id: scan_id.clone(),
        filename: path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string(),
        file_type: ext.clone(),
        sha256: sha256.clone(),
        status: db::ScanStatus::Pending.as_str().to_string(),
        created_at: now.clone(),
        updated_at: now,
    };
    db::insert_scan(&pool, &scan_row).await?;

    // Broadcast sink (no WS consumers in CLI mode)
    let (progress_tx, _) = broadcast::channel::<String>(64);

    // Run the scanner
    let work_dir = work_base.join("work");
    tokio::fs::create_dir_all(&work_dir).await?;

    // Also create the uploads/<scan_id> dir so result.json is written there
    let upload_dir = format!("uploads/{}", scan_id);
    tokio::fs::create_dir_all(&upload_dir).await?;

    let has_critical: bool;
    let output_content: String;

    if ext == "apk" {
        let result =
            scanner::android::scan_apk(&dest_file, &work_dir, &scan_id, &pool, &progress_tx)
                .await?;

        has_critical = result.finding_counts.critical > 0;

        output_content = match format {
            "json" => serde_json::to_string_pretty(&result)?,
            "html" => {
                let masvs = result
                    .masvs_report
                    .clone()
                    .unwrap_or_else(|| masvs::compute_masvs_score(&result.findings));
                report::render_html_report_with_masvs(&result, &masvs)?
            }
            _ => format_text_report_android(&result),
        };
    } else {
        let result =
            scanner::ios::scan_ipa(&dest_file, &work_dir, &scan_id, &pool, &progress_tx).await?;

        has_critical = result.finding_counts.critical > 0;

        output_content = match format {
            "json" => serde_json::to_string_pretty(&result)?,
            "html" => {
                let masvs = result
                    .masvs_report
                    .clone()
                    .unwrap_or_else(|| masvs::compute_masvs_score(&result.findings));
                report::render_ios_html_report(&result, &masvs)?
            }
            _ => format_text_report_ios(&result),
        };
    }

    // Write or print
    if let Some(out_file) = out_path {
        tokio::fs::write(out_file, &output_content).await?;
    } else {
        print!("{}", output_content);
    }

    // Clean up temp dir (best-effort)
    let _ = tokio::fs::remove_dir_all(&work_base).await;
    let _ = tokio::fs::remove_dir_all(&upload_dir).await;

    // Exit 1 if critical findings found
    if has_critical {
        std::process::exit(1);
    }

    Ok(())
}

fn format_text_report_android(result: &scanner::android::AndroidScanResult) -> String {
    let mut out = String::new();
    out.push_str("=== lancer-mobsf scan report ===\n");
    out.push_str(&format!("File:     {}\n", result.scan_id));
    out.push_str(&format!("Package:  {}\n", result.package_name));
    out.push_str(&format!("SHA256:   {}\n", result.sha256));
    out.push_str(&format!("Scan ID:  {}\n", result.scan_id));
    out.push('\n');

    let counts = &result.finding_counts;
    out.push_str(&format_findings_by_severity(&result.findings));

    let masvs_pct = result
        .masvs_report
        .as_ref()
        .map(|m| (m.overall_score * 100.0).round() as u8)
        .unwrap_or(0);

    out.push_str(&format!("\nMAVS Score: {}%\n", masvs_pct));
    out.push_str(&format!(
        "Total findings: {} ({} critical, {} high, {} medium, {} low, {} info)\n",
        counts.total,
        counts.critical,
        counts.high,
        counts.medium,
        counts.low,
        counts.info
    ));
    out.push_str(&format!("Risk Score: {}/100\n", result.risk_score));
    out
}

fn format_text_report_ios(result: &scanner::ios::IosScanResult) -> String {
    let mut out = String::new();
    out.push_str("=== lancer-mobsf scan report ===\n");
    out.push_str(&format!("File:     {}\n", result.scan_id));
    out.push_str(&format!("Bundle:   {}\n", result.bundle_id));
    out.push_str(&format!("SHA256:   {}\n", result.sha256));
    out.push_str(&format!("Scan ID:  {}\n", result.scan_id));
    out.push('\n');

    let counts = &result.finding_counts;
    out.push_str(&format_findings_by_severity(&result.findings));

    let masvs_pct = result
        .masvs_report
        .as_ref()
        .map(|m| (m.overall_score * 100.0).round() as u8)
        .unwrap_or(0);

    out.push_str(&format!("\nMAVS Score: {}%\n", masvs_pct));
    out.push_str(&format!(
        "Total findings: {} ({} critical, {} high, {} medium, {} low, {} info)\n",
        counts.total,
        counts.critical,
        counts.high,
        counts.medium,
        counts.low,
        counts.info
    ));
    out.push_str(&format!("Risk Score: {}/100\n", result.risk_score));
    out
}

fn format_findings_by_severity(findings: &[scanner::ScanFinding]) -> String {
    let mut out = String::new();
    for sev in &["critical", "high", "medium", "low", "info"] {
        let group: Vec<_> = findings.iter().filter(|f| f.severity == *sev).collect();
        if group.is_empty() {
            continue;
        }
        out.push_str(&format!(
            "{} ({}):\n",
            sev.to_uppercase(),
            group.len()
        ));
        for f in &group {
            out.push_str(&format!("  [{}] {}\n", f.rule_id, f.title));
            if let Some(ref fp) = f.file_path {
                let loc = if let Some(ln) = f.line_number {
                    format!("{}:{}", fp, ln)
                } else {
                    fp.clone()
                };
                out.push_str(&format!("    File: {}\n", loc));
            }
        }
        out.push('\n');
    }
    out
}

/// Run the `report` CLI subcommand.
async fn run_report_cli(
    scan_id: &str,
    format: &str,
    out_path: Option<&str>,
    db_path: &str,
) -> anyhow::Result<()> {
    let pool = db::init_db(db_path).await?;
    let scan = db::get_scan(&pool, scan_id).await?;
    if scan.is_none() {
        anyhow::bail!("Scan not found: {}", scan_id);
    }

    let result_path = format!("uploads/{}/result.json", scan_id);
    let data = tokio::fs::read_to_string(&result_path).await.map_err(|e| {
        anyhow::anyhow!("result.json not found for scan {}: {}", scan_id, e)
    })?;
    let result: scanner::android::AndroidScanResult = serde_json::from_str(&data)?;

    let content = match format {
        "html" => {
            let masvs = result
                .masvs_report
                .clone()
                .unwrap_or_else(|| masvs::compute_masvs_score(&result.findings));
            report::render_html_report_with_masvs(&result, &masvs)?
        }
        "pdf" => {
            let masvs = result
                .masvs_report
                .clone()
                .unwrap_or_else(|| masvs::compute_masvs_score(&result.findings));
            let html = report::render_html_report_with_masvs(&result, &masvs)?;
            let pdf_path = std::env::temp_dir().join(format!("mobsf_{}.pdf", scan_id));
            match report::render_pdf_report(&html, &pdf_path).await {
                Some(bytes) => {
                    let _ = tokio::fs::remove_file(&pdf_path).await;
                    let target = out_path.unwrap_or("report.pdf");
                    tokio::fs::write(target, &bytes).await?;
                    println!("PDF written to {}", target);
                    return Ok(());
                }
                None => {
                    anyhow::bail!("PDF export requires weasyprint in PATH");
                }
            }
        }
        _ => serde_json::to_string_pretty(&result)?,
    };

    if let Some(out_file) = out_path {
        tokio::fs::write(out_file, &content).await?;
    } else {
        print!("{}", content);
    }

    Ok(())
}

/// Run the `list` CLI subcommand.
async fn run_list_cli(db_path: &str) -> anyhow::Result<()> {
    let pool = db::init_db(db_path).await?;
    let scans = db::list_scans(&pool, 50).await?;

    if scans.is_empty() {
        println!("No scans found.");
        return Ok(());
    }

    println!(
        "{:<38}  {:<8}  {:<8}  {:<20}  {}",
        "SCAN ID", "TYPE", "STATUS", "CREATED", "FILE"
    );
    println!("{}", "-".repeat(100));

    for s in &scans {
        println!(
            "{:<38}  {:<8}  {:<8}  {:<20}  {}",
            s.id,
            s.file_type,
            s.status,
            &s.created_at[..19],
            s.filename
        );
    }

    Ok(())
}
