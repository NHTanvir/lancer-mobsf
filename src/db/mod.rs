// db module - database connection and query helpers

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};

pub type DbPool = SqlitePool;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Pending,
    Running,
    Done,
    Error,
}

impl ScanStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanStatus::Pending => "pending",
            ScanStatus::Running => "running",
            ScanStatus::Done => "done",
            ScanStatus::Error => "error",
        }
    }
}

impl std::fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TryFrom<String> for ScanStatus {
    type Error = anyhow::Error;
    fn try_from(s: String) -> Result<Self> {
        match s.as_str() {
            "pending" => Ok(ScanStatus::Pending),
            "running" => Ok(ScanStatus::Running),
            "done" => Ok(ScanStatus::Done),
            "error" => Ok(ScanStatus::Error),
            other => Err(anyhow::anyhow!("unknown scan status: {}", other)),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    pub id: String,
    pub filename: String,
    pub file_type: String,
    pub sha256: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: i64,
    pub scan_id: String,
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub description: String,
    pub file_path: Option<String>,
    pub line_number: Option<i64>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub masvs: Option<String>,
    pub extra: Option<String>,
}

/// Create or open the SQLite database and run migrations.
pub async fn init_db(db_path: &str) -> Result<DbPool> {
    // Ensure parent directory exists
    if let Some(parent) = std::path::Path::new(db_path).parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }

    let connection_string = format!("sqlite://{}?mode=rwc", db_path);
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&connection_string)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&pool)
        .await?;

    Ok(pool)
}

pub async fn insert_scan(pool: &DbPool, scan: &Scan) -> Result<()> {
    sqlx::query(
        "INSERT INTO scans (id, filename, file_type, sha256, status, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(&scan.id)
    .bind(&scan.filename)
    .bind(&scan.file_type)
    .bind(&scan.sha256)
    .bind(&scan.status)
    .bind(&scan.created_at)
    .bind(&scan.updated_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_scan_status(pool: &DbPool, scan_id: &str, status: &ScanStatus) -> Result<()> {
    let status_str = status.as_str();
    let now = chrono::Utc::now().to_rfc3339();
    let result = sqlx::query("UPDATE scans SET status = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(status_str)
        .bind(now)
        .bind(scan_id)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(anyhow::anyhow!("scan not found: {}", scan_id));
    }
    Ok(())
}

pub async fn get_scan(pool: &DbPool, scan_id: &str) -> Result<Option<Scan>> {
    let row = sqlx::query(
        "SELECT id, filename, file_type, sha256, status, created_at, updated_at \
         FROM scans WHERE id = ?1",
    )
    .bind(scan_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| Scan {
        id: r.get("id"),
        filename: r.get("filename"),
        file_type: r.get("file_type"),
        sha256: r.get("sha256"),
        status: r.get("status"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }))
}

pub async fn list_scans(pool: &DbPool, limit: i64) -> Result<Vec<Scan>> {
    let rows = sqlx::query(
        "SELECT id, filename, file_type, sha256, status, created_at, updated_at \
         FROM scans ORDER BY created_at DESC LIMIT ?1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| Scan {
            id: r.get("id"),
            filename: r.get("filename"),
            file_type: r.get("file_type"),
            sha256: r.get("sha256"),
            status: r.get("status"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        })
        .collect())
}

pub async fn insert_finding(pool: &DbPool, finding: &Finding) -> Result<i64> {
    let result = sqlx::query(
        "INSERT INTO findings \
         (scan_id, rule_id, title, severity, description, file_path, line_number, cwe, owasp, masvs, extra) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    )
    .bind(&finding.scan_id)
    .bind(&finding.rule_id)
    .bind(&finding.title)
    .bind(&finding.severity)
    .bind(&finding.description)
    .bind(&finding.file_path)
    .bind(finding.line_number)
    .bind(&finding.cwe)
    .bind(&finding.owasp)
    .bind(&finding.masvs)
    .bind(&finding.extra)
    .execute(pool)
    .await?;
    Ok(result.last_insert_rowid())
}

pub async fn get_findings(pool: &DbPool, scan_id: &str) -> Result<Vec<Finding>> {
    let rows = sqlx::query(
        "SELECT id, scan_id, rule_id, title, severity, description, \
         file_path, line_number, cwe, owasp, masvs, extra \
         FROM findings WHERE scan_id = ?1 ORDER BY id ASC",
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| Finding {
            id: r.get("id"),
            scan_id: r.get("scan_id"),
            rule_id: r.get("rule_id"),
            title: r.get("title"),
            severity: r.get("severity"),
            description: r.get("description"),
            file_path: r.get("file_path"),
            line_number: r.get("line_number"),
            cwe: r.get("cwe"),
            owasp: r.get("owasp"),
            masvs: r.get("masvs"),
            extra: r.get("extra"),
        })
        .collect())
}
