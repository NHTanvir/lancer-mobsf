// scanner module - Android and iOS static analysis
pub mod ai_triage;
pub mod android;
pub mod cve;
pub mod frida_generator;
pub mod ios;
pub mod threat_intel;

/// Unified finding type produced by all scanner sub-modules.
/// This is the *scan-time* finding (not the DB model).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanFinding {
    pub rule_id: String,
    pub title: String,
    /// "critical" | "high" | "medium" | "low" | "info"
    pub severity: String,
    pub description: String,
    pub file_path: Option<String>,
    pub line_number: Option<i32>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub masvs: Option<String>,
    pub evidence: Option<String>,
}
