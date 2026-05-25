// android scanner module
pub mod apk;
pub mod manifest;
pub mod permissions;
pub mod cert;
pub mod jadx;
pub mod rules;
pub mod binary;
pub mod strings;
pub mod secrets;
pub mod tracker;

use crate::scanner::ScanFinding;
use crate::scanner::threat_intel::{self, ThreatIntelResult};
use crate::db::{DbPool, ScanStatus};
use crate::masvs::MasvsReport;
use std::path::Path;
use anyhow::Result;

/// Compiled android rules embedded at build time.
const ANDROID_RULES_YAML: &str = include_str!("../../../rules/android_rules.yaml");

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AndroidScanResult {
    pub scan_id: String,
    pub package_name: String,
    pub version_name: String,
    pub sha256: String,
    pub manifest: Option<manifest::ParsedManifest>,
    pub cert_info: Option<cert::CertInfo>,
    pub elf_hardenings: Vec<binary::ElfHardening>,
    pub jadx_success: bool,
    pub java_file_count: usize,
    pub findings: Vec<ScanFinding>,
    pub finding_counts: FindingCounts,
    pub masvs_report: Option<MasvsReport>,
    pub risk_score: u8,
    pub threat_intel: Option<ThreatIntelResult>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct FindingCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}

impl FindingCounts {
    pub fn from_findings(findings: &[ScanFinding]) -> Self {
        let mut critical = 0usize;
        let mut high = 0usize;
        let mut medium = 0usize;
        let mut low = 0usize;
        let mut info = 0usize;

        for f in findings {
            match f.severity.as_str() {
                "critical" => critical += 1,
                "high" => high += 1,
                "medium" => medium += 1,
                "low" => low += 1,
                _ => info += 1,
            }
        }

        FindingCounts {
            critical,
            high,
            medium,
            low,
            info,
            total: findings.len(),
        }
    }
}

fn severity_order(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn broadcast(tx: &tokio::sync::broadcast::Sender<String>, scan_id: &str, message: &str, percent: u8) {
    let msg = serde_json::json!({
        "type": "progress",
        "scan_id": scan_id,
        "message": message,
        "percent": percent,
    })
    .to_string();
    let _ = tx.send(msg);
}

/// Full Android static scan pipeline.
pub async fn scan_apk(
    apk_path: &Path,
    work_dir: &Path,
    scan_id: &str,
    db: &DbPool,
    progress_tx: &tokio::sync::broadcast::Sender<String>,
) -> Result<AndroidScanResult> {
    let mut all_findings: Vec<ScanFinding> = Vec::new();

    // Step 1: Extract APK
    broadcast(progress_tx, scan_id, "Extracting APK...", 5);
    let extracted = apk::extract_apk(apk_path, work_dir).await?;

    // Compute SHA-256 of APK
    let apk_bytes = tokio::fs::read(apk_path).await.unwrap_or_default();
    let sha256 = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&apk_bytes);
        hex::encode(hasher.finalize())
    };

    // Step 2: Parse manifest
    broadcast(progress_tx, scan_id, "Parsing manifest...", 15);
    let parsed_manifest = if extracted.manifest_bytes.is_empty() {
        None
    } else {
        match manifest::parse_manifest(&extracted.manifest_bytes) {
            Ok(m) => {
                // Manifest findings
                let mf = manifest::analyze_manifest(&m);
                all_findings.extend(mf);
                // Permission findings
                let pf = permissions::analyze_permissions(&m.permissions);
                all_findings.extend(pf);
                Some(m)
            }
            Err(e) => {
                tracing::warn!("Failed to parse manifest: {}", e);
                None
            }
        }
    };

    let package_name = parsed_manifest
        .as_ref()
        .map(|m| m.package.clone())
        .unwrap_or_default();
    let version_name = parsed_manifest
        .as_ref()
        .map(|m| m.version_name.clone())
        .unwrap_or_default();

    // Step 3: Analyze certificates
    broadcast(progress_tx, scan_id, "Analyzing certificates...", 25);
    let (cert_info, cert_findings) = cert::analyze_cert(&extracted.cert_files)?;
    all_findings.extend(cert_findings);

    // Step 4: Run jadx
    broadcast(progress_tx, scan_id, "Running jadx decompiler...", 35);
    let sources_dir = work_dir.join("sources");
    let jadx_result = jadx::decompile_with_jadx(apk_path, work_dir).await?;
    let jadx_success = jadx_result.success;
    let java_file_count = jadx_result.file_count;

    // Step 5: Scan Java source with rule engine
    broadcast(progress_tx, scan_id, "Scanning Java source...", 50);
    if jadx_success && sources_dir.is_dir() {
        match rules::RuleEngine::from_yaml(ANDROID_RULES_YAML) {
            Ok(engine) => {
                let rule_findings = engine.scan_directory(&sources_dir, &["java", "kt"]).await;
                all_findings.extend(rule_findings);
            }
            Err(e) => {
                tracing::warn!("Failed to load android rules: {}", e);
            }
        }
    }

    // Step 6: Analyze native binaries
    broadcast(progress_tx, scan_id, "Analyzing native binaries...", 70);
    let (elf_hardenings, binary_findings) = binary::analyze_binaries(&extracted.so_files);
    all_findings.extend(binary_findings);

    // Step 7: Extract strings and find string findings
    broadcast(progress_tx, scan_id, "Extracting strings...", 75);
    let strings_found =
        strings::extract_strings_from_apk(&extracted.so_files, &extracted.dex_files);
    let string_findings = strings::find_string_findings(&strings_found);
    all_findings.extend(string_findings);

    // Step 8: Hardcoded secrets scan
    broadcast(progress_tx, scan_id, "Scanning for hardcoded secrets...", 80);
    if jadx_success && sources_dir.is_dir() {
        let secret_findings = secrets::scan_secrets_in_directory(&sources_dir).await;
        all_findings.extend(secret_findings);
    }

    // Step 9: Tracker detection
    broadcast(progress_tx, scan_id, "Detecting tracker libraries...", 85);
    if jadx_success && sources_dir.is_dir() {
        let tracker_db = tracker::load_tracker_db();
        let java_files = tracker::collect_java_files(&sources_dir);
        let tracker_findings = tracker::detect_trackers(&java_files, &tracker_db);
        all_findings.extend(tracker_findings);
    }

    // Step 9b: Network Security Config analysis
    {
        let nsc_path = extracted.dir.join("res/xml/network_security_config.xml");
        if nsc_path.exists() {
            if let Ok(nsc_xml) = tokio::fs::read_to_string(&nsc_path).await {
                match manifest::parse_network_security_config(&nsc_xml) {
                    Ok(nsc) => {
                        let nsc_findings = manifest::analyze_network_security_config(&nsc);
                        all_findings.extend(nsc_findings);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse NSC: {}", e);
                    }
                }
            }
        }
    }

    // Step 9c: Firebase database URL public access check
    {
        let firebase_findings = secrets::check_firebase_urls(&strings_found).await;
        all_findings.extend(firebase_findings);
    }

    // Step 10: Threat intelligence (async, may be skipped if no API keys)
    broadcast(progress_tx, scan_id, "Querying threat intelligence...", 88);
    let threat_intel_result = match threat_intel::analyze_threat_intel(&sha256).await {
        Ok((ti_result, ti_findings)) => {
            all_findings.extend(ti_findings);
            Some(ti_result)
        }
        Err(e) => {
            tracing::warn!("Threat intel query failed: {}", e);
            None
        }
    };

    // Step 11: Generate report (sort findings by severity)
    broadcast(progress_tx, scan_id, "Generating report...", 90);
    all_findings.sort_by_key(|f| severity_order(f.severity.as_str()));

    let finding_counts = FindingCounts::from_findings(&all_findings);

    // Compute MASVS compliance score and overall risk score
    let masvs_report = Some(crate::masvs::compute_masvs_score(&all_findings));
    let risk_score = crate::masvs::overall_risk_score(&all_findings);

    let result = AndroidScanResult {
        scan_id: scan_id.to_string(),
        package_name,
        version_name,
        sha256,
        manifest: parsed_manifest,
        cert_info,
        elf_hardenings,
        jadx_success,
        java_file_count,
        findings: all_findings,
        finding_counts,
        masvs_report,
        risk_score,
        threat_intel: threat_intel_result,
    };

    // Step 9: Persist result.json
    let result_json = serde_json::to_string_pretty(&result)?;
    let result_path = format!("uploads/{}/result.json", scan_id);
    if let Err(e) = tokio::fs::write(&result_path, &result_json).await {
        tracing::warn!("Failed to write result.json: {}", e);
    }

    // Step 10: Update DB scan status to done
    if let Err(e) = crate::db::update_scan_status(db, scan_id, &ScanStatus::Done).await {
        tracing::warn!("Failed to update scan status to done: {}", e);
    }

    broadcast(progress_tx, scan_id, "Scan complete", 100);

    Ok(result)
}

/// Trigger a scan asynchronously (spawns a Tokio task).
pub async fn trigger_scan(
    scan_id: String,
    db: DbPool,
    tx: tokio::sync::broadcast::Sender<String>,
) {
    tokio::spawn(async move {
        // Mark scan as running
        if let Err(e) = crate::db::update_scan_status(&db, &scan_id, &ScanStatus::Running).await {
            tracing::error!("Failed to mark scan as running: {}", e);
        }

        // Build paths
        let upload_dir = format!("uploads/{}", scan_id);
        let work_dir = format!("uploads/{}/work", scan_id);

        // Find the APK file in the upload dir
        let apk_path = match find_apk_in_dir(&upload_dir) {
            Some(p) => p,
            None => {
                tracing::error!("No APK found in {}", upload_dir);
                let _ =
                    crate::db::update_scan_status(&db, &scan_id, &ScanStatus::Error).await;
                return;
            }
        };

        let work_path = std::path::PathBuf::from(&work_dir);
        if let Err(e) = tokio::fs::create_dir_all(&work_path).await {
            tracing::error!("Failed to create work dir: {}", e);
            let _ = crate::db::update_scan_status(&db, &scan_id, &ScanStatus::Error).await;
            return;
        }

        match scan_apk(&apk_path, &work_path, &scan_id, &db, &tx).await {
            Ok(_) => {
                tracing::info!("Scan {} completed successfully", scan_id);
            }
            Err(e) => {
                tracing::error!("Scan {} failed: {}", scan_id, e);
                let _ =
                    crate::db::update_scan_status(&db, &scan_id, &ScanStatus::Error).await;
            }
        }
    });
}

/// Find the first .apk file in a directory.
fn find_apk_in_dir(dir: &str) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("apk") {
            return Some(path);
        }
    }
    None
}
