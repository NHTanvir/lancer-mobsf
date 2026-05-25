// android scanner module
pub mod apk;
pub mod apkid;
pub mod binary;
pub mod cert;
pub mod domain_reputation;
pub mod jadx;
pub mod manifest;
pub mod permissions;
pub mod rules;
pub mod secrets;
pub mod strings;
pub mod tracker;

use crate::scanner::ScanFinding;
use crate::scanner::ai_triage::{self, TriageSummary};
use crate::scanner::cve::{self, LibraryCveResult};
use crate::scanner::frida_generator::{ClassInfo, MethodInfo};
use crate::scanner::threat_intel::{self, ThreatIntelResult};
use crate::db::{DbPool, ScanStatus};
use crate::masvs::MasvsReport;
use std::path::Path;
use anyhow::Result;
use regex::Regex;

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
    pub ai_triage: Option<TriageSummary>,
    pub cve_results: Vec<LibraryCveResult>,
    /// Class/method inventory extracted from decompiled Java source (populated if jadx succeeded).
    pub class_inventory: Vec<ClassInfo>,
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

    // Step 9d: Packer/obfuscator detection
    broadcast(progress_tx, scan_id, "Detecting packers and obfuscators...", 86);
    {
        // Collect raw DEX bytes from the extracted DEX file paths.
        let dex_bytes: Vec<Vec<u8>> = extracted
            .dex_files
            .iter()
            .filter_map(|p| std::fs::read(p).ok())
            .collect();

        // Collect Java source paths if jadx succeeded (reuse sources_dir).
        let java_files_for_apkid: Vec<std::path::PathBuf> = if jadx_success && sources_dir.is_dir() {
            tracker::collect_java_files(&sources_dir)
        } else {
            Vec::new()
        };

        let packer_results = apkid::detect_packers(apk_path, &dex_bytes, &java_files_for_apkid);
        let packer_findings = apkid::packer_findings(&packer_results);
        all_findings.extend(packer_findings);
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

    // Step 9e: Domain reputation check (Google Safe Browsing)
    broadcast(progress_tx, scan_id, "Checking domain reputation...", 87);
    {
        let urls_to_check = domain_reputation::extract_urls_from_strings(&strings_found);
        match domain_reputation::check_urls(&urls_to_check).await {
            Ok(matches) => {
                let rep_findings = domain_reputation::safe_browsing_findings(&matches);
                all_findings.extend(rep_findings);
            }
            Err(e) => {
                tracing::warn!("Safe Browsing check failed: {}", e);
            }
        }
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

    // Step 11: AI triage (optional, requires ANTHROPIC_API_KEY)
    broadcast(progress_tx, scan_id, "Running AI triage analysis...", 92);
    let ai_triage = ai_triage::generate_triage(&all_findings, &package_name, "apk")
        .await
        .ok()
        .flatten();

    // Step 12: CVE correlation (if jadx succeeded)
    let java_files: Vec<std::path::PathBuf> = if jadx_success && sources_dir.is_dir() {
        crate::scanner::android::tracker::collect_java_files(&sources_dir)
    } else {
        Vec::new()
    };
    let cve_results = if !java_files.is_empty() {
        cve::correlate_cves(&java_files).await.unwrap_or_default()
    } else {
        Vec::new()
    };
    let cve_findings = cve::cve_to_findings(&cve_results);
    all_findings.extend(cve_findings);

    // Step 13: Generate report (sort findings by severity)
    broadcast(progress_tx, scan_id, "Generating report...", 90);
    all_findings.sort_by_key(|f| severity_order(f.severity.as_str()));

    let finding_counts = FindingCounts::from_findings(&all_findings);

    // Compute MASVS compliance score and overall risk score
    let masvs_report = Some(crate::masvs::compute_masvs_score(&all_findings));
    let risk_score = crate::masvs::overall_risk_score(&all_findings);

    // Step 14: Extract class/method inventory from decompiled Java files
    let class_inventory = if jadx_success && sources_dir.is_dir() {
        extract_class_inventory(&java_files)
    } else {
        Vec::new()
    };

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
        ai_triage,
        cve_results,
        class_inventory,
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

/// Extract class/method inventory from decompiled Java source files.
///
/// Uses best-effort regex parsing (not a full Java parser).
pub fn extract_class_inventory(java_files: &[std::path::PathBuf]) -> Vec<ClassInfo> {
    // Compile patterns once
    let class_re = Regex::new(
        r"(?:public|private|protected)?\s+(?:abstract\s+|final\s+)?class\s+(\w+)"
    )
    .unwrap_or_else(|_| Regex::new(r"class\s+(\w+)").unwrap());

    let method_re = Regex::new(
        r"(?:public|private|protected)\s+(static\s+)?(\w+(?:<\w+>)?)\s+(\w+)\s*\(([^)]*)\)"
    )
    .unwrap_or_else(|_| Regex::new(r"void\s+(\w+)\s*\(\)").unwrap());

    let mut inventory: Vec<ClassInfo> = Vec::new();

    for file_path in java_files.iter().take(500) {
        let source = match std::fs::read_to_string(file_path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Derive package from file path: com/example/Foo.java -> com.example
        let package = {
            let mut pkg = String::new();
            // Try to find package declaration in source first
            for line in source.lines().take(5) {
                let line = line.trim();
                if line.starts_with("package ") {
                    pkg = line
                        .trim_start_matches("package ")
                        .trim_end_matches(';')
                        .trim()
                        .to_string();
                    break;
                }
            }
            // Fall back to path-based package
            if pkg.is_empty() {
                if let Some(parent) = file_path.parent() {
                    let path_str = parent.to_string_lossy();
                    // Find the java/ or sources/ root in the path
                    let cleaned = if let Some(pos) = path_str.find("sources/") {
                        &path_str[pos + 8..]
                    } else if let Some(pos) = path_str.find("java/") {
                        &path_str[pos + 5..]
                    } else {
                        path_str.as_ref()
                    };
                    pkg = cleaned.replace(['/', '\\'], ".").trim_matches('.').to_string();
                }
            }
            pkg
        };

        // Extract class name
        let class_name = if let Some(cap) = class_re.captures(&source) {
            let simple = cap.get(1).map(|m| m.as_str()).unwrap_or("Unknown").to_string();
            if package.is_empty() {
                simple
            } else {
                format!("{}.{}", package, simple)
            }
        } else {
            // Use filename as class name
            let stem = file_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("Unknown")
                .to_string();
            if package.is_empty() {
                stem
            } else {
                format!("{}.{}", package, stem)
            }
        };

        // Extract methods
        let mut methods: Vec<MethodInfo> = Vec::new();
        for cap in method_re.captures_iter(&source) {
            let is_static = cap.get(1).is_some();
            let return_type = cap.get(2).map(|m| m.as_str()).unwrap_or("void").to_string();
            let name = cap.get(3).map(|m| m.as_str()).unwrap_or("").to_string();
            let params_str = cap.get(4).map(|m| m.as_str()).unwrap_or("").to_string();

            // Skip constructors and common noise
            if name.is_empty() || name == "class" || name == "interface" || name == "extends" {
                continue;
            }

            let params: Vec<String> = params_str
                .split(',')
                .map(|p| {
                    // Keep only the type part (last word before parameter name, or full if one token)
                    let trimmed = p.trim();
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        parts[parts.len() - 2].to_string()
                    } else if !parts.is_empty() {
                        parts[0].to_string()
                    } else {
                        String::new()
                    }
                })
                .filter(|s| !s.is_empty())
                .collect();

            methods.push(MethodInfo {
                name,
                return_type,
                params,
                is_static,
            });
        }

        inventory.push(ClassInfo {
            class_name,
            methods,
            package,
        });
    }

    inventory
}
