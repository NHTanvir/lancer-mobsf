// ios scanner module
pub mod ipa;
pub mod plist_analysis;
pub mod macho;
pub mod ats;

use crate::scanner::ScanFinding;
use crate::db::{DbPool, ScanStatus};
use std::path::Path;
use anyhow::Result;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct IosScanResult {
    pub scan_id: String,
    pub bundle_id: String,
    pub bundle_name: String,
    pub version: String,
    pub sha256: String,
    pub info_plist: Option<plist_analysis::ParsedInfoPlist>,
    pub macho_info: Option<macho::MachoHardening>,
    pub provisioning: Option<ipa::ProvisioningProfile>,
    pub findings: Vec<ScanFinding>,
    pub finding_counts: crate::scanner::android::FindingCounts,
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

/// Full iOS static scan pipeline.
pub async fn scan_ipa(
    ipa_path: &Path,
    work_dir: &Path,
    scan_id: &str,
    db: &DbPool,
    progress_tx: &tokio::sync::broadcast::Sender<String>,
) -> Result<IosScanResult> {
    let mut all_findings: Vec<ScanFinding> = Vec::new();

    // Step 1: Compute SHA-256
    broadcast(progress_tx, scan_id, "Computing SHA-256...", 5);
    let ipa_bytes = tokio::fs::read(ipa_path).await.unwrap_or_default();
    let sha256 = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&ipa_bytes);
        hex::encode(hasher.finalize())
    };

    // Step 2: Extract IPA
    broadcast(progress_tx, scan_id, "Extracting IPA...", 10);
    let extracted = ipa::extract_ipa(ipa_path, work_dir).await?;

    // Step 3: Parse Info.plist
    broadcast(progress_tx, scan_id, "Parsing Info.plist...", 25);
    let parsed_plist = match plist_analysis::parse_info_plist(&extracted.info_plist_bytes) {
        Ok(p) => {
            let plist_findings = plist_analysis::analyze_info_plist(&p);
            all_findings.extend(plist_findings);
            Some(p)
        }
        Err(e) => {
            tracing::warn!("Failed to parse Info.plist: {}", e);
            None
        }
    };

    let bundle_id = parsed_plist
        .as_ref()
        .map(|p| p.bundle_id.clone())
        .unwrap_or_default();
    let bundle_name = parsed_plist
        .as_ref()
        .map(|p| p.bundle_name.clone())
        .unwrap_or_default();
    let version = parsed_plist
        .as_ref()
        .map(|p| p.bundle_short_version.clone())
        .unwrap_or_default();

    // Step 4: Analyze Mach-O binary
    broadcast(progress_tx, scan_id, "Analyzing Mach-O binary...", 50);
    let macho_info = if let Some(ref bin_path) = extracted.binary_path {
        match macho::analyze_macho(bin_path) {
            Ok((hardening, macho_findings)) => {
                all_findings.extend(macho_findings);
                Some(hardening)
            }
            Err(e) => {
                tracing::warn!("Failed to analyze Mach-O binary: {}", e);
                None
            }
        }
    } else {
        tracing::warn!("No main binary found in IPA");
        None
    };

    // Step 5: Parse provisioning profile
    broadcast(progress_tx, scan_id, "Parsing provisioning profile...", 70);
    let provisioning = if let Some(ref prov_path) = extracted.provisioning_path {
        match std::fs::read(prov_path) {
            Ok(data) => {
                let profile = ipa::parse_mobileprovision(&data);
                if let Some(ref p) = profile {
                    // Generate provisioning findings
                    if p.get_task_allow {
                        all_findings.push(ScanFinding {
                            rule_id: "ios_debug_provisioning".to_string(),
                            title: "Provisioning profile allows debugger attachment (get-task-allow=true)".to_string(),
                            severity: "critical".to_string(),
                            description: "The embedded.mobileprovision has get-task-allow=true in its \
                                entitlements. This allows a debugger to attach to the process, \
                                enabling runtime inspection and code injection. This must be \
                                disabled in production builds."
                                .to_string(),
                            file_path: Some("embedded.mobileprovision".to_string()),
                            line_number: None,
                            cwe: Some("CWE-489".to_string()),
                            owasp: None,
                            masvs: Some("MASVS-RESILIENCE-3".to_string()),
                            evidence: Some("get-task-allow = true".to_string()),
                        });
                    }

                    if p.is_development {
                        all_findings.push(ScanFinding {
                            rule_id: "ios_development_provisioning".to_string(),
                            title: "Development provisioning profile in use".to_string(),
                            severity: "medium".to_string(),
                            description: "The app is signed with a development provisioning profile \
                                (ProvisionedDevices is present). Development builds may have \
                                reduced security controls and should not be distributed publicly."
                                .to_string(),
                            file_path: Some("embedded.mobileprovision".to_string()),
                            line_number: None,
                            cwe: None,
                            owasp: None,
                            masvs: None,
                            evidence: None,
                        });
                    }

                    if p.aps_environment.as_deref() == Some("development") {
                        all_findings.push(ScanFinding {
                            rule_id: "ios_push_development".to_string(),
                            title: "APNs environment is set to development".to_string(),
                            severity: "info".to_string(),
                            description: "The aps-environment entitlement is set to 'development'. \
                                Push notifications are routed through the APNs development \
                                sandbox. Production apps should use the production environment."
                                .to_string(),
                            file_path: Some("embedded.mobileprovision".to_string()),
                            line_number: None,
                            cwe: None,
                            owasp: None,
                            masvs: None,
                            evidence: Some("aps-environment = development".to_string()),
                        });
                    }
                }
                profile
            }
            Err(e) => {
                tracing::warn!("Failed to read provisioning profile: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Step 6: Sort findings by severity
    broadcast(progress_tx, scan_id, "Generating report...", 85);
    all_findings.sort_by_key(|f| severity_order(f.severity.as_str()));

    let finding_counts = crate::scanner::android::FindingCounts::from_findings(&all_findings);

    let result = IosScanResult {
        scan_id: scan_id.to_string(),
        bundle_id,
        bundle_name,
        version,
        sha256,
        info_plist: parsed_plist,
        macho_info,
        provisioning,
        findings: all_findings,
        finding_counts,
    };

    // Step 7: Persist result.json
    let result_json = serde_json::to_string_pretty(&result)?;
    let result_path = format!("uploads/{}/result.json", scan_id);
    if let Err(e) = tokio::fs::write(&result_path, &result_json).await {
        tracing::warn!("Failed to write result.json: {}", e);
    }

    // Step 8: Update DB scan status to done
    if let Err(e) = crate::db::update_scan_status(db, scan_id, &ScanStatus::Done).await {
        tracing::warn!("Failed to update scan status to done: {}", e);
    }

    broadcast(progress_tx, scan_id, "Scan complete", 100);

    Ok(result)
}

/// Trigger an iOS scan asynchronously (spawns a Tokio task).
pub async fn trigger_scan(
    scan_id: String,
    db: DbPool,
    tx: tokio::sync::broadcast::Sender<String>,
) {
    tokio::spawn(async move {
        // Mark scan as running
        if let Err(e) = crate::db::update_scan_status(&db, &scan_id, &ScanStatus::Running).await {
            tracing::error!("Failed to mark iOS scan as running: {}", e);
        }

        // Build paths
        let upload_dir = format!("uploads/{}", scan_id);
        let work_dir = format!("uploads/{}/work", scan_id);

        // Find the IPA file in the upload dir
        let ipa_path = match find_ipa_in_dir(&upload_dir) {
            Some(p) => p,
            None => {
                tracing::error!("No IPA found in {}", upload_dir);
                let _ = crate::db::update_scan_status(&db, &scan_id, &ScanStatus::Error).await;
                return;
            }
        };

        let work_path = std::path::PathBuf::from(&work_dir);
        if let Err(e) = tokio::fs::create_dir_all(&work_path).await {
            tracing::error!("Failed to create work dir for iOS scan: {}", e);
            let _ = crate::db::update_scan_status(&db, &scan_id, &ScanStatus::Error).await;
            return;
        }

        match scan_ipa(&ipa_path, &work_path, &scan_id, &db, &tx).await {
            Ok(_) => {
                tracing::info!("iOS scan {} completed successfully", scan_id);
            }
            Err(e) => {
                tracing::error!("iOS scan {} failed: {}", scan_id, e);
                let _ = crate::db::update_scan_status(&db, &scan_id, &ScanStatus::Error).await;
            }
        }
    });
}

/// Find the first .ipa file in a directory.
fn find_ipa_in_dir(dir: &str) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("ipa") {
            return Some(path);
        }
    }
    None
}
