// dynamic module - dynamic analysis (ADB, Frida, traffic)
pub mod adb;
pub mod frida;
pub mod traffic;

use anyhow::{bail, Context, Result};
use tracing::{info, warn};

use crate::db::DbPool;

// ─────────────────────────────────────────────────────────────────────────────
// Public data types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize)]
pub struct DynamicSessionState {
    pub scan_id: String,
    pub device_serial: String,
    pub package: String,
    pub is_frida_running: bool,
    pub is_proxy_running: bool,
    pub activity_tests: Vec<adb::ActivityTestResult>,
}

#[derive(Debug, serde::Deserialize)]
pub struct DynamicScanRequest {
    /// Existing static scan ID
    pub scan_id: String,
    pub device_serial: Option<String>,
    pub enable_frida: bool,
    pub enable_proxy: bool,
    pub run_activity_tests: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Orchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// Start a dynamic analysis session.
///
/// Pipeline:
/// 1. Check adb availability + list devices
/// 2. Load static scan result (uploads/<scan_id>/result.json)
/// 3. Install the APK
/// 4. Optionally start Frida (stub)
/// 5. Optionally start proxy (stub)
/// 6. Optionally test exported activities
/// 7. Capture logcat
/// 8. Take screenshot
/// 9. Return DynamicSessionState
pub async fn start_dynamic_session(
    req: DynamicScanRequest,
    _db: &DbPool,
    progress_tx: &tokio::sync::broadcast::Sender<String>,
) -> Result<DynamicSessionState> {
    let emit = |msg: &str| {
        let _ = progress_tx.send(msg.to_string());
        info!("{}", msg);
    };

    // ── Step 1: adb availability ─────────────────────────────────────────────
    emit("dynamic: checking adb availability");
    if !adb::AdbClient::is_available().await {
        bail!("adb is not available in PATH; cannot start dynamic session");
    }

    let devices = adb::AdbClient::list_devices().await.context("failed to list adb devices")?;
    if devices.is_empty() {
        bail!("no ADB devices connected");
    }

    // Choose device: use requested serial or fall back to first connected device
    let device_serial = if let Some(ref serial) = req.device_serial {
        let found = devices.iter().any(|d| &d.serial == serial);
        if !found {
            bail!("device '{}' not found in adb device list", serial);
        }
        serial.clone()
    } else {
        devices[0].serial.clone()
    };

    emit(&format!("dynamic: using device {}", device_serial));

    let client = adb::AdbClient::new(Some(device_serial.clone()));

    // ── Step 2: load static scan result ─────────────────────────────────────
    emit(&format!("dynamic: loading scan result for {}", req.scan_id));
    let result_path = format!("uploads/{}/result.json", req.scan_id);
    let result_data = tokio::fs::read_to_string(&result_path)
        .await
        .with_context(|| format!("result.json not found for scan {}", req.scan_id))?;

    let scan_result: crate::scanner::android::AndroidScanResult =
        serde_json::from_str(&result_data)
            .context("failed to parse result.json as AndroidScanResult")?;

    let package = scan_result.package_name.clone();
    let manifest = scan_result.manifest.clone();

    // Find the APK path inside the upload directory
    let apk_path = find_apk_in_upload_dir(&req.scan_id).await?;

    // ── Step 3: install APK ──────────────────────────────────────────────────
    emit(&format!("dynamic: installing APK {}", apk_path.display()));
    if let Err(e) = client.install(&apk_path).await {
        warn!("APK install failed (continuing): {}", e);
        emit(&format!("dynamic: APK install warning: {}", e));
    } else {
        emit("dynamic: APK installed successfully");
    }

    // ── Step 4: Frida (stub) ─────────────────────────────────────────────────
    let is_frida_running = if req.enable_frida {
        emit("dynamic: Frida requested (stub - not yet implemented)");
        false
    } else {
        false
    };

    // ── Step 5: proxy (stub) ─────────────────────────────────────────────────
    let is_proxy_running = if req.enable_proxy {
        emit("dynamic: traffic proxy requested (stub - not yet implemented)");
        false
    } else {
        false
    };

    // ── Step 6: activity tests ───────────────────────────────────────────────
    let activity_tests = if req.run_activity_tests {
        if let Some(ref mf) = manifest {
            emit("dynamic: testing exported activities");
            let results = adb::test_exported_activities(&client, mf, &package).await;
            emit(&format!("dynamic: tested {} activities", results.len()));
            results
        } else {
            warn!("dynamic: no manifest available for activity tests");
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // ── Step 7: capture logcat ───────────────────────────────────────────────
    emit("dynamic: capturing logcat");
    let logcat_path = format!("uploads/{}/logcat.txt", req.scan_id);
    match client.logcat(500).await {
        Ok(log) => {
            let _ = tokio::fs::write(&logcat_path, &log).await;
            emit(&format!("dynamic: logcat saved to {}", logcat_path));
        }
        Err(e) => warn!("dynamic: logcat capture failed: {}", e),
    }

    // ── Step 8: screenshot ───────────────────────────────────────────────────
    emit("dynamic: taking screenshot");
    let screenshot_path = std::path::PathBuf::from(format!(
        "uploads/{}/screenshot.png",
        req.scan_id
    ));
    if let Err(e) = client.screencap(&screenshot_path).await {
        warn!("dynamic: screencap failed (continuing): {}", e);
    } else {
        emit(&format!("dynamic: screenshot saved to {}", screenshot_path.display()));
    }

    // ── Step 9: return state ─────────────────────────────────────────────────
    Ok(DynamicSessionState {
        scan_id: req.scan_id,
        device_serial,
        package,
        is_frida_running,
        is_proxy_running,
        activity_tests,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

async fn find_apk_in_upload_dir(scan_id: &str) -> Result<std::path::PathBuf> {
    let dir = format!("uploads/{}", scan_id);
    let mut entries = tokio::fs::read_dir(&dir)
        .await
        .with_context(|| format!("upload directory not found: {}", dir))?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("apk") {
            return Ok(path);
        }
    }

    bail!("no APK file found in {}", dir);
}
