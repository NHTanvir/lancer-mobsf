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
    pub fs_delta: Option<adb::FsDelta>,
    pub traffic_entries: Vec<traffic::TrafficEntry>,
}

#[derive(Debug, serde::Deserialize)]
pub struct DynamicScanRequest {
    /// Existing static scan ID
    pub scan_id: String,
    pub device_serial: Option<String>,
    pub enable_frida: bool,
    pub enable_proxy: bool,
    pub run_activity_tests: bool,
    /// Directory to save captures (traffic, screenshots). Defaults to uploads/<scan_id>
    pub capture_dir: Option<String>,
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
/// 4. Filesystem snapshot (before)
/// 5. Optionally start Frida
/// 6. Optionally start mitmproxy + configure device proxy
/// 7. Screenshot before activity tests
/// 8. Optionally test exported activities (run app for ~30 s)
/// 9. Screenshot after activity tests
/// 10. Filesystem snapshot (after) + compute delta
/// 11. Load traffic if proxy was running
/// 12. Capture logcat
/// 13. Return DynamicSessionState
pub async fn start_dynamic_session(
    req: DynamicScanRequest,
    _db: &DbPool,
    progress_tx: &tokio::sync::broadcast::Sender<String>,
) -> Result<DynamicSessionState> {
    let emit = |msg: &str| {
        let _ = progress_tx.send(msg.to_string());
        info!("{}", msg);
    };

    // Resolve capture directory
    let capture_dir = req
        .capture_dir
        .clone()
        .unwrap_or_else(|| format!("uploads/{}", req.scan_id));

    tokio::fs::create_dir_all(&capture_dir)
        .await
        .with_context(|| format!("failed to create capture dir: {}", capture_dir))?;

    // ── Step 1: adb availability ─────────────────────────────────────────────
    emit("dynamic: checking adb availability");
    if !adb::AdbClient::is_available().await {
        bail!("adb is not available in PATH; cannot start dynamic session");
    }

    let devices = adb::AdbClient::list_devices().await.context("failed to list adb devices")?;
    if devices.is_empty() {
        bail!("no ADB devices connected");
    }

    // Choose device
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

    // Find the APK path
    let apk_path = find_apk_in_upload_dir(&req.scan_id).await?;

    // ── Step 3: install APK ──────────────────────────────────────────────────
    emit(&format!("dynamic: installing APK {}", apk_path.display()));
    if let Err(e) = client.install(&apk_path).await {
        warn!("APK install failed (continuing): {}", e);
        emit(&format!("dynamic: APK install warning: {}", e));
    } else {
        emit("dynamic: APK installed successfully");
    }

    // ── Step 4: filesystem snapshot (before) ─────────────────────────────────
    emit("dynamic: taking filesystem snapshot (before)");
    let fs_before = client
        .fs_snapshot("/data/data")
        .await
        .unwrap_or_default();

    // ── Step 5: Frida ─────────────────────────────────────────────────────────
    let is_frida_running = if req.enable_frida {
        if frida::FridaClient::is_available().await {
            emit("dynamic: Frida available – running SSL bypass");
            let frida_client = frida::FridaClient::new(frida::FridaDevice::Usb);
            match frida::run_ssl_bypass(&frida_client, &package).await {
                Ok(output) => {
                    emit(&format!("dynamic: Frida SSL bypass output: {}", output.trim()));
                    true
                }
                Err(e) => {
                    warn!("dynamic: Frida SSL bypass failed: {}", e);
                    emit(&format!("dynamic: Frida SSL bypass failed: {}", e));
                    false
                }
            }
        } else {
            warn!("dynamic: Frida not found in PATH; skipping instrumentation");
            emit("dynamic: Frida not available (install frida-tools)");
            false
        }
    } else {
        false
    };

    // ── Step 6: mitmproxy ─────────────────────────────────────────────────────
    let capture_file = std::path::PathBuf::from(format!("{}/traffic.flow", capture_dir));
    let mut proxy = traffic::MitmProxy::new(8080, capture_file);

    let is_proxy_running = if req.enable_proxy {
        if traffic::MitmProxy::is_available().await {
            emit("dynamic: starting mitmproxy");
            match proxy.start().await {
                Ok(()) => {
                    // Give mitmdump a moment to bind
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    // Configure device
                    if let Err(e) = proxy.configure_device_proxy(&client).await {
                        warn!("dynamic: could not set device proxy: {}", e);
                    }
                    emit("dynamic: mitmproxy running");
                    true
                }
                Err(e) => {
                    warn!("dynamic: failed to start mitmproxy: {}", e);
                    emit(&format!("dynamic: mitmproxy start failed: {}", e));
                    false
                }
            }
        } else {
            warn!("dynamic: mitmproxy/mitmdump not found in PATH; skipping proxy");
            emit("dynamic: mitmproxy not available (install mitmproxy)");
            false
        }
    } else {
        false
    };

    // ── Step 7: screenshot before activity tests ──────────────────────────────
    emit("dynamic: taking screenshot (before)");
    if let Err(e) = traffic::take_screenshot(&client, &req.scan_id, "before").await {
        warn!("dynamic: screenshot (before) failed: {}", e);
    }

    // ── Step 8: activity tests (~30 s run window) ─────────────────────────────
    let activity_tests = if req.run_activity_tests {
        if let Some(ref mf) = manifest {
            emit("dynamic: testing exported activities");
            let results = adb::test_exported_activities(&client, mf, &package).await;
            emit(&format!("dynamic: tested {} activities", results.len()));
            results
        } else {
            warn!("dynamic: no manifest available for activity tests");
            // Still wait ~30 s to capture traffic even if no activity tests
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            Vec::new()
        }
    } else {
        // Wait 30 s so traffic/fs changes accumulate
        if is_proxy_running || req.enable_proxy {
            emit("dynamic: waiting 30 s for app interaction");
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
        Vec::new()
    };

    // ── Step 9: screenshot after activity tests ───────────────────────────────
    emit("dynamic: taking screenshot (after)");
    if let Err(e) = traffic::take_screenshot(&client, &req.scan_id, "after").await {
        warn!("dynamic: screenshot (after) failed: {}", e);
    }

    // ── Step 10: filesystem snapshot (after) + delta ──────────────────────────
    emit("dynamic: taking filesystem snapshot (after)");
    let fs_after = client
        .fs_snapshot("/data/data")
        .await
        .unwrap_or_default();

    let fs_delta = Some(adb::AdbClient::fs_delta(&fs_before, &fs_after));
    emit(&format!(
        "dynamic: fs delta – created:{} deleted:{} modified:{}",
        fs_delta.as_ref().map(|d| d.created.len()).unwrap_or(0),
        fs_delta.as_ref().map(|d| d.deleted.len()).unwrap_or(0),
        fs_delta.as_ref().map(|d| d.modified.len()).unwrap_or(0),
    ));

    // ── Step 11: stop proxy + load traffic ────────────────────────────────────
    let traffic_entries = if is_proxy_running {
        // Clear device proxy before stopping
        if let Err(e) = proxy.clear_device_proxy(&client).await {
            warn!("dynamic: could not clear device proxy: {}", e);
        }
        proxy.stop().await.ok();
        emit("dynamic: loading captured traffic");
        proxy.load_traffic().await.unwrap_or_default()
    } else {
        Vec::new()
    };

    emit(&format!("dynamic: {} traffic entries captured", traffic_entries.len()));

    // ── Step 12: capture logcat ───────────────────────────────────────────────
    emit("dynamic: capturing logcat");
    let logcat_path = format!("uploads/{}/logcat.txt", req.scan_id);
    match client.logcat(500).await {
        Ok(log) => {
            let _ = tokio::fs::write(&logcat_path, &log).await;
            emit(&format!("dynamic: logcat saved to {}", logcat_path));
        }
        Err(e) => warn!("dynamic: logcat capture failed: {}", e),
    }

    // ── Step 13: return state ─────────────────────────────────────────────────
    Ok(DynamicSessionState {
        scan_id: req.scan_id,
        device_serial,
        package,
        is_frida_running,
        is_proxy_running,
        activity_tests,
        fs_delta,
        traffic_entries,
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
