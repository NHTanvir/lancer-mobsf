// Traffic capture via mitmproxy/mitmdump subprocess orchestration

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use anyhow::{Context, Result};
use tracing::{info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Data types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body_preview: Option<String>, // first 500 bytes
    pub timestamp: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body_preview: Option<String>,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TrafficEntry {
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub duration_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// MitmProxy
// ─────────────────────────────────────────────────────────────────────────────

pub struct MitmProxy {
    port: u16,
    process: Option<tokio::process::Child>,
    capture_file: PathBuf,
}

impl MitmProxy {
    pub fn new(port: u16, capture_file: PathBuf) -> Self {
        Self {
            port,
            process: None,
            capture_file,
        }
    }

    /// Check if mitmproxy or mitmdump is available in PATH.
    pub async fn is_available() -> bool {
        // Try mitmdump first, then mitmproxy
        for tool in &["mitmdump", "mitmproxy"] {
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::process::Command::new(tool)
                    .arg("--version")
                    .output(),
            )
            .await;
            if let Ok(Ok(o)) = result {
                if o.status.success() {
                    return true;
                }
            }
        }
        false
    }

    /// Start mitmdump in background, writing a HAR/JSON dump to capture_file.
    pub async fn start(&mut self) -> Result<()> {
        if self.process.is_some() {
            return Ok(()); // already running
        }

        // Ensure parent directory for capture file exists
        if let Some(parent) = self.capture_file.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .context("failed to create capture directory")?;
        }

        // Use mitmdump with --ssl-insecure and write flows to the capture file.
        // We capture stdout/stderr to avoid polluting our own output.
        let child = tokio::process::Command::new("mitmdump")
            .arg("--mode")
            .arg("regular")
            .arg("-p")
            .arg(self.port.to_string())
            .arg("--ssl-insecure")
            .arg("-w")
            .arg(&self.capture_file)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .context("failed to spawn mitmdump")?;

        self.process = Some(child);
        info!("mitmdump started on port {} (capture: {})", self.port, self.capture_file.display());
        Ok(())
    }

    /// Stop mitmdump.
    pub async fn stop(&mut self) -> Result<()> {
        if let Some(mut child) = self.process.take() {
            let _ = child.kill().await;
            let _ = child.wait().await;
            info!("mitmdump stopped");
        }
        Ok(())
    }

    /// Load captured traffic.
    ///
    /// We attempt to read a JSON file next to the capture file (same stem,
    /// `.json` extension). If the capture file itself is JSON/HAR we try that
    /// directly.  If nothing is found we return an empty Vec rather than
    /// failing — graceful degradation.
    pub async fn load_traffic(&self) -> Result<Vec<TrafficEntry>> {
        // Derive candidate JSON paths
        let json_path = self.capture_file.with_extension("json");
        let har_path = self.capture_file.with_extension("har");

        let candidates = [
            json_path.as_path(),
            har_path.as_path(),
            self.capture_file.as_path(),
        ];

        for candidate in &candidates {
            if !candidate.exists() {
                continue;
            }
            match tokio::fs::read_to_string(candidate).await {
                Ok(content) => {
                    match parse_traffic_json(&content) {
                        Ok(entries) => return Ok(entries),
                        Err(e) => {
                            warn!("could not parse traffic file {}: {}", candidate.display(), e);
                        }
                    }
                }
                Err(e) => {
                    warn!("could not read traffic file {}: {}", candidate.display(), e);
                }
            }
        }

        // Nothing parseable — graceful empty result
        Ok(Vec::new())
    }

    /// Configure Android device to use this proxy via ADB.
    pub async fn configure_device_proxy(&self, adb: &super::adb::AdbClient) -> Result<()> {
        // Determine host IP visible to the device; fall back to loopback for emulators.
        let host_ip = get_host_ip().await.unwrap_or_else(|| "10.0.2.2".to_string());
        let proxy_str = format!("{}:{}", host_ip, self.port);
        adb.shell(&format!(
            "settings put global http_proxy {}",
            proxy_str
        ))
        .await
        .context("failed to set device proxy")?;
        info!("device proxy set to {}", proxy_str);
        Ok(())
    }

    /// Clear device proxy settings.
    pub async fn clear_device_proxy(&self, adb: &super::adb::AdbClient) -> Result<()> {
        adb.shell("settings put global http_proxy :0")
            .await
            .context("failed to clear device proxy")?;
        info!("device proxy cleared");
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Screenshot helper
// ─────────────────────────────────────────────────────────────────────────────

/// Take a screenshot and save it under `uploads/<scan_id>/screenshots/<label>_<timestamp>.png`.
/// Returns the path to the saved screenshot.
pub async fn take_screenshot(
    adb: &super::adb::AdbClient,
    scan_id: &str,
    label: &str,
) -> Result<PathBuf> {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let filename = format!("{}_{}.png", label, timestamp);
    let screenshot_dir = format!("uploads/{}/screenshots", scan_id);
    tokio::fs::create_dir_all(&screenshot_dir)
        .await
        .context("failed to create screenshots directory")?;
    let output_path = PathBuf::from(format!("{}/{}", screenshot_dir, filename));
    adb.screencap(&output_path)
        .await
        .context("screencap failed")?;
    info!("screenshot saved: {}", output_path.display());
    Ok(output_path)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Try to determine the machine's LAN IP address.
async fn get_host_ip() -> Option<String> {
    // We shell out to `hostname -I` (Linux) or `ipconfig` (Windows) to find the
    // first non-loopback IPv4 address.  On failure we return None and the caller
    // falls back to the Android emulator gateway (10.0.2.2).
    #[cfg(unix)]
    {
        let out = tokio::process::Command::new("hostname")
            .arg("-I")
            .output()
            .await
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        s.split_whitespace()
            .find(|ip| {
                let ip = *ip;
                !ip.starts_with("127.") && !ip.starts_with("::1")
            })
            .map(|s| s.to_string())
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Parse a JSON string that is either a JSON array of flow objects or a HAR
/// archive.  Returns an empty Vec for unrecognised formats.
fn parse_traffic_json(content: &str) -> Result<Vec<TrafficEntry>> {
    let value: serde_json::Value =
        serde_json::from_str(content).context("traffic file is not valid JSON")?;

    // HAR format: { "log": { "entries": [...] } }
    if let Some(entries) = value
        .get("log")
        .and_then(|l| l.get("entries"))
        .and_then(|e| e.as_array())
    {
        return Ok(entries.iter().filter_map(parse_har_entry).collect());
    }

    // Plain JSON array of mitmproxy flow objects
    if let Some(flows) = value.as_array() {
        return Ok(flows.iter().filter_map(parse_flow_entry).collect());
    }

    Ok(Vec::new())
}

fn parse_har_entry(entry: &serde_json::Value) -> Option<TrafficEntry> {
    let req_obj = entry.get("request")?;
    let method = req_obj.get("method")?.as_str()?.to_string();
    let url = req_obj.get("url")?.as_str()?.to_string();

    let req_headers = extract_har_headers(req_obj.get("headers"));
    let timestamp = entry
        .get("startedDateTime")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let body_preview = req_obj
        .get("postData")
        .and_then(|pd| pd.get("text"))
        .and_then(|t| t.as_str())
        .map(|s| s.chars().take(500).collect());

    let request = HttpRequest {
        method,
        url,
        headers: req_headers,
        body_preview,
        timestamp,
    };

    let response = entry.get("response").map(|resp_obj| {
        let status_code = resp_obj
            .get("status")
            .and_then(|s| s.as_u64())
            .unwrap_or(0) as u16;
        let resp_headers = extract_har_headers(resp_obj.get("headers"));
        let content_type = resp_headers.get("content-type").cloned();
        let body_preview = resp_obj
            .get("content")
            .and_then(|c| c.get("text"))
            .and_then(|t| t.as_str())
            .map(|s| s.chars().take(500).collect());
        HttpResponse {
            status_code,
            headers: resp_headers,
            body_preview,
            content_type,
        }
    });

    let duration_ms = entry
        .get("time")
        .and_then(|t| t.as_f64())
        .unwrap_or(0.0) as u64;

    Some(TrafficEntry {
        request,
        response,
        duration_ms,
    })
}

fn extract_har_headers(headers_val: Option<&serde_json::Value>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(arr) = headers_val.and_then(|v| v.as_array()) {
        for h in arr {
            if let (Some(name), Some(value)) = (
                h.get("name").and_then(|n| n.as_str()),
                h.get("value").and_then(|v| v.as_str()),
            ) {
                map.insert(name.to_lowercase(), value.to_string());
            }
        }
    }
    map
}

fn parse_flow_entry(flow: &serde_json::Value) -> Option<TrafficEntry> {
    let req_obj = flow.get("request")?;
    let method = req_obj.get("method")?.as_str()?.to_string();

    // Build URL from scheme + host + path
    let scheme = req_obj
        .get("scheme")
        .and_then(|s| s.as_str())
        .unwrap_or("http");
    let host = req_obj
        .get("host")
        .and_then(|s| s.as_str())
        .unwrap_or("");
    let path = req_obj
        .get("path")
        .and_then(|s| s.as_str())
        .unwrap_or("/");
    let url = format!("{}://{}{}", scheme, host, path);

    let req_headers = extract_flow_headers(req_obj.get("headers"));
    let timestamp = flow
        .get("timestamp_start")
        .and_then(|v| v.as_f64())
        .map(|ts| {
            chrono::DateTime::<chrono::Utc>::from_timestamp(ts as i64, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default()
        })
        .unwrap_or_default();

    let body_preview = req_obj
        .get("content")
        .and_then(|c| c.as_str())
        .map(|s| s.chars().take(500).collect());

    let request = HttpRequest {
        method,
        url,
        headers: req_headers,
        body_preview,
        timestamp,
    };

    let response = flow.get("response").map(|resp_obj| {
        let status_code = resp_obj
            .get("status_code")
            .and_then(|s| s.as_u64())
            .unwrap_or(0) as u16;
        let resp_headers = extract_flow_headers(resp_obj.get("headers"));
        let content_type = resp_headers.get("content-type").cloned();
        let body_preview = resp_obj
            .get("content")
            .and_then(|c| c.as_str())
            .map(|s| s.chars().take(500).collect());
        HttpResponse {
            status_code,
            headers: resp_headers,
            body_preview,
            content_type,
        }
    });

    let duration_ms = {
        let start = flow
            .get("timestamp_start")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let end = flow
            .get("timestamp_end")
            .and_then(|v| v.as_f64())
            .unwrap_or(start);
        ((end - start) * 1000.0) as u64
    };

    Some(TrafficEntry {
        request,
        response,
        duration_ms,
    })
}

fn extract_flow_headers(headers_val: Option<&serde_json::Value>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    // mitmproxy JSON stores headers as [[name, value], ...]
    if let Some(arr) = headers_val.and_then(|v| v.as_array()) {
        for h in arr {
            if let Some(pair) = h.as_array() {
                if pair.len() == 2 {
                    if let (Some(name), Some(value)) =
                        (pair[0].as_str(), pair[1].as_str())
                    {
                        map.insert(name.to_lowercase(), value.to_string());
                    }
                }
            }
        }
    }
    map
}
