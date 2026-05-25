// Frida instrumentation - subprocess-based client (no FFI)

use std::path::Path;
use anyhow::{Context, Result};
use tracing::{info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Embedded Frida scripts (compiled in at build time)
// ─────────────────────────────────────────────────────────────────────────────

const SSL_PINNING_BYPASS_JS: &str =
    include_str!("../../frida-scripts/ssl_pinning_bypass.js");
const ROOT_DETECTION_BYPASS_JS: &str =
    include_str!("../../frida-scripts/root_detection_bypass.js");
const CRYPTO_LOGGER_JS: &str =
    include_str!("../../frida-scripts/crypto_logger.js");
const ANTI_DEBUG_BYPASS_JS: &str =
    include_str!("../../frida-scripts/anti_debug_bypass.js");
const API_MONITOR_JS: &str =
    include_str!("../../frida-scripts/api_monitor.js");

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct FridaProcess {
    pub pid: u32,
    pub name: String,
    pub identifier: String, // package name for Android
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum FridaDevice {
    Usb,            // frida -U
    Local,          // frida (local)
    Remote(String), // frida -H <host>
}

pub struct FridaClient {
    device: FridaDevice,
}

/// Built-in scripts that can be injected without an external file.
pub enum BuiltinScript {
    SslPinningBypass,
    RootDetectionBypass,
    CryptoLogger,
    AntiDebugBypass,
    ApiMonitor,
}

// ─────────────────────────────────────────────────────────────────────────────
// get_builtin_script_content
// ─────────────────────────────────────────────────────────────────────────────

pub fn get_builtin_script_content(script: BuiltinScript) -> &'static str {
    match script {
        BuiltinScript::SslPinningBypass => SSL_PINNING_BYPASS_JS,
        BuiltinScript::RootDetectionBypass => ROOT_DETECTION_BYPASS_JS,
        BuiltinScript::CryptoLogger => CRYPTO_LOGGER_JS,
        BuiltinScript::AntiDebugBypass => ANTI_DEBUG_BYPASS_JS,
        BuiltinScript::ApiMonitor => API_MONITOR_JS,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FridaClient implementation
// ─────────────────────────────────────────────────────────────────────────────

impl FridaClient {
    pub fn new(device: FridaDevice) -> Self {
        Self { device }
    }

    /// Return the CLI flags that select the target device.
    #[allow(dead_code)]
    fn device_args(&self) -> Vec<&str> {
        match &self.device {
            FridaDevice::Usb => vec!["-U"],
            FridaDevice::Local => vec![],
            FridaDevice::Remote(_) => vec!["-H"],
        }
    }

    /// Build the full device argument list, including a host value when needed.
    fn device_args_owned(&self) -> Vec<String> {
        match &self.device {
            FridaDevice::Usb => vec!["-U".to_string()],
            FridaDevice::Local => vec![],
            FridaDevice::Remote(host) => vec!["-H".to_string(), host.clone()],
        }
    }

    /// Check whether the `frida` CLI tool is available in PATH.
    pub async fn is_available() -> bool {
        let result = tokio::process::Command::new("frida")
            .arg("--version")
            .output()
            .await;
        matches!(result, Ok(o) if o.status.success())
    }

    /// List running processes on the target device via `frida-ps`.
    ///
    /// Output format (from `frida-ps -U`):
    /// ```
    ///  PID  Name
    /// ----  ----
    ///  1234  com.example.app
    /// ```
    pub async fn list_processes(&self) -> Result<Vec<FridaProcess>> {
        let mut cmd = tokio::process::Command::new("frida-ps");
        for arg in self.device_args_owned() {
            cmd.arg(arg);
        }
        // Request application list with identifiers
        cmd.arg("-a");

        let output = cmd.output().await.context("failed to run frida-ps")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("frida-ps failed: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let processes = parse_frida_ps_output(&stdout);
        Ok(processes)
    }

    /// Inject a Frida script into a running process (spawn mode).
    ///
    /// The script is written to a temp file and passed via `-l`.
    /// Stdout lines are streamed through the returned `mpsc::Receiver`.
    pub async fn inject_script(
        &self,
        target: &str,
        script_path: &Path,
    ) -> Result<tokio::sync::mpsc::Receiver<String>> {
        use tokio::io::{AsyncBufReadExt, BufReader};

        let mut args = self.device_args_owned();
        args.push("-f".to_string());
        args.push(target.to_string());
        args.push("-l".to_string());
        args.push(
            script_path
                .to_str()
                .context("script path is not valid UTF-8")?
                .to_string(),
        );
        args.push("--no-pause".to_string());

        let mut child = tokio::process::Command::new("frida")
            .args(&args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("failed to spawn frida")?;

        let stdout = child
            .stdout
            .take()
            .context("failed to capture frida stdout")?;

        let (tx, rx) = tokio::sync::mpsc::channel::<String>(256);

        tokio::spawn(async move {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx.send(line).await.is_err() {
                    break;
                }
            }
            // Wait for the child to avoid zombie processes
            let _ = child.wait().await;
        });

        Ok(rx)
    }

    /// Run a Frida script inline (via a temp file) and capture the full output
    /// within `timeout_secs` seconds.
    pub async fn run_script(
        &self,
        target: &str,
        script_content: &str,
        timeout_secs: u64,
    ) -> Result<String> {
        // Write content to a named temporary file
        let tmp_path = std::env::temp_dir().join(format!(
            "lancer_frida_{}.js",
            uuid_simple()
        ));
        tokio::fs::write(&tmp_path, script_content)
            .await
            .context("failed to write temp frida script")?;

        let mut args = self.device_args_owned();
        args.push("-n".to_string());
        args.push(target.to_string());
        args.push("-l".to_string());
        args.push(tmp_path.to_str().unwrap_or_default().to_string());

        let run_future = async {
            tokio::process::Command::new("frida")
                .args(&args)
                .output()
                .await
                .context("failed to run frida")
        };

        let output = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            run_future,
        )
        .await
        .context("frida script timed out")?
        .context("frida execution error")?;

        // Clean up temp file (best-effort)
        let _ = tokio::fs::remove_file(&tmp_path).await;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("frida run_script stderr: {}", stderr);
        }

        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// High-level helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Run the universal SSL bypass script on a connected device.
pub async fn run_ssl_bypass(client: &FridaClient, package: &str) -> Result<String> {
    info!("frida: running SSL bypass on {}", package);
    client
        .run_script(package, SSL_PINNING_BYPASS_JS, 30)
        .await
}

/// Run the API monitor script and return captured log lines.
pub async fn run_api_monitor(
    client: &FridaClient,
    package: &str,
    duration_secs: u64,
) -> Result<Vec<String>> {
    info!("frida: running API monitor on {} for {}s", package, duration_secs);
    let output = client
        .run_script(package, API_MONITOR_JS, duration_secs)
        .await?;
    let lines = output.lines().map(|l| l.to_owned()).collect();
    Ok(lines)
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsing helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parse `frida-ps -U -a` output into a list of FridaProcess entries.
///
/// Expected format:
/// ```
///  PID  Name                    Identifier
/// ----  ----------------------  ----------------------------------
///  1234  My App                  com.example.myapp
/// ```
fn parse_frida_ps_output(output: &str) -> Vec<FridaProcess> {
    let mut processes = Vec::new();

    for line in output.lines() {
        // Skip header / separator lines
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("PID")
            || trimmed.starts_with("---")
            || trimmed.starts_with("----")
        {
            continue;
        }

        // First token is PID; remaining columns are separated by 2+ spaces
        // (App names may contain single spaces, so we can't split on single whitespace)
        let mut iter = trimmed.splitn(2, char::is_whitespace);
        let pid_str = iter.next().unwrap_or("").trim();
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Rest of line: split on 2+ consecutive spaces to separate Name from Identifier
        let rest = iter.next().unwrap_or("").trim();
        let col_parts: Vec<&str> = {
            // Manual split on runs of 2+ spaces
            let mut parts = Vec::new();
            let mut start = 0;
            let bytes = rest.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if i + 1 < bytes.len() && bytes[i] == b' ' && bytes[i + 1] == b' ' {
                    parts.push(rest[start..i].trim());
                    while i < bytes.len() && bytes[i] == b' ' { i += 1; }
                    start = i;
                } else {
                    i += 1;
                }
            }
            parts.push(rest[start..].trim());
            parts.into_iter().filter(|s| !s.is_empty()).collect()
        };

        if col_parts.is_empty() {
            continue;
        }

        let name = col_parts[0].to_string();
        let identifier = if col_parts.len() >= 2 {
            col_parts[col_parts.len() - 1].to_string()
        } else {
            name.clone()
        };

        processes.push(FridaProcess { pid, name, identifier });
    }

    processes
}

// ─────────────────────────────────────────────────────────────────────────────
// Tiny UUID helper (avoids adding the uuid crate feature just for this)
// ─────────────────────────────────────────────────────────────────────────────

fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{:x}_{}", std::process::id(), nanos)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_frida_ps_basic() {
        let input = " PID  Name                    Identifier\n\
                     ----  ----------------------  ----------------------------------\n\
                     1234  My App                  com.example.myapp\n\
                     5678  Another App             org.test.app\n";
        let procs = parse_frida_ps_output(input);
        assert_eq!(procs.len(), 2);
        assert_eq!(procs[0].pid, 1234);
        assert_eq!(procs[0].identifier, "com.example.myapp");
        assert_eq!(procs[1].pid, 5678);
    }

    #[test]
    fn test_parse_frida_ps_empty() {
        let procs = parse_frida_ps_output("");
        assert!(procs.is_empty());
    }

    #[test]
    fn test_builtin_scripts_nonempty() {
        assert!(!get_builtin_script_content(BuiltinScript::SslPinningBypass).is_empty());
        assert!(!get_builtin_script_content(BuiltinScript::RootDetectionBypass).is_empty());
        assert!(!get_builtin_script_content(BuiltinScript::CryptoLogger).is_empty());
        assert!(!get_builtin_script_content(BuiltinScript::AntiDebugBypass).is_empty());
        assert!(!get_builtin_script_content(BuiltinScript::ApiMonitor).is_empty());
    }

    #[test]
    fn test_device_args() {
        let usb = FridaClient::new(FridaDevice::Usb);
        assert_eq!(usb.device_args(), vec!["-U"]);

        let local = FridaClient::new(FridaDevice::Local);
        assert!(local.device_args().is_empty());
    }
}
