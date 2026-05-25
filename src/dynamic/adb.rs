// ADB interaction - shells out to the `adb` command-line tool

use std::path::Path;
use std::time::Duration;
use anyhow::{bail, Context, Result};
use tracing::{debug, info, warn};

use crate::scanner::android::manifest::ParsedManifest;

// ─────────────────────────────────────────────────────────────────────────────
// Data types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct AdbDevice {
    pub serial: String,
    /// "device", "offline", "unauthorized", "emulator"
    pub state: String,
    pub model: String,
    pub product: String,
}

pub struct AdbClient {
    /// If None, uses the first available device (adb picks it)
    pub device_serial: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ActivityTestResult {
    pub activity: String,
    pub launched: bool,
    pub crashed: bool,
    pub crash_log: Option<String>,
    pub response_time_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// AdbClient implementation
// ─────────────────────────────────────────────────────────────────────────────

impl AdbClient {
    pub fn new(serial: Option<String>) -> Self {
        Self { device_serial: serial }
    }

    /// List connected ADB devices by parsing `adb devices -l`.
    pub async fn list_devices() -> Result<Vec<AdbDevice>> {
        let output = tokio::time::timeout(
            Duration::from_secs(30),
            tokio::process::Command::new("adb")
                .args(["devices", "-l"])
                .output(),
        )
        .await
        .context("adb devices timed out")??;

        let stdout = String::from_utf8_lossy(&output.stdout);
        debug!("adb devices -l output:\n{}", stdout);

        let mut devices = Vec::new();
        for line in stdout.lines().skip(1) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Format: "serial  state  product:xxx model:yyy device:zzz"
            let mut parts = line.splitn(2, char::is_whitespace);
            let serial = match parts.next() {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => continue,
            };
            let rest = parts.next().unwrap_or("").trim();

            // Determine state (second whitespace-separated token)
            let mut rest_iter = rest.split_whitespace();
            let state = rest_iter.next().unwrap_or("unknown").to_string();

            // Extract model / product from key:value pairs
            let mut model = String::new();
            let mut product = String::new();
            for token in rest_iter {
                if let Some(v) = token.strip_prefix("model:") {
                    model = v.to_string();
                } else if let Some(v) = token.strip_prefix("product:") {
                    product = v.to_string();
                }
            }

            devices.push(AdbDevice { serial, state, model, product });
        }

        Ok(devices)
    }

    /// Returns true if `adb` is on PATH and responds to `adb version`.
    pub async fn is_available() -> bool {
        match tokio::time::timeout(
            Duration::from_secs(5),
            tokio::process::Command::new("adb").arg("version").output(),
        )
        .await
        {
            Ok(Ok(o)) => o.status.success(),
            _ => false,
        }
    }

    /// Push a local file to `remote` path on the device.
    pub async fn push(&self, local: &Path, remote: &str) -> Result<()> {
        let mut cmd = self.build_adb_cmd();
        cmd.arg("push")
            .arg(local.as_os_str())
            .arg(remote);
        self.run_with_timeout(cmd, 30).await?;
        Ok(())
    }

    /// Pull a file from `remote` on the device to `local`.
    pub async fn pull(&self, remote: &str, local: &Path) -> Result<()> {
        let mut cmd = self.build_adb_cmd();
        cmd.arg("pull").arg(remote).arg(local.as_os_str());
        self.run_with_timeout(cmd, 30).await?;
        Ok(())
    }

    /// Install an APK on the device (`-r` = reinstall if already present).
    pub async fn install(&self, apk_path: &Path) -> Result<()> {
        let mut cmd = self.build_adb_cmd();
        cmd.arg("install").arg("-r").arg(apk_path.as_os_str());
        info!("Installing APK: {}", apk_path.display());
        self.run_with_timeout(cmd, 300).await?;
        Ok(())
    }

    /// Uninstall a package from the device.
    pub async fn uninstall(&self, package: &str) -> Result<()> {
        let mut cmd = self.build_adb_cmd();
        cmd.arg("uninstall").arg(package);
        self.run_with_timeout(cmd, 30).await?;
        Ok(())
    }

    /// Run an arbitrary `adb shell` command and return stdout.
    pub async fn shell(&self, shell_cmd: &str) -> Result<String> {
        let mut cmd = self.build_adb_cmd();
        cmd.arg("shell").arg(shell_cmd);
        let out = self.run_with_timeout(cmd, 30).await?;
        Ok(out)
    }

    /// Launch an activity with `am start -n <package>/<activity>` and return am output.
    pub async fn start_activity(&self, package: &str, activity: &str) -> Result<String> {
        let target = format!("{}/{}", package, activity);
        self.shell(&format!("am start -n {}", target)).await
    }

    /// Capture the last `lines` lines from logcat (`-d` = dump and exit).
    pub async fn logcat(&self, lines: usize) -> Result<String> {
        let mut cmd = self.build_adb_cmd();
        cmd.arg("logcat").arg("-d").arg("-t").arg(lines.to_string());
        self.run_with_timeout(cmd, 30).await
    }

    /// Take a screenshot and save it to `output` on the host.
    pub async fn screencap(&self, output: &Path) -> Result<()> {
        // Step 1: capture on device
        self.shell("screencap /sdcard/screencap.png").await
            .context("screencap on device failed")?;
        // Step 2: pull to host
        self.pull("/sdcard/screencap.png", output).await
            .context("pulling screencap failed")?;
        Ok(())
    }

    /// Forward `tcp:<local_port>` → `tcp:<device_port>`.
    pub async fn forward(&self, local_port: u16, device_port: u16) -> Result<()> {
        let mut cmd = self.build_adb_cmd();
        cmd.arg("forward")
            .arg(format!("tcp:{}", local_port))
            .arg(format!("tcp:{}", device_port));
        self.run_with_timeout(cmd, 30).await?;
        Ok(())
    }

    /// Dump package info via `dumpsys package <package>`.
    pub async fn dumpsys_package(&self, package: &str) -> Result<String> {
        self.shell(&format!("dumpsys package {}", package)).await
    }

    // ── private helpers ──────────────────────────────────────────────────────

    /// Build a base `tokio::process::Command` for adb, inserting `-s <serial>`
    /// when a device serial was provided.
    fn build_adb_cmd(&self) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new("adb");
        if let Some(ref serial) = self.device_serial {
            cmd.arg("-s").arg(serial);
        }
        cmd
    }

    /// Run `cmd`, collect stdout, and fail on non-zero exit or timeout.
    async fn run_with_timeout(
        &self,
        mut cmd: tokio::process::Command,
        timeout_secs: u64,
    ) -> Result<String> {
        let output = tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            cmd.output(),
        )
        .await
        .context("adb command timed out")??;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

        if !output.status.success() {
            let msg = if stderr.is_empty() { stdout.clone() } else { stderr };
            bail!("adb command failed ({}): {}", output.status, msg.trim());
        }

        if !stderr.is_empty() {
            debug!("adb stderr: {}", stderr.trim());
        }

        Ok(stdout)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Filesystem snapshot / delta
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct FsDelta {
    pub created: Vec<String>,
    pub deleted: Vec<String>,
    pub modified: Vec<String>,
}

impl AdbClient {
    /// Take a snapshot of the filesystem at `remote_path`.
    ///
    /// Runs `find <path> -type f -printf "%p %s %T@\n"` on the device and
    /// returns the raw output lines.  Each line contains
    /// `<path> <size_bytes> <mtime_unix>`.
    pub async fn fs_snapshot(&self, remote_path: &str) -> Result<Vec<String>> {
        // Use ls -la recursively as a fallback on devices without GNU find.
        // GNU find with -printf is the preferred approach.
        let cmd = format!(
            "find {} -type f -printf \"%p %s %T@\\n\" 2>/dev/null || true",
            remote_path
        );
        let raw = self.shell(&cmd).await.unwrap_or_default();
        let lines: Vec<String> = raw
            .lines()
            .map(|l| l.to_string())
            .filter(|l| !l.is_empty())
            .collect();
        Ok(lines)
    }

    /// Compute the delta between two filesystem snapshots.
    pub fn fs_delta(before: &[String], after: &[String]) -> FsDelta {
        use std::collections::HashMap;

        // Parse "path size mtime" triples into a HashMap<path, (size, mtime)>
        fn parse_snapshot(lines: &[String]) -> HashMap<String, (String, String)> {
            let mut map = HashMap::new();
            for line in lines {
                let parts: Vec<&str> = line.splitn(3, ' ').collect();
                if parts.len() >= 3 {
                    map.insert(
                        parts[0].to_string(),
                        (parts[1].to_string(), parts[2].to_string()),
                    );
                } else if parts.len() == 2 {
                    map.insert(
                        parts[0].to_string(),
                        (parts[1].to_string(), String::new()),
                    );
                } else if !line.is_empty() {
                    map.insert(line.to_string(), (String::new(), String::new()));
                }
            }
            map
        }

        let before_map = parse_snapshot(before);
        let after_map = parse_snapshot(after);

        let mut created = Vec::new();
        let mut deleted = Vec::new();
        let mut modified = Vec::new();

        // Files in after but not in before → created
        // Files in after that differ from before → modified
        for (path, after_meta) in &after_map {
            match before_map.get(path) {
                None => created.push(path.clone()),
                Some(before_meta) => {
                    if before_meta != after_meta {
                        modified.push(path.clone());
                    }
                }
            }
        }

        // Files in before but not in after → deleted
        for path in before_map.keys() {
            if !after_map.contains_key(path) {
                deleted.push(path.clone());
            }
        }

        created.sort();
        deleted.sort();
        modified.sort();

        FsDelta { created, deleted, modified }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Activity tester (Part B)
// ─────────────────────────────────────────────────────────────────────────────

/// Test all exported activities from `manifest` against the live device.
///
/// An activity is considered "exported" when:
///   - `exported == Some(true)`, OR
///   - it has at least one intent-filter (implicit export on older SDK levels)
pub async fn test_exported_activities(
    adb: &AdbClient,
    manifest: &ParsedManifest,
    package: &str,
) -> Vec<ActivityTestResult> {
    let mut results = Vec::new();

    for activity in &manifest.activities {
        let is_exported = activity.exported == Some(true) || !activity.intent_filters.is_empty();
        if !is_exported {
            continue;
        }

        let activity_name = &activity.name;
        info!("Testing exported activity: {}/{}", package, activity_name);

        let start = std::time::Instant::now();

        // Launch the activity
        let launch_result = adb.start_activity(package, activity_name).await;
        let launched = launch_result.is_ok();

        if let Err(ref e) = launch_result {
            warn!("Failed to start activity {}: {}", activity_name, e);
        }

        // Wait 2 seconds for the activity to start / crash
        tokio::time::sleep(Duration::from_secs(2)).await;

        let response_time_ms = start.elapsed().as_millis() as u64;

        // Check logcat for crash signals
        let (crashed, crash_log) = match adb.logcat(200).await {
            Ok(log) => {
                let crashed = log.contains("FATAL EXCEPTION") || log.contains("AndroidRuntime");
                let crash_log = if crashed {
                    // Extract the relevant portion of the log
                    let snippet: String = log
                        .lines()
                        .filter(|l| {
                            l.contains("FATAL EXCEPTION")
                                || l.contains("AndroidRuntime")
                                || l.contains("at android.")
                                || l.contains("Caused by:")
                        })
                        .take(30)
                        .collect::<Vec<_>>()
                        .join("\n");
                    Some(snippet)
                } else {
                    None
                };
                (crashed, crash_log)
            }
            Err(e) => {
                warn!("logcat read failed: {}", e);
                (false, None)
            }
        };

        results.push(ActivityTestResult {
            activity: activity_name.clone(),
            launched,
            crashed,
            crash_log,
            response_time_ms,
        });
    }

    results
}
