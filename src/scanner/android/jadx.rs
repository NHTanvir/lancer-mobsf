// jadx subprocess wrapper

use std::path::{Path, PathBuf};
use anyhow::Result;
use tracing::{info, warn};

/// Output of a jadx decompilation run.
#[derive(Debug)]
pub struct JadxOutput {
    /// Directory containing decompiled .java files.
    pub java_src_dir: PathBuf,
    pub success: bool,
    pub error: Option<String>,
    pub file_count: usize,
}

/// Probe whether `jadx` (or `jadx.bat` on Windows) is available.
///
/// Returns the binary name/path to pass to `Command::new` if found, or `None`.
fn find_jadx() -> Option<String> {
    // Determine the platform-appropriate binary name.
    #[cfg(target_os = "windows")]
    let bin_name = "jadx.bat";
    #[cfg(not(target_os = "windows"))]
    let bin_name = "jadx";

    // 1. Try PATH via a quick --version probe.
    let probe = std::process::Command::new(bin_name)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    if probe.map(|s| s.success()).unwrap_or(false) {
        return Some(bin_name.to_string());
    }

    // 2. Check tools/jadx/bin/ relative to the current executable.
    if let Ok(exe) = std::env::current_exe() {
        // Walk up a couple of levels to find the project root with a `tools/` dir.
        for ancestor in exe.ancestors().take(5) {
            #[cfg(target_os = "windows")]
            let candidate = ancestor.join("tools").join("jadx").join("bin").join("jadx.bat");
            #[cfg(not(target_os = "windows"))]
            let candidate = ancestor.join("tools").join("jadx").join("bin").join("jadx");

            if candidate.exists() {
                let path_str = candidate.to_string_lossy().into_owned();
                // Quick probe
                let probe2 = std::process::Command::new(&path_str)
                    .arg("--version")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                if probe2.map(|s| s.success()).unwrap_or(false) {
                    return Some(path_str);
                }
                // Return path even without a successful probe if the file exists.
                return Some(path_str);
            }
        }
    }

    None
}

/// Walk `java_src_dir` recursively and return all `.java` file paths.
pub fn collect_java_files(java_src_dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if !java_src_dir.is_dir() {
        return files;
    }
    collect_java_files_inner(java_src_dir, &mut files);
    files
}

fn collect_java_files_inner(dir: &Path, out: &mut Vec<PathBuf>) {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_java_files_inner(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("java") {
            out.push(path);
        }
    }
}

/// Decompile an APK to Java source using jadx.
///
/// Looks for `jadx` / `jadx.bat` in PATH, then in `tools/jadx/bin/` relative
/// to the current executable.  Returns a `JadxOutput` with `success = false`
/// if jadx cannot be located.
///
/// The subprocess is given a 5-minute (300 s) timeout.
pub async fn decompile_with_jadx(apk_path: &Path, output_dir: &Path) -> Result<JadxOutput> {
    let java_src_dir = output_dir.join("sources");

    let jadx_bin = match find_jadx() {
        Some(b) => b,
        None => {
            warn!("jadx not found in PATH or tools/jadx/");
            return Ok(JadxOutput {
                java_src_dir,
                success: false,
                error: Some(
                    "jadx not found in PATH or tools/jadx/. \
                     Install jadx and ensure it is on the PATH."
                        .to_string(),
                ),
                file_count: 0,
            });
        }
    };

    // Ensure output directory exists.
    if let Err(e) = std::fs::create_dir_all(&java_src_dir) {
        return Ok(JadxOutput {
            java_src_dir,
            success: false,
            error: Some(format!("Failed to create output dir: {}", e)),
            file_count: 0,
        });
    }

    info!(
        "Running jadx: {} --deobf --show-bad-code -d {} {}",
        jadx_bin,
        java_src_dir.display(),
        apk_path.display()
    );

    let mut cmd = tokio::process::Command::new(&jadx_bin);
    cmd.arg("--deobf")
        .arg("--show-bad-code")
        .arg("-d")
        .arg(&java_src_dir)
        .arg(apk_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    // Spawn and apply a 5-minute timeout.
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return Ok(JadxOutput {
                java_src_dir,
                success: false,
                error: Some(format!("Failed to spawn jadx: {}", e)),
                file_count: 0,
            });
        }
    };

    let timeout_duration = std::time::Duration::from_secs(300);
    let output_result =
        tokio::time::timeout(timeout_duration, child.wait_with_output()).await;

    match output_result {
        Err(_elapsed) => {
            warn!("jadx timed out after 300 s for {}", apk_path.display());
            Ok(JadxOutput {
                java_src_dir,
                success: false,
                error: Some("jadx timed out after 300 seconds".to_string()),
                file_count: 0,
            })
        }
        Ok(Err(io_err)) => Ok(JadxOutput {
            java_src_dir,
            success: false,
            error: Some(format!("jadx I/O error: {}", io_err)),
            file_count: 0,
        }),
        Ok(Ok(output)) => {
            let stderr_text = String::from_utf8_lossy(&output.stderr).to_string();
            let success = output.status.success();

            if !success {
                warn!(
                    "jadx exited with status {:?} for {}",
                    output.status.code(),
                    apk_path.display()
                );
            }

            // Count .java files produced.
            let java_files = collect_java_files(&java_src_dir);
            let file_count = java_files.len();

            info!(
                "jadx finished: success={}, java_files={}",
                success, file_count
            );

            let error = if !success && !stderr_text.is_empty() {
                // Trim to a reasonable length to avoid giant log entries.
                let trimmed = if stderr_text.len() > 2048 {
                    format!("{}… (truncated)", &stderr_text[..2048])
                } else {
                    stderr_text.clone()
                };
                Some(trimmed)
            } else if !success {
                Some(format!(
                    "jadx exited with status {:?}",
                    output.status.code()
                ))
            } else {
                None
            };

            Ok(JadxOutput {
                java_src_dir,
                success,
                error,
                file_count,
            })
        }
    }
}
