// CVE correlation engine — cross-references detected library versions against
// the NVD CVE database (NVD API v2).
//
// Rate limiting: 6 second delay between requests without an API key.
// Set NVD_API_KEY env var for higher rate limits.

use crate::scanner::ScanFinding;
use anyhow::Result;
use reqwest::Client;
use std::path::PathBuf;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LibraryVersion {
    pub name: String,
    pub version: String,
    /// How it was detected (e.g. Java package prefix)
    pub package_pattern: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CveEntry {
    pub cve_id: String,
    pub description: String,
    pub cvss_score: Option<f32>,
    pub cvss_severity: String,
    pub published: String,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LibraryCveResult {
    pub library: LibraryVersion,
    pub cves: Vec<CveEntry>,
    pub highest_cvss: Option<f32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Known library patterns: (import_prefix, canonical_name, nvd_keyword)
// ─────────────────────────────────────────────────────────────────────────────

static LIBRARY_PATTERNS: &[(&str, &str, &str)] = &[
    ("import okhttp3.",                   "OkHttp",       "okhttp"),
    ("import retrofit2.",                 "Retrofit",     "retrofit"),
    ("import com.google.gson.",           "Gson",         "gson google"),
    ("import org.springframework.",       "Spring",       "spring framework"),
    ("import com.squareup.picasso.",      "Picasso",      "picasso squareup"),
    ("import com.bumptech.glide.",        "Glide",        "glide bumptech"),
    ("import io.reactivex.rxjava3.",      "RxJava",       "rxjava"),
    ("import io.reactivex.",              "RxJava",       "rxjava"),
    ("import com.facebook.react.",        "React Native", "react native facebook"),
    ("import com.google.firebase.",       "Firebase",     "firebase google"),
    ("import androidx.",                  "AndroidX",     "androidx jetpack"),
];

// ─────────────────────────────────────────────────────────────────────────────
// Library detection
// ─────────────────────────────────────────────────────────────────────────────

/// Detect library versions from Java/Kotlin source files.
pub fn detect_library_versions(java_files: &[PathBuf]) -> Vec<LibraryVersion> {
    use std::collections::HashMap;

    // Track which library names we've already emitted so we don't duplicate.
    let mut found: HashMap<String, LibraryVersion> = HashMap::new();

    for file in java_files {
        let content = match std::fs::read_to_string(file) {
            Ok(c)  => c,
            Err(_) => continue,
        };

        for &(pattern, name, _nvd_kw) in LIBRARY_PATTERNS {
            if found.contains_key(name) {
                continue;
            }
            if !content.contains(pattern) {
                continue;
            }

            // Attempt to extract a version string near the import.
            // Look for patterns like:  "OkHttp/4.9.3"  or  // v2.9.0
            let version = extract_version_hint(&content, name)
                .unwrap_or_else(|| "unknown".to_string());

            found.insert(name.to_string(), LibraryVersion {
                name: name.to_string(),
                version,
                package_pattern: pattern.to_string(),
            });
        }

        // Stop early if we found all libraries
        if found.len() == LIBRARY_PATTERNS.len() {
            break;
        }
    }

    found.into_values().collect()
}

/// Try to find a version string in the file content related to the library.
fn extract_version_hint(content: &str, lib_name: &str) -> Option<String> {
    // Patterns we look for:
    //   "OkHttp/4.9.3"
    //   Retrofit/2.9.0
    //   // v2.9.0
    //   version = "4.9.3"
    //   VERSION = "3.14.9"
    let lib_lower = lib_name.to_lowercase();

    for line in content.lines() {
        let line_lower = line.to_lowercase();
        if !line_lower.contains(&lib_lower) && !line_lower.contains("version") {
            continue;
        }

        // Try: LibName/X.Y.Z
        if let Some(ver) = extract_slash_version(line, lib_name) {
            return Some(ver);
        }

        // Try: // v<semver>  or  // Version X.Y.Z
        if let Some(ver) = extract_comment_version(line) {
            return Some(ver);
        }

        // Try: "X.Y.Z"  (bare version in a string literal)
        if let Some(ver) = extract_quoted_version(line) {
            return Some(ver);
        }
    }
    None
}

fn extract_slash_version(line: &str, lib_name: &str) -> Option<String> {
    // e.g.  "OkHttp/4.9.3"
    let key = format!("{}/", lib_name);
    let start = line.to_lowercase().find(&key.to_lowercase())? + key.len();
    let rest = &line[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(rest.len());
    let ver = &rest[..end];
    if ver.is_empty() || !ver.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        return None;
    }
    Some(ver.to_string())
}

fn extract_comment_version(line: &str) -> Option<String> {
    // e.g.  // v2.9.0   or  # v1.2.3
    let re_str = r"[/#*]\s*v?(\d+\.\d+[\.\d]*)";
    let re = regex::Regex::new(re_str).ok()?;
    let caps = re.captures(line)?;
    Some(caps[1].to_string())
}

fn extract_quoted_version(line: &str) -> Option<String> {
    // e.g.  version = "4.9.3"
    let re = regex::Regex::new(r#"["'](\d+\.\d+[\.\d]*)["']"#).ok()?;
    let caps = re.captures(line)?;
    Some(caps[1].to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// NVD API query
// ─────────────────────────────────────────────────────────────────────────────

/// Query NVD for CVEs affecting a library.
/// Uses NVD API v2: https://services.nvd.nist.gov/rest/json/cves/2.0
pub async fn query_nvd_cves(library: &LibraryVersion) -> Result<Vec<CveEntry>> {
    // Find the NVD keyword for this library
    let nvd_keyword = LIBRARY_PATTERNS
        .iter()
        .find(|&&(_, name, _)| name == library.name)
        .map(|&(_, _, kw)| kw)
        .unwrap_or(&library.name);

    let nvd_api_key = std::env::var("NVD_API_KEY").ok();

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default();

    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&cvssV3Severity=HIGH",
        urlencoding_simple(nvd_keyword),
    );

    let mut req = client.get(&url);
    if let Some(ref key) = nvd_api_key {
        req = req.header("apiKey", key);
    }

    let resp = match req.send().await {
        Ok(r)  => r,
        Err(e) => {
            tracing::warn!("NVD request for {} failed: {}", library.name, e);
            return Ok(Vec::new());
        }
    };

    if !resp.status().is_success() {
        tracing::warn!("NVD API returned {} for {}", resp.status(), library.name);
        return Ok(Vec::new());
    }

    let json: serde_json::Value = match resp.json().await {
        Ok(j)  => j,
        Err(e) => {
            tracing::warn!("NVD JSON parse error for {}: {}", library.name, e);
            return Ok(Vec::new());
        }
    };

    let vulnerabilities = match json["vulnerabilities"].as_array() {
        Some(v) => v,
        None    => return Ok(Vec::new()),
    };

    let mut cves: Vec<CveEntry> = Vec::new();

    for vuln in vulnerabilities {
        let cve_obj = &vuln["cve"];

        // Extract CVSS v3.1 score (filter: only >= 7.0)
        let (cvss_score, cvss_severity) = extract_cvss_v31(cve_obj);

        let score_val = cvss_score.unwrap_or(0.0);
        if score_val < 7.0 {
            continue;
        }

        let cve_id = cve_obj["id"].as_str().unwrap_or("").to_string();
        if cve_id.is_empty() {
            continue;
        }

        let description = cve_obj["descriptions"]
            .as_array()
            .and_then(|arr| {
                arr.iter()
                    .find(|d| d["lang"].as_str() == Some("en"))
                    .and_then(|d| d["value"].as_str())
            })
            .unwrap_or("")
            .to_string();

        let published = cve_obj["published"].as_str().unwrap_or("").to_string();

        let references: Vec<String> = cve_obj["references"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .take(3)
                    .filter_map(|r| r["url"].as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        cves.push(CveEntry {
            cve_id,
            description,
            cvss_score,
            cvss_severity,
            published,
            references,
        });

        // Cap at 5 CVEs per library
        if cves.len() >= 5 {
            break;
        }
    }

    Ok(cves)
}

fn extract_cvss_v31(cve_obj: &serde_json::Value) -> (Option<f32>, String) {
    if let Some(arr) = cve_obj["metrics"]["cvssMetricV31"].as_array() {
        if let Some(metric) = arr.first() {
            let score = metric["cvssData"]["baseScore"]
                .as_f64()
                .map(|s| s as f32);
            let severity = metric["cvssData"]["baseSeverity"]
                .as_str()
                .unwrap_or("UNKNOWN")
                .to_string();
            return (score, severity);
        }
    }
    // Fall back to v30
    if let Some(arr) = cve_obj["metrics"]["cvssMetricV30"].as_array() {
        if let Some(metric) = arr.first() {
            let score = metric["cvssData"]["baseScore"]
                .as_f64()
                .map(|s| s as f32);
            let severity = metric["cvssData"]["baseSeverity"]
                .as_str()
                .unwrap_or("UNKNOWN")
                .to_string();
            return (score, severity);
        }
    }
    (None, "UNKNOWN".to_string())
}

/// Minimal percent-encode for a search keyword (spaces → %20).
fn urlencoding_simple(s: &str) -> String {
    s.chars().map(|c| if c == ' ' { "%20".to_string() } else { c.to_string() }).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Correlate all detected libraries
// ─────────────────────────────────────────────────────────────────────────────

/// Correlate all detected libraries with CVEs.
/// Adds a 6-second delay between NVD requests if no API key is set.
pub async fn correlate_cves(java_files: &[PathBuf]) -> Result<Vec<LibraryCveResult>> {
    let libraries = detect_library_versions(java_files);

    if libraries.is_empty() {
        return Ok(Vec::new());
    }

    let has_api_key = std::env::var("NVD_API_KEY").is_ok();
    let mut results: Vec<LibraryCveResult> = Vec::new();

    for (i, library) in libraries.iter().enumerate() {
        // Rate limiting: 6 second delay between requests without API key
        if i > 0 && !has_api_key {
            tokio::time::sleep(std::time::Duration::from_secs(6)).await;
        }

        tracing::debug!("Querying NVD for library: {} {}", library.name, library.version);

        let cves = query_nvd_cves(library).await.unwrap_or_default();

        let highest_cvss = cves
            .iter()
            .filter_map(|c| c.cvss_score)
            .reduce(f32::max);

        results.push(LibraryCveResult {
            library: library.clone(),
            cves,
            highest_cvss,
        });
    }

    Ok(results)
}

// ─────────────────────────────────────────────────────────────────────────────
// Convert CVE results to ScanFindings
// ─────────────────────────────────────────────────────────────────────────────

/// Convert CVE correlation results into ScanFindings.
pub fn cve_to_findings(results: &[LibraryCveResult]) -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    for result in results {
        if result.cves.is_empty() {
            continue;
        }

        let highest = result.highest_cvss.unwrap_or(0.0);
        let severity = if highest >= 9.0 {
            "critical"
        } else if highest >= 7.0 {
            "high"
        } else if highest >= 4.0 {
            "medium"
        } else {
            "low"
        };

        let cve_ids: Vec<&str> = result.cves.iter().map(|c| c.cve_id.as_str()).collect();
        let evidence = format!("CVE IDs: {}", cve_ids.join(", "));

        let title = format!(
            "Library {} {} has {} known CVEs (highest: CVSSv3 {:.1})",
            result.library.name,
            result.library.version,
            result.cves.len(),
            highest,
        );

        findings.push(ScanFinding {
            rule_id: "cve_correlation".to_string(),
            title,
            severity: severity.to_string(),
            description: format!(
                "The library '{}' (version: {}) has {} known CVEs with CVSS score >= 7.0. \
                Detected via import pattern: {}",
                result.library.name,
                result.library.version,
                result.cves.len(),
                result.library.package_pattern,
            ),
            file_path: None,
            line_number: None,
            cwe: Some("CWE-1104".to_string()),
            owasp: Some("m8".to_string()),
            masvs: None,
            evidence: Some(evidence),
        });
    }

    findings
}
