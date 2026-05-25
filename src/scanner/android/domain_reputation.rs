// Google Safe Browsing v4 domain reputation check
use anyhow::Result;
use crate::scanner::ScanFinding;

// Compile the URL regex once at startup (stable since Rust 1.80)
static URL_RE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r#"https?://[^\s"'<>]+"#).unwrap());

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SafeBrowsingMatch {
    pub url: String,
    pub threat_type: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal API request/response types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct SbClient {
    #[serde(rename = "clientId")]
    client_id: String,
    #[serde(rename = "clientVersion")]
    client_version: String,
}

#[derive(serde::Serialize)]
struct SbThreatEntry {
    url: String,
}

#[derive(serde::Serialize)]
struct SbThreatInfo {
    #[serde(rename = "threatTypes")]
    threat_types: Vec<String>,
    #[serde(rename = "platformTypes")]
    platform_types: Vec<String>,
    #[serde(rename = "threatEntryTypes")]
    threat_entry_types: Vec<String>,
    #[serde(rename = "threatEntries")]
    threat_entries: Vec<SbThreatEntry>,
}

#[derive(serde::Serialize)]
struct SbRequest {
    client: SbClient,
    #[serde(rename = "threatInfo")]
    threat_info: SbThreatInfo,
}

#[derive(serde::Deserialize)]
struct SbResponse {
    matches: Option<Vec<SbMatch>>,
}

#[derive(serde::Deserialize)]
struct SbMatch {
    #[serde(rename = "threatType")]
    threat_type: String,
    threat: SbThreat,
}

#[derive(serde::Deserialize)]
struct SbThreat {
    url: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// URL normalization helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Normalize a URL: lowercase the hostname and strip the fragment.
fn normalize_url(url: &str) -> String {
    // Strip fragment
    let without_fragment = if let Some(pos) = url.find('#') {
        &url[..pos]
    } else {
        url
    };

    // Lowercase the scheme+host portion only
    // Find end of authority (scheme://host[:port])
    if let Some(after_scheme) = without_fragment.find("://") {
        let scheme = &without_fragment[..after_scheme];
        let rest = &without_fragment[after_scheme + 3..];
        // Find end of host (before first '/' or end of string)
        let host_end = rest.find('/').unwrap_or(rest.len());
        let host = &rest[..host_end];
        let path = &rest[host_end..];
        format!("{}://{}{}", scheme.to_lowercase(), host.to_lowercase(), path)
    } else {
        without_fragment.to_string()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Extract HTTP/HTTPS URLs from a list of raw strings (from strings extraction).
/// Filters out obviously-internal URLs (localhost, 192.168., 10., 127.).
pub fn extract_urls_from_strings(strings: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut urls: Vec<String> = Vec::new();

    for s in strings {
        for m in URL_RE.find_iter(s) {
            let raw = m.as_str();
            // Filter internal addresses
            if is_internal_url(raw) {
                continue;
            }
            let normalized = normalize_url(raw);
            if seen.insert(normalized.clone()) {
                urls.push(normalized);
            }
        }
    }

    urls
}

/// Returns true if the URL points to an internal/private address.
fn is_internal_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    lower.contains("localhost")
        || lower.contains("127.")
        || lower.contains("192.168.")
        // 10.x.x.x: use precise host-only check to avoid false positives like example10.com
        || is_rfc1918_ten_block(url)
}

/// More precise check for 10.x.x.x to avoid filtering e.g. example10.com.
fn is_rfc1918_ten_block(url: &str) -> bool {
    if let Some(after_scheme) = url.find("://") {
        let rest = &url[after_scheme + 3..];
        let host_end = rest.find('/').unwrap_or(rest.len());
        let host = &rest[..host_end].to_lowercase();
        // host is like "10.0.0.1" or "10.0.0.1:8080"
        let host_no_port = host.split(':').next().unwrap_or(host);
        host_no_port.starts_with("10.")
    } else {
        false
    }
}

/// Check a list of URLs against Google Safe Browsing v4 API.
/// Returns Ok(vec) where each entry is a matched URL + threat type.
/// Returns Ok(empty) if GOOGLE_SAFE_BROWSING_API_KEY not set or no threats found.
pub async fn check_urls(urls: &[String]) -> Result<Vec<SafeBrowsingMatch>> {
    let api_key = match std::env::var("GOOGLE_SAFE_BROWSING_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            // Graceful degradation — no key configured
            return Ok(Vec::new());
        }
    };

    if urls.is_empty() {
        return Ok(Vec::new());
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    // Build base URL without embedding the key (keeps key out of logs/error messages)
    let base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find";

    let mut all_matches: Vec<SafeBrowsingMatch> = Vec::new();

    // Process in chunks of 500 (API limit)
    let chunks: Vec<&[String]> = urls.chunks(500).collect();
    let total_chunks = chunks.len();
    let mut completed_chunks = 0usize;

    for chunk in &chunks {
        let threat_entries: Vec<SbThreatEntry> = chunk
            .iter()
            .map(|u| SbThreatEntry { url: u.clone() })
            .collect();

        let request_body = SbRequest {
            client: SbClient {
                client_id: "lancer-mobsf".to_string(),
                client_version: "0.1.0".to_string(),
            },
            threat_info: SbThreatInfo {
                threat_types: vec![
                    "MALWARE".to_string(),
                    "SOCIAL_ENGINEERING".to_string(),
                    "UNWANTED_SOFTWARE".to_string(),
                    "POTENTIALLY_HARMFUL_APPLICATION".to_string(),
                ],
                platform_types: vec!["ANY_PLATFORM".to_string()],
                threat_entry_types: vec!["URL".to_string()],
                threat_entries,
            },
        };

        // Pass the API key as a query parameter so it never appears in logged URL strings
        let response = match client
            .post(base_url)
            .query(&[("key", &api_key)])
            .json(&request_body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Safe Browsing API request failed: {}", e);
                tracing::warn!(
                    "Safe Browsing check partially failed: only {} of {} chunks completed",
                    completed_chunks,
                    total_chunks
                );
                return Ok(all_matches);
            }
        };

        if !response.status().is_success() {
            tracing::warn!(
                "Safe Browsing API returned non-200 status: {}",
                response.status()
            );
            tracing::warn!(
                "Safe Browsing check partially failed: only {} of {} chunks completed",
                completed_chunks,
                total_chunks
            );
            return Ok(all_matches);
        }

        let sb_response: SbResponse = match response.json().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Failed to parse Safe Browsing API response: {}", e);
                tracing::warn!(
                    "Safe Browsing check partially failed: only {} of {} chunks completed",
                    completed_chunks,
                    total_chunks
                );
                return Ok(all_matches);
            }
        };

        if let Some(matches) = sb_response.matches {
            for m in matches {
                all_matches.push(SafeBrowsingMatch {
                    url: m.threat.url,
                    threat_type: m.threat_type,
                });
            }
        }

        completed_chunks += 1;
    }

    Ok(all_matches)
}

/// Convert Safe Browsing matches to ScanFindings.
pub fn safe_browsing_findings(matches: &[SafeBrowsingMatch]) -> Vec<ScanFinding> {
    matches
        .iter()
        .map(|m| {
            let is_high = matches!(
                m.threat_type.as_str(),
                "MALWARE" | "SOCIAL_ENGINEERING"
            );

            let (severity, rule_id, title) = if is_high {
                (
                    "high",
                    "android_domain_reputation_malware",
                    format!("Malicious URL Detected: {}", m.url),
                )
            } else {
                (
                    "medium",
                    "android_domain_reputation_suspicious",
                    format!("Suspicious URL Detected: {}", m.url),
                )
            };

            ScanFinding {
                rule_id: rule_id.to_string(),
                title,
                severity: severity.to_string(),
                description: format!(
                    "URL '{}' was flagged by Google Safe Browsing as {}. \
                     Remove or replace this URL to protect users.",
                    m.url, m.threat_type
                ),
                file_path: None,
                line_number: None,
                cwe: Some("CWE-829".to_string()),
                owasp: Some("m3".to_string()),
                masvs: Some("network-1".to_string()),
                evidence: Some(format!("threat_type: {}", m.threat_type)),
            }
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_urls_from_strings() {
        let strings = vec![
            "https://api.example.com/v1/data".to_string(),
            "http://192.168.1.1/admin".to_string(),
            "http://localhost:8080/api".to_string(),
            "http://127.0.0.1/health".to_string(),
            "http://10.0.0.1/internal".to_string(),
            "https://malware.example.org/payload#fragment".to_string(),
            "no url here".to_string(),
            "https://another.site.com/path?q=1".to_string(),
        ];

        let urls = extract_urls_from_strings(&strings);

        // Should include external URLs
        assert!(urls.contains(&"https://api.example.com/v1/data".to_string()));
        assert!(urls.contains(&"https://malware.example.org/payload".to_string())); // fragment stripped
        assert!(urls.contains(&"https://another.site.com/path?q=1".to_string()));

        // Should NOT include internal/private URLs
        assert!(!urls.iter().any(|u| u.contains("192.168.")));
        assert!(!urls.iter().any(|u| u.contains("localhost")));
        assert!(!urls.iter().any(|u| u.contains("127.")));
        assert!(!urls.iter().any(|u| u.contains("10.0.0")));

        // Fragment should be stripped
        assert!(!urls.iter().any(|u| u.contains('#')));
    }

    #[test]
    fn test_safe_browsing_findings_severity_mapping() {
        let matches = vec![
            SafeBrowsingMatch {
                url: "http://evil.com".to_string(),
                threat_type: "MALWARE".to_string(),
            },
            SafeBrowsingMatch {
                url: "http://phishing.com".to_string(),
                threat_type: "SOCIAL_ENGINEERING".to_string(),
            },
            SafeBrowsingMatch {
                url: "http://pup.com".to_string(),
                threat_type: "UNWANTED_SOFTWARE".to_string(),
            },
            SafeBrowsingMatch {
                url: "http://harmful.com".to_string(),
                threat_type: "POTENTIALLY_HARMFUL_APPLICATION".to_string(),
            },
        ];

        let findings = safe_browsing_findings(&matches);

        assert_eq!(findings.len(), 4);

        // MALWARE -> high + malware rule
        let malware_finding = &findings[0];
        assert_eq!(malware_finding.severity, "high");
        assert_eq!(malware_finding.rule_id, "android_domain_reputation_malware");
        assert!(malware_finding.title.contains("Malicious URL Detected"));
        assert_eq!(malware_finding.owasp.as_deref(), Some("m3"));
        assert_eq!(malware_finding.masvs.as_deref(), Some("network-1"));

        // SOCIAL_ENGINEERING -> high
        let social_finding = &findings[1];
        assert_eq!(social_finding.severity, "high");
        assert_eq!(social_finding.rule_id, "android_domain_reputation_malware");

        // UNWANTED_SOFTWARE -> medium + suspicious rule
        let pup_finding = &findings[2];
        assert_eq!(pup_finding.severity, "medium");
        assert_eq!(pup_finding.rule_id, "android_domain_reputation_suspicious");
        assert!(pup_finding.title.contains("Suspicious URL Detected"));

        // POTENTIALLY_HARMFUL_APPLICATION -> medium
        let pha_finding = &findings[3];
        assert_eq!(pha_finding.severity, "medium");
        assert_eq!(pha_finding.rule_id, "android_domain_reputation_suspicious");
    }
}
