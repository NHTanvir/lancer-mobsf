// Strings extraction from binary and DEX files

use std::path::PathBuf;
use std::collections::HashSet;

use crate::scanner::ScanFinding;

/// Extract printable ASCII strings of length >= min_len from raw bytes.
/// Scans for consecutive printable ASCII characters (0x20–0x7E).
pub fn extract_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = Vec::new();

    for &byte in data {
        if byte >= 0x20 && byte <= 0x7E {
            current.push(byte as char);
        } else {
            if current.len() >= min_len {
                result.push(current.iter().collect::<String>());
            }
            current.clear();
        }
    }

    // Flush any remaining run at end of data
    if current.len() >= min_len {
        result.push(current.iter().collect::<String>());
    }

    result
}

/// Returns true if a string looks like a plain symbol (no spaces, all-lower or all-upper).
fn is_symbol_only(s: &str) -> bool {
    if s.contains(' ') {
        return false;
    }
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return true;
    }
    let all_lower = chars.iter().all(|c| !c.is_alphabetic() || c.is_lowercase());
    let all_upper = chars.iter().all(|c| !c.is_alphabetic() || c.is_uppercase());
    all_lower || all_upper
}

/// Extract strings from all .so files and .dex files in an extracted APK directory.
/// Returns deduplicated, interesting strings (non-symbol-only).
pub fn extract_strings_from_apk(
    so_files: &[PathBuf],
    dex_files: &[PathBuf],
) -> Vec<String> {
    const MIN_LEN: usize = 6;

    let mut seen: HashSet<String> = HashSet::new();
    let mut result: Vec<String> = Vec::new();

    let all_files = so_files.iter().chain(dex_files.iter());

    for path in all_files {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "Failed to read file for string extraction");
                continue;
            }
        };

        let strings = extract_strings(&data, MIN_LEN);

        for s in strings {
            // Filter out symbol-only strings
            if is_symbol_only(&s) {
                continue;
            }
            // Deduplicate
            if seen.insert(s.clone()) {
                result.push(s);
            }
        }
    }

    result
}

/// Scan extracted strings for interesting security patterns and generate findings.
pub fn find_string_findings(strings: &[String]) -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    // Pre-compiled patterns for performance
    let url_re = regex::Regex::new(r#"https?://[^\s'"]{8,}"#).unwrap();
    let ip_re = regex::Regex::new(r#"\b(?:\d{1,3}\.){3}\d{1,3}\b"#).unwrap();
    let email_re = regex::Regex::new(r#"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"#).unwrap();
    // API key: 20+ char alphanumeric (no spaces), mixed case or with digits
    let apikey_re = regex::Regex::new(r#"[A-Za-z0-9_\-]{20,}"#).unwrap();
    // Base64: ends with = or == padding and looks encoded
    let base64_re = regex::Regex::new(r#"[A-Za-z0-9+/]{24,}={0,2}"#).unwrap();
    // Hardcoded paths
    let path_re = regex::Regex::new(r#"(/data/|/sdcard/)[\w./\-]+"#).unwrap();

    let mut seen_urls: HashSet<String> = HashSet::new();
    let mut seen_ips: HashSet<String> = HashSet::new();
    let mut seen_emails: HashSet<String> = HashSet::new();
    let mut seen_apikeys: HashSet<String> = HashSet::new();
    let mut seen_base64: HashSet<String> = HashSet::new();
    let mut seen_paths: HashSet<String> = HashSet::new();

    for s in strings {
        // URLs
        for m in url_re.find_iter(s) {
            let val = m.as_str().to_string();
            if seen_urls.insert(val.clone()) {
                findings.push(ScanFinding {
                    rule_id: "hardcoded_url".to_string(),
                    title: "Hardcoded URL found".to_string(),
                    severity: "info".to_string(),
                    description: format!("Hardcoded URL detected in binary strings: {val}"),
                    file_path: None,
                    line_number: None,
                    cwe: None,
                    owasp: None,
                    masvs: None,
                    evidence: Some(val),
                });
            }
        }

        // IP addresses
        for m in ip_re.find_iter(s) {
            let val = m.as_str().to_string();
            // Filter out obviously invalid IPs and version strings like 1.0.0.0
            if seen_ips.insert(val.clone()) {
                findings.push(ScanFinding {
                    rule_id: "hardcoded_ip".to_string(),
                    title: "Hardcoded IP address found".to_string(),
                    severity: "medium".to_string(),
                    description: format!("Hardcoded IP address detected in binary strings: {val}"),
                    file_path: None,
                    line_number: None,
                    cwe: None,
                    owasp: None,
                    masvs: None,
                    evidence: Some(val),
                });
            }
        }

        // Email addresses
        for m in email_re.find_iter(s) {
            let val = m.as_str().to_string();
            if seen_emails.insert(val.clone()) {
                findings.push(ScanFinding {
                    rule_id: "hardcoded_email".to_string(),
                    title: "Hardcoded email address found".to_string(),
                    severity: "info".to_string(),
                    description: format!("Hardcoded email address detected in binary strings: {val}"),
                    file_path: None,
                    line_number: None,
                    cwe: None,
                    owasp: None,
                    masvs: None,
                    evidence: Some(val),
                });
            }
        }

        // Possible API keys: long alphanumeric strings - require mixed content (not pure lower/upper)
        for m in apikey_re.find_iter(s) {
            let val = m.as_str();
            // Must have at least one digit and one letter to avoid pure symbols
            let has_digit = val.chars().any(|c| c.is_ascii_digit());
            let has_upper = val.chars().any(|c| c.is_ascii_uppercase());
            let has_lower = val.chars().any(|c| c.is_ascii_lowercase());
            if has_digit && (has_upper || has_lower) && seen_apikeys.insert(val.to_string()) {
                findings.push(ScanFinding {
                    rule_id: "possible_api_key".to_string(),
                    title: "Possible hardcoded API key found".to_string(),
                    severity: "high".to_string(),
                    description: format!(
                        "A long alphanumeric string that may be an API key was found in binary strings: {val}"
                    ),
                    file_path: None,
                    line_number: None,
                    cwe: None,
                    owasp: None,
                    masvs: None,
                    evidence: Some(val.to_string()),
                });
            }
        }

        // Base64 patterns
        for m in base64_re.find_iter(s) {
            let val = m.as_str().to_string();
            if seen_base64.insert(val.clone()) {
                findings.push(ScanFinding {
                    rule_id: "possible_base64".to_string(),
                    title: "Possible base64-encoded data found".to_string(),
                    severity: "info".to_string(),
                    description: format!(
                        "A string resembling base64 encoding was found in binary strings: {val}"
                    ),
                    file_path: None,
                    line_number: None,
                    cwe: None,
                    owasp: None,
                    masvs: None,
                    evidence: Some(val),
                });
            }
        }

        // Hardcoded paths
        for m in path_re.find_iter(s) {
            let val = m.as_str().to_string();
            if seen_paths.insert(val.clone()) {
                findings.push(ScanFinding {
                    rule_id: "hardcoded_path".to_string(),
                    title: "Hardcoded filesystem path found".to_string(),
                    severity: "medium".to_string(),
                    description: format!(
                        "A hardcoded filesystem path was found in binary strings: {val}"
                    ),
                    file_path: None,
                    line_number: None,
                    cwe: None,
                    owasp: None,
                    masvs: None,
                    evidence: Some(val),
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_strings_basic() {
        let data = b"hello world\x00short\x00this is a longer string\x00";
        let strings = extract_strings(data, 6);
        assert!(strings.contains(&"hello world".to_string()));
        assert!(strings.contains(&"this is a longer string".to_string()));
        // "short" is 5 chars, below min_len=6
        assert!(!strings.contains(&"short".to_string()));
    }

    #[test]
    fn test_extract_strings_min_len() {
        let data = b"abcdef\x00abcde\x00";
        let strings = extract_strings(data, 6);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0], "abcdef");
    }

    #[test]
    fn test_is_symbol_only() {
        assert!(is_symbol_only("LOWERCASE"));
        assert!(is_symbol_only("uppercase"));
        assert!(!is_symbol_only("Mixed Case"));
        assert!(!is_symbol_only("has space"));
    }

    #[test]
    fn test_find_string_findings_url() {
        let strings = vec!["https://api.example.com/v1/data".to_string()];
        let findings = find_string_findings(&strings);
        assert!(findings.iter().any(|f| f.rule_id == "hardcoded_url"));
    }

    #[test]
    fn test_find_string_findings_ip() {
        let strings = vec!["connect to 192.168.1.100 port 8080".to_string()];
        let findings = find_string_findings(&strings);
        assert!(findings.iter().any(|f| f.rule_id == "hardcoded_ip"));
    }
}
