// Hardcoded secrets scanner - gitleaks-style patterns
use crate::scanner::ScanFinding;
use regex::Regex;
use std::path::Path;

/// A single secret pattern.
struct SecretPattern {
    id: &'static str,
    name: &'static str,
    pattern: &'static str,
    severity: &'static str,
    confidence: &'static str,
    cwe: &'static str,
}

static PATTERNS: &[SecretPattern] = &[
    // AWS
    SecretPattern {
        id: "aws_access_key",
        name: "AWS Access Key ID",
        pattern: r"AKIA[0-9A-Z]{16}",
        severity: "critical",
        confidence: "high",
        cwe: "CWE-798",
    },
    SecretPattern {
        id: "aws_secret_key",
        name: "AWS Secret Access Key",
        pattern: r#"(?i)(aws_secret|aws_secret_access_key)\s*[=:]\s*['"][0-9a-zA-Z/+]{40}"#,
        severity: "critical",
        confidence: "high",
        cwe: "CWE-798",
    },
    // Google
    SecretPattern {
        id: "google_api_key",
        name: "Google API Key",
        pattern: r"AIza[0-9A-Za-z_-]{35}",
        severity: "high",
        confidence: "high",
        cwe: "CWE-798",
    },
    SecretPattern {
        id: "google_oauth",
        name: "Google OAuth Client ID",
        pattern: r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        severity: "high",
        confidence: "high",
        cwe: "CWE-798",
    },
    // GitHub
    SecretPattern {
        id: "github_token",
        name: "GitHub Personal Access Token",
        pattern: r"ghp_[0-9a-zA-Z]{36}",
        severity: "critical",
        confidence: "high",
        cwe: "CWE-798",
    },
    SecretPattern {
        id: "github_app_token",
        name: "GitHub App Token",
        pattern: r"ghs_[0-9a-zA-Z]{36}",
        severity: "critical",
        confidence: "high",
        cwe: "CWE-798",
    },
    // JWT
    SecretPattern {
        id: "jwt_token",
        name: "JSON Web Token",
        pattern: r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        severity: "high",
        confidence: "high",
        cwe: "CWE-522",
    },
    // Stripe
    SecretPattern {
        id: "stripe_live_key",
        name: "Stripe Live Secret Key",
        pattern: r"sk_live_[0-9a-zA-Z]{24}",
        severity: "critical",
        confidence: "high",
        cwe: "CWE-798",
    },
    SecretPattern {
        id: "stripe_test_key",
        name: "Stripe Test Secret Key",
        pattern: r"sk_test_[0-9a-zA-Z]{24}",
        severity: "medium",
        confidence: "high",
        cwe: "CWE-798",
    },
    // Slack
    SecretPattern {
        id: "slack_token",
        name: "Slack API Token",
        pattern: r"xox[baprs]-[0-9a-zA-Z]{10,}",
        severity: "critical",
        confidence: "high",
        cwe: "CWE-798",
    },
    SecretPattern {
        id: "slack_webhook",
        name: "Slack Incoming Webhook URL",
        pattern: r"https://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+",
        severity: "high",
        confidence: "high",
        cwe: "CWE-798",
    },
    // Firebase
    SecretPattern {
        id: "firebase_server_key",
        name: "Firebase Server Key (FCM)",
        pattern: r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
        severity: "critical",
        confidence: "high",
        cwe: "CWE-798",
    },
    // Private Keys
    SecretPattern {
        id: "rsa_private_key",
        name: "RSA Private Key",
        pattern: r"-----BEGIN RSA PRIVATE KEY-----",
        severity: "critical",
        confidence: "high",
        cwe: "CWE-321",
    },
    SecretPattern {
        id: "ec_private_key",
        name: "EC Private Key",
        pattern: r"-----BEGIN EC PRIVATE KEY-----",
        severity: "critical",
        confidence: "high",
        cwe: "CWE-321",
    },
    SecretPattern {
        id: "private_key",
        name: "PKCS8 Private Key",
        pattern: r"-----BEGIN PRIVATE KEY-----",
        severity: "critical",
        confidence: "high",
        cwe: "CWE-321",
    },
    SecretPattern {
        id: "openssh_private_key",
        name: "OpenSSH Private Key",
        pattern: r"-----BEGIN OPENSSH PRIVATE KEY-----",
        severity: "critical",
        confidence: "high",
        cwe: "CWE-321",
    },
    // Passwords / Secrets
    SecretPattern {
        id: "hardcoded_password",
        name: "Hardcoded Password",
        pattern: r#"(?i)(password|passwd|pwd)\s*[=:]\s*['"][^'"]{6,}"#,
        severity: "high",
        confidence: "medium",
        cwe: "CWE-259",
    },
    SecretPattern {
        id: "hardcoded_secret",
        name: "Hardcoded Secret",
        pattern: r#"(?i)(secret|api_secret|client_secret)\s*[=:]\s*['"][^'"]{6,}"#,
        severity: "high",
        confidence: "medium",
        cwe: "CWE-798",
    },
    SecretPattern {
        id: "hardcoded_token",
        name: "Hardcoded Token",
        pattern: r#"(?i)(token|auth_token|access_token)\s*[=:]\s*['"][^'"]{8,}"#,
        severity: "high",
        confidence: "medium",
        cwe: "CWE-522",
    },
    // Database
    SecretPattern {
        id: "connection_string",
        name: "Database Connection String",
        pattern: r#"(?i)(jdbc:|mongodb://|redis://|mysql://|postgres://)[^"'\s]{10,}"#,
        severity: "high",
        confidence: "high",
        cwe: "CWE-312",
    },
    SecretPattern {
        id: "db_password",
        name: "Database Password",
        pattern: r#"(?i)(db_pass|database_password|db_password)\s*[=:]\s*['"][^'"]{4,}"#,
        severity: "high",
        confidence: "medium",
        cwe: "CWE-259",
    },
    // Cloud Providers
    SecretPattern {
        id: "azure_storage",
        name: "Azure Storage Connection String",
        pattern: r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
        severity: "critical",
        confidence: "high",
        cwe: "CWE-798",
    },
    SecretPattern {
        id: "heroku_api_key",
        name: "Heroku API Key",
        pattern: r"[hH]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        severity: "high",
        confidence: "medium",
        cwe: "CWE-798",
    },
    SecretPattern {
        id: "sendgrid_key",
        name: "SendGrid API Key",
        pattern: r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        severity: "high",
        confidence: "high",
        cwe: "CWE-798",
    },
    SecretPattern {
        id: "mailchimp_key",
        name: "Mailchimp API Key",
        pattern: r"[0-9a-f]{32}-us[0-9]{1,2}",
        severity: "medium",
        confidence: "medium",
        cwe: "CWE-798",
    },
    // Crypto keys
    SecretPattern {
        id: "generic_secret_hex",
        name: "Generic Hex Secret",
        pattern: r#"(?i)(key|secret|token)\s*[=:]\s*['"][0-9a-fA-F]{32,}"#,
        severity: "medium",
        confidence: "low",
        cwe: "CWE-321",
    },
    SecretPattern {
        id: "base64_high_entropy",
        name: "Base64 High-Entropy Value",
        pattern: r#"(?i)(key|secret|token)\s*[=:]\s*['"][A-Za-z0-9+/]{40,}={0,2}['"]{1}"#,
        severity: "medium",
        confidence: "low",
        cwe: "CWE-321",
    },
    // Social Media APIs
    SecretPattern {
        id: "twitter_bearer",
        name: "Twitter Bearer Token",
        pattern: r"AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{30,}",
        severity: "high",
        confidence: "high",
        cwe: "CWE-798",
    },
    SecretPattern {
        id: "twitter_secret",
        name: "Twitter API Secret",
        pattern: r"(?i)twitter.*[0-9a-zA-Z]{35,44}",
        severity: "medium",
        confidence: "low",
        cwe: "CWE-798",
    },
    SecretPattern {
        id: "facebook_token",
        name: "Facebook Access Token",
        pattern: r"EAACEdEose0cBA[0-9A-Za-z]+",
        severity: "high",
        confidence: "high",
        cwe: "CWE-798",
    },
    // Payment
    SecretPattern {
        id: "paypal_braintree",
        name: "PayPal Braintree Access Token",
        pattern: r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
        severity: "critical",
        confidence: "high",
        cwe: "CWE-798",
    },
    SecretPattern {
        id: "square_access",
        name: "Square Access Token",
        pattern: r"sq0atp-[0-9A-Za-z_-]{22}",
        severity: "critical",
        confidence: "high",
        cwe: "CWE-798",
    },
    // Encryption keys
    SecretPattern {
        id: "aes_key",
        name: "AES Encryption Key",
        pattern: r"(?i)aes.*key.*[0-9a-fA-F]{32,64}",
        severity: "high",
        confidence: "medium",
        cwe: "CWE-321",
    },
    SecretPattern {
        id: "crypto_iv",
        name: "Cryptographic IV",
        pattern: r"(?i)(iv|initialization_vector).*[0-9a-fA-F]{32}",
        severity: "medium",
        confidence: "low",
        cwe: "CWE-329",
    },
    // Misc
    SecretPattern {
        id: "url_with_cred",
        name: "URL with Embedded Credentials",
        pattern: r"https?://[^@\s]+:[^@\s]+@[^\s]+",
        severity: "high",
        confidence: "high",
        cwe: "CWE-522",
    },
    SecretPattern {
        id: "generic_api_key",
        name: "Generic API Key",
        pattern: r#"(?i)api[_-]?key\s*[=:]\s*['"][A-Za-z0-9_-]{20,}"#,
        severity: "medium",
        confidence: "low",
        cwe: "CWE-798",
    },
];

// Shannon entropy helper
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.len() as f64;
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn build_patterns() -> Vec<(usize, Regex)> {
    PATTERNS
        .iter()
        .enumerate()
        .filter_map(|(i, p)| Regex::new(p.pattern).ok().map(|r| (i, r)))
        .collect()
}

/// Scan a string for hardcoded secrets. Returns one finding per match.
pub fn scan_for_secrets(content: &str, file_path: &str) -> Vec<ScanFinding> {
    let compiled = build_patterns();
    let mut findings: Vec<ScanFinding> = Vec::new();

    // Regex for Java/Kotlin string literals of 20+ chars (for entropy check)
    let lit_re = Regex::new(r#""([^"\\]{20,})""#).unwrap_or_else(|_| Regex::new(r"x^").unwrap());

    for (line_no, line) in content.lines().enumerate() {
        let line_no_i32 = line_no as i32 + 1;

        // Pattern-based detection
        for (idx, re) in &compiled {
            let pat = &PATTERNS[*idx];
            if re.is_match(line) {
                let evidence = line.trim().chars().take(200).collect::<String>();
                findings.push(ScanFinding {
                    rule_id: pat.id.to_string(),
                    title: format!("Hardcoded secret: {}", pat.name),
                    severity: pat.severity.to_string(),
                    description: format!(
                        "{} detected in source code. Rotate or remove immediately.",
                        pat.name
                    ),
                    file_path: Some(file_path.to_string()),
                    line_number: Some(line_no_i32),
                    cwe: Some(pat.cwe.to_string()),
                    owasp: Some("m2".to_string()),
                    masvs: Some("storage-14".to_string()),
                    evidence: Some(evidence),
                });
            }
        }

        // High-entropy string detection
        for cap in lit_re.captures_iter(line) {
            let s = &cap[1];
            if shannon_entropy(s) > 4.5 {
                let evidence = format!("\"{}\"", s.chars().take(100).collect::<String>());
                findings.push(ScanFinding {
                    rule_id: "high_entropy_string".to_string(),
                    title: "High-entropy string literal".to_string(),
                    severity: "medium".to_string(),
                    description:
                        "A string literal with high Shannon entropy was found. It may be a hardcoded secret or key."
                            .to_string(),
                    file_path: Some(file_path.to_string()),
                    line_number: Some(line_no_i32),
                    cwe: Some("CWE-798".to_string()),
                    owasp: Some("m2".to_string()),
                    masvs: Some("storage-14".to_string()),
                    evidence: Some(evidence),
                });
            }
        }
    }

    findings
}

/// Check Firebase Realtime Database URLs for public read access
/// by hitting the <url>/.json endpoint.
pub async fn check_firebase_urls(strings: &[String]) -> Vec<ScanFinding> {
    let firebase_re = match regex::Regex::new(r"https://[a-z0-9-]+\.firebaseio\.com") {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    // Collect unique Firebase URLs
    let mut urls: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for s in strings {
        for m in firebase_re.find_iter(s) {
            let url = m.as_str().to_string();
            if seen.insert(url.clone()) {
                urls.push(url);
            }
        }
    }

    let mut findings: Vec<ScanFinding> = Vec::new();

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return findings,
    };

    for url in urls {
        let check_url = format!("{}/.json", url.trim_end_matches('/'));
        match client.get(&check_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.text().await {
                    Ok(body) if body != "null" && !body.is_empty() => {
                        findings.push(ScanFinding {
                            rule_id: "firebase_public_db".to_string(),
                            title: format!("Firebase database is publicly readable: {}", url),
                            severity: "high".to_string(),
                            description: format!(
                                "Firebase Realtime Database at '{}' is publicly readable. \
                                 The /.json endpoint returned non-null data without authentication.",
                                url
                            ),
                            file_path: None,
                            line_number: None,
                            cwe: Some("CWE-284".to_string()),
                            owasp: Some("m2".to_string()),
                            masvs: Some("storage-5".to_string()),
                            evidence: Some(check_url),
                        });
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    findings
}

/// Scan all Java/Kotlin/XML files in a directory tree for hardcoded secrets.
pub async fn scan_secrets_in_directory(dir: &Path) -> Vec<ScanFinding> {
    let mut findings: Vec<ScanFinding> = Vec::new();

    let mut dirs = vec![dir.to_path_buf()];
    while let Some(current) = dirs.pop() {
        let mut read_dir = match tokio::fs::read_dir(&current).await {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        while let Ok(Some(entry)) = read_dir.next_entry().await {
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
            } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if ext == "java" || ext == "kt" || ext == "xml" {
                    if let Ok(content) = tokio::fs::read_to_string(&path).await {
                        let fp = path.to_string_lossy().to_string();
                        findings.extend(scan_for_secrets(&content, &fp));
                    }
                }
            }
        }
    }

    findings
}
