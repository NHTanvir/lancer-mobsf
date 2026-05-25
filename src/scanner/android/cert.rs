// cert/signature parsing

use crate::scanner::ScanFinding;
use anyhow::Result;
use sha2::{Digest, Sha256};

/// Certificate information extracted from a META-INF signing file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub sha256_fingerprint: String,
    pub is_self_signed: bool,
    pub is_debug_cert: bool,
    pub signature_algorithm: String,
    pub key_size: Option<u32>,
}

// Known Android debug certificate SHA-256 fingerprint (hex, lowercase, no colons).
const ANDROID_DEBUG_CERT_SHA256: &str =
    "a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc";

// OID byte sequences (the value bytes inside a DER OID TLV, i.e. after tag 0x06 + length).
// MD5withRSA  1.2.840.113549.1.1.4  -> 2a 86 48 86 f7 0d 01 01 04
const OID_MD5_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04];
// SHA1withRSA 1.2.840.113549.1.1.5  -> 2a 86 48 86 f7 0d 01 01 05
const OID_SHA1_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
// SHA256withRSA 1.2.840.113549.1.1.11 -> 2a 86 48 86 f7 0d 01 01 0b
const OID_SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
// SHA384withRSA 1.2.840.113549.1.1.12
const OID_SHA384_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
// SHA512withRSA 1.2.840.113549.1.1.13
const OID_SHA512_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];

/// Return true if `haystack` contains `needle` as a contiguous byte sub-slice.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w == needle)
}

/// Detect the signature algorithm by scanning for known OID bytes in the DER blob.
fn detect_sig_algorithm(der: &[u8]) -> String {
    if contains_bytes(der, OID_MD5_WITH_RSA) {
        "MD5withRSA".to_string()
    } else if contains_bytes(der, OID_SHA1_WITH_RSA) {
        "SHA1withRSA".to_string()
    } else if contains_bytes(der, OID_SHA256_WITH_RSA) {
        "SHA256withRSA".to_string()
    } else if contains_bytes(der, OID_SHA384_WITH_RSA) {
        "SHA384withRSA".to_string()
    } else if contains_bytes(der, OID_SHA512_WITH_RSA) {
        "SHA512withRSA".to_string()
    } else {
        "Unknown".to_string()
    }
}

/// Scan the DER bytes for sequences of printable ASCII that look like DN components.
/// Returns deduplicated strings that contain '=' (e.g. "CN=Android Debug", "O=Android").
fn extract_dn_strings(der_bytes: &[u8]) -> Vec<String> {
    let mut results: Vec<String> = Vec::new();
    let mut start: Option<usize> = None;

    for (i, &b) in der_bytes.iter().enumerate() {
        let printable = b.is_ascii_alphanumeric()
            || b == b'='
            || b == b','
            || b == b' '
            || b == b'.'
            || b == b'-'
            || b == b'_'
            || b == b'@'
            || b == b'/'
            || b == b':'
            || b == b'+'
            || b == b'\''
            || b == b'('
            || b == b')';

        if printable {
            if start.is_none() {
                start = Some(i);
            }
        } else {
            if let Some(s) = start.take() {
                let len = i - s;
                if len >= 3 && len <= 200 {
                    if let Ok(text) = std::str::from_utf8(&der_bytes[s..i]) {
                        if text.contains('=') {
                            results.push(text.to_string());
                        }
                    }
                }
            }
        }
    }
    // handle trailing run
    if let Some(s) = start {
        let len = der_bytes.len() - s;
        if len >= 3 && len <= 200 {
            if let Ok(text) = std::str::from_utf8(&der_bytes[s..]) {
                if text.contains('=') {
                    results.push(text.to_string());
                }
            }
        }
    }

    // Deduplicate while preserving order
    let mut seen = std::collections::HashSet::new();
    results.retain(|s| seen.insert(s.clone()));
    results
}

/// Try to extract a reasonably clean subject / issuer pair from DN string candidates.
///
/// Prefer longer strings (they tend to be more complete DNs), and try to find
/// ones that start with common RDN attributes.
fn best_dn(candidates: &[String]) -> String {
    let rdn_prefixes = ["CN=", "O=", "OU=", "C=", "L=", "ST=", "E="];
    candidates
        .iter()
        .filter(|s| rdn_prefixes.iter().any(|p| s.starts_with(p)))
        .max_by_key(|s| s.len())
        .cloned()
        .unwrap_or_else(|| {
            candidates
                .iter()
                .max_by_key(|s| s.len())
                .cloned()
                .unwrap_or_else(|| "Unknown".to_string())
        })
}

/// Analyse cert files extracted from META-INF/ and return a `CertInfo` plus any findings.
pub fn analyze_cert(
    cert_files: &[std::path::PathBuf],
) -> Result<(Option<CertInfo>, Vec<ScanFinding>)> {
    let mut findings: Vec<ScanFinding> = Vec::new();

    // --- No cert files at all => emit info finding ---
    if cert_files.is_empty() {
        findings.push(ScanFinding {
            rule_id: "no_v2_signature".to_string(),
            title: "APK lacks v2/v3 signature scheme".to_string(),
            severity: "info".to_string(),
            description:
                "No META-INF signing certificate was found. The APK may be unsigned or \
                 rely solely on v2/v3 APK Signature Scheme blocks which were not extracted."
                    .to_string(),
            file_path: None,
            line_number: None,
            cwe: None,
            owasp: None,
            masvs: Some("MSTG-CODE-1".to_string()),
            evidence: None,
        });
        return Ok((None, findings));
    }

    // Use the first cert file found (APKs typically have one signer).
    let cert_path = &cert_files[0];
    let file_str = cert_path.display().to_string();

    let der_bytes = match std::fs::read(cert_path) {
        Ok(b) => b,
        Err(e) => {
            findings.push(ScanFinding {
                rule_id: "cert_read_error".to_string(),
                title: "Certificate file could not be read".to_string(),
                severity: "info".to_string(),
                description: format!("Failed to read {}: {}", file_str, e),
                file_path: Some(file_str),
                line_number: None,
                cwe: None,
                owasp: None,
                masvs: None,
                evidence: None,
            });
            return Ok((None, findings));
        }
    };

    // --- SHA-256 fingerprint of the raw cert file ---
    let mut hasher = Sha256::new();
    hasher.update(&der_bytes);
    let sha256_fingerprint = hex::encode(hasher.finalize());

    // --- Signature algorithm ---
    let signature_algorithm = detect_sig_algorithm(&der_bytes);

    // --- Extract DN strings ---
    let dn_candidates = extract_dn_strings(&der_bytes);

    // Heuristic: the first occurrence tends to be the issuer in a PKCS#7 structure,
    // the second (or largest) is the subject.  We collect all and pick best two.
    let subject = if dn_candidates.len() >= 2 {
        best_dn(&dn_candidates[1..])
    } else {
        best_dn(&dn_candidates)
    };
    let issuer = best_dn(&dn_candidates);

    let is_self_signed = !subject.is_empty() && !issuer.is_empty() && subject == issuer;
    let is_debug_cert = sha256_fingerprint == ANDROID_DEBUG_CERT_SHA256;

    let cert_info = CertInfo {
        subject: subject.clone(),
        issuer: issuer.clone(),
        serial: String::new(),      // not parsed without full ASN.1 library
        not_before: String::new(),  // not parsed
        not_after: String::new(),   // not parsed
        sha256_fingerprint: sha256_fingerprint.clone(),
        is_self_signed,
        is_debug_cert,
        signature_algorithm: signature_algorithm.clone(),
        key_size: None,
    };

    // --- Generate findings ---

    if is_debug_cert {
        findings.push(ScanFinding {
            rule_id: "debug_cert".to_string(),
            title: "APK signed with debug certificate".to_string(),
            severity: "critical".to_string(),
            description:
                "The APK is signed with the well-known Android debug keystore certificate. \
                 Production APKs must never use the debug certificate as it is publicly \
                 known and provides no security guarantee."
                    .to_string(),
            file_path: Some(file_str.clone()),
            line_number: None,
            cwe: Some("CWE-321".to_string()),
            owasp: Some("M8".to_string()),
            masvs: Some("MSTG-CODE-1".to_string()),
            evidence: Some(format!("SHA-256: {}", sha256_fingerprint)),
        });
    }

    if is_self_signed && !is_debug_cert {
        findings.push(ScanFinding {
            rule_id: "self_signed_cert".to_string(),
            title: "APK signed with self-signed certificate".to_string(),
            severity: "medium".to_string(),
            description:
                "The signing certificate is self-signed (subject == issuer). While this is \
                 common for Android apps, it means there is no third-party CA validation. \
                 Ensure the private key is adequately protected."
                    .to_string(),
            file_path: Some(file_str.clone()),
            line_number: None,
            cwe: Some("CWE-295".to_string()),
            owasp: Some("M3".to_string()),
            masvs: Some("MSTG-CODE-1".to_string()),
            evidence: Some(format!("Subject: {}", subject)),
        });
    }

    if signature_algorithm == "MD5withRSA" || signature_algorithm == "SHA1withRSA" {
        findings.push(ScanFinding {
            rule_id: "weak_signature".to_string(),
            title: format!(
                "APK uses weak signature algorithm ({})",
                signature_algorithm
            ),
            severity: "medium".to_string(),
            description:
                "The APK is signed with a weak digest algorithm (MD5 or SHA-1). These \
                 algorithms are cryptographically broken and should be replaced with \
                 SHA-256 or stronger."
                    .to_string(),
            file_path: Some(file_str.clone()),
            line_number: None,
            cwe: Some("CWE-327".to_string()),
            owasp: Some("M8".to_string()),
            masvs: Some("MSTG-CRYPTO-4".to_string()),
            evidence: Some(format!("Algorithm: {}", signature_algorithm)),
        });
    }

    Ok((Some(cert_info), findings))
}
