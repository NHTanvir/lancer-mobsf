// APKiD-style packer/obfuscator/protector detection for Android APKs.
//
// Detection is performed by:
//   1. Scanning APK zip entries for suspicious asset/library file names.
//   2. Searching raw DEX bytes for known byte-string signatures.
//   3. Scanning decompiled Java source files (up to 50) for known package names.

use std::path::{Path, PathBuf};
use crate::scanner::ScanFinding;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackerInfo {
    pub name: String,
    pub category: String,
    /// "high" | "medium" | "low"
    pub confidence: &'static str,
}

// ---------------------------------------------------------------------------
// Signature database
// ---------------------------------------------------------------------------

/// A single detection rule.
struct Signature {
    /// Display name, e.g. "360 Jiagu"
    name: &'static str,
    category: &'static str,
    confidence: &'static str,
    /// Substrings to look for in APK zip entry names (case-insensitive).
    asset_patterns: &'static [&'static str],
    /// Byte strings to search in raw DEX data (ASCII).
    dex_patterns: &'static [&'static str],
    /// Strings to search in decompiled Java source text.
    java_patterns: &'static [&'static str],
}

static SIGNATURES: &[Signature] = &[
    // ── Packers ────────────────────────────────────────────────────────────
    Signature {
        name: "360 Jiagu",
        category: "packer",
        confidence: "high",
        asset_patterns: &["jiagu", "jiagu_sign", "assets/jiagu"],
        dex_patterns: &["com/qihoo/util", "jiagu"],
        java_patterns: &["com/qihoo/util", "jiagu"],
    },
    Signature {
        name: "Bangcle/SecNeo",
        category: "packer",
        confidence: "high",
        asset_patterns: &["libsecexe.so", "libSecShell.so"],
        dex_patterns: &["com/bangcle", "bangcle"],
        java_patterns: &["com/bangcle", "bangcle"],
    },
    Signature {
        name: "ijiami",
        category: "packer",
        confidence: "high",
        asset_patterns: &["ijiami"],
        dex_patterns: &["ijiami", "com.ijiami"],
        java_patterns: &["ijiami", "com.ijiami"],
    },
    Signature {
        name: "Qihoo 360",
        category: "packer",
        confidence: "medium",
        asset_patterns: &["libjiagu"],
        dex_patterns: &["com/qihoo", "libjiagu"],
        java_patterns: &["com/qihoo", "libjiagu"],
    },
    Signature {
        name: "Tencent legu",
        category: "packer",
        confidence: "high",
        asset_patterns: &["0OO00l111l1l"],
        dex_patterns: &["com/tencent/StubShell", "assets/0OO00l111l1l"],
        java_patterns: &["com/tencent/StubShell"],
    },
    Signature {
        name: "Alibaba",
        category: "packer",
        confidence: "high",
        asset_patterns: &["libmobisec.so"],
        dex_patterns: &["libmobisec.so", "com/alibaba/wireless/security"],
        java_patterns: &["com/alibaba/wireless/security"],
    },
    Signature {
        name: "Baidu",
        category: "packer",
        confidence: "high",
        asset_patterns: &["libBaiduProtect.so"],
        dex_patterns: &["libBaiduProtect.so"],
        java_patterns: &["libBaiduProtect"],
    },
    Signature {
        name: "Naga",
        category: "packer",
        confidence: "medium",
        asset_patterns: &["naga.jar", "assets/naga"],
        dex_patterns: &["assets/naga.jar"],
        java_patterns: &["naga.jar"],
    },
    Signature {
        name: "ApkProtect",
        category: "packer",
        confidence: "medium",
        asset_patterns: &["apkprotect"],
        dex_patterns: &["com/apkprotect"],
        java_patterns: &["com/apkprotect"],
    },
    // ── Obfuscators ────────────────────────────────────────────────────────
    Signature {
        name: "DexGuard",
        category: "obfuscator",
        confidence: "high",
        asset_patterns: &["dexguard"],
        dex_patterns: &["com/guard"],
        java_patterns: &["com/guard"],
    },
    Signature {
        name: "Allatori",
        category: "obfuscator",
        confidence: "medium",
        asset_patterns: &[],
        dex_patterns: &["allatori"],
        java_patterns: &["allatori"],
    },
    // ── Protectors / compilers ─────────────────────────────────────────────
    Signature {
        name: "DexProtector",
        category: "protector",
        confidence: "high",
        asset_patterns: &[],
        dex_patterns: &["com/mob/dexprotect", "DexProtector"],
        java_patterns: &["com/mob/dexprotect", "DexProtector"],
    },
    Signature {
        name: "NativeShield",
        category: "protector",
        confidence: "medium",
        asset_patterns: &[],
        dex_patterns: &["nativeshield"],
        java_patterns: &["nativeshield"],
    },
];

// ---------------------------------------------------------------------------
// Core detection function
// ---------------------------------------------------------------------------

/// Detect packers, obfuscators, and protectors in an Android APK.
///
/// # Arguments
/// * `apk_path`   – Path to the `.apk` file on disk.
/// * `dex_files`  – Raw DEX bytes for each classes*.dex file already extracted.
/// * `java_files` – Paths to decompiled Java source files (may be empty).
pub fn detect_packers(
    apk_path: &Path,
    dex_files: &[Vec<u8>],
    java_files: &[PathBuf],
) -> Vec<PackerInfo> {
    let mut results: Vec<PackerInfo> = Vec::new();

    // ── 1. Collect APK zip entry names ─────────────────────────────────────
    let zip_names: Vec<String> = collect_zip_names(apk_path);
    let has_proguard_dir = zip_names
        .iter()
        .any(|n| n.to_lowercase().starts_with("meta-inf/proguard/"));

    // ── 2. ProGuard detection (directory-based) ────────────────────────────
    if has_proguard_dir {
        results.push(PackerInfo {
            name: "ProGuard".to_string(),
            category: "obfuscator".to_string(),
            confidence: "high",
        });
    }

    // ── 3. Per-signature detection ─────────────────────────────────────────
    'sig: for sig in SIGNATURES {
        // 3a. Check APK asset/library file names
        for pattern in sig.asset_patterns {
            let lower_pattern = pattern.to_lowercase();
            if zip_names
                .iter()
                .any(|n| n.to_lowercase().contains(&lower_pattern))
            {
                results.push(PackerInfo {
                    name: sig.name.to_string(),
                    category: sig.category.to_string(),
                    confidence: sig.confidence,
                });
                continue 'sig;
            }
        }

        // 3b. Scan DEX byte data for byte-string signatures
        if !sig.dex_patterns.is_empty() {
            for dex in dex_files {
                for pattern in sig.dex_patterns {
                    if bytes_contain(dex, pattern.as_bytes()) {
                        results.push(PackerInfo {
                            name: sig.name.to_string(),
                            category: sig.category.to_string(),
                            confidence: sig.confidence,
                        });
                        continue 'sig;
                    }
                }
            }
        }

        // 3c. Scan decompiled Java source (up to 50 files)
        if !sig.java_patterns.is_empty() {
            'java: for java_path in java_files.iter().take(50) {
                let source = match std::fs::read_to_string(java_path) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                for pattern in sig.java_patterns {
                    if source.contains(pattern) {
                        results.push(PackerInfo {
                            name: sig.name.to_string(),
                            category: sig.category.to_string(),
                            confidence: sig.confidence,
                        });
                        break 'java;
                    }
                }
            }
        }
    }

    // Deduplicate by name (a signature can only appear once)
    results.dedup_by(|a, b| a.name == b.name);

    results
}

// ---------------------------------------------------------------------------
// Conversion to ScanFinding
// ---------------------------------------------------------------------------

/// Convert a slice of `PackerInfo` results into `ScanFinding` entries.
pub fn packer_findings(packers: &[PackerInfo]) -> Vec<ScanFinding> {
    packers
        .iter()
        .map(|p| {
            let name_slug = p
                .name
                .to_lowercase()
                .replace(' ', "_")
                .replace('/', "_")
                .replace('-', "_");
            let rule_id = format!("android_packer_{name_slug}");
            let title = format!("Packer Detected: {}", p.name);
            let description = format!(
                "The {} '{}' was detected in the APK. This may indicate that the application \
                 binary has been protected, packed, or obfuscated, which can hinder static \
                 analysis and may be used to hide malicious behaviour.",
                p.category, p.name
            );

            ScanFinding {
                rule_id,
                title,
                severity: "medium".to_string(),
                description,
                file_path: None,
                line_number: None,
                cwe: Some("CWE-656".to_string()),
                owasp: Some("m9".to_string()),
                masvs: Some("code-2".to_string()),
                evidence: Some(format!(
                    "category={}, confidence={}",
                    p.category, p.confidence
                )),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Open an APK as a zip archive and return all entry names.
/// Returns an empty `Vec` if the file cannot be opened or parsed.
fn collect_zip_names(apk_path: &Path) -> Vec<String> {
    let file = match std::fs::File::open(apk_path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let mut archive = match zip::ZipArchive::new(file) {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };
    let mut names = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        if let Ok(entry) = archive.by_index(i) {
            names.push(entry.name().to_string());
        }
    }
    names
}

/// Returns `true` if `haystack` contains the byte sequence `needle`.
/// Uses the sliding-window approach (`.windows()`) — no extra dependencies.
#[inline]
fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a minimal, valid empty ZIP (just the EOCD record) and write it to a
    /// uniquely-named file in the system temp directory.  Returns the path.
    fn write_empty_zip() -> PathBuf {
        let eocd: &[u8] = &[
            0x50, 0x4B, 0x05, 0x06, // EOCD signature
            0x00, 0x00, // disk number
            0x00, 0x00, // disk with start of CD
            0x00, 0x00, // number of entries on this disk
            0x00, 0x00, // total entries
            0x00, 0x00, 0x00, 0x00, // size of CD
            0x00, 0x00, 0x00, 0x00, // offset of CD
            0x00, 0x00, // comment length
        ];
        let path = std::env::temp_dir().join(format!(
            "lancer_apkid_test_{}.apk",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let mut f = std::fs::File::create(&path).expect("create temp apk");
        f.write_all(eocd).expect("write eocd");
        path
    }

    #[test]
    fn test_empty_apk_returns_no_packers() {
        let tmp = write_empty_zip();
        let result = detect_packers(&tmp, &[], &[]);
        let _ = std::fs::remove_file(&tmp);
        assert!(
            result.is_empty(),
            "Expected no detections for empty APK, got: {:?}",
            result
        );
    }

    #[test]
    fn test_dex_bytes_trigger_jiagu_detection() {
        let tmp = write_empty_zip();

        // Construct a fake DEX buffer containing the Jiagu signature.
        let mut fake_dex = vec![0u8; 64];
        fake_dex.extend_from_slice(b"com/qihoo/util");
        fake_dex.extend_from_slice(&[0u8; 16]);

        let result = detect_packers(&tmp, &[fake_dex], &[]);
        let _ = std::fs::remove_file(&tmp);

        assert!(
            result.iter().any(|p| p.name == "360 Jiagu"),
            "Expected '360 Jiagu' detection from DEX bytes, got: {:?}",
            result
        );
        assert!(result.iter().any(|p| p.category == "packer"));
    }

    #[test]
    fn test_bytes_contain_helper() {
        assert!(bytes_contain(b"hello world", b"world"));
        assert!(bytes_contain(b"hello world", b"hello"));
        assert!(!bytes_contain(b"hello world", b"xyz"));
        assert!(bytes_contain(b"anything", b""));
    }

    #[test]
    fn test_packer_findings_produces_correct_fields() {
        let packers = vec![PackerInfo {
            name: "360 Jiagu".to_string(),
            category: "packer".to_string(),
            confidence: "high",
        }];
        let findings = packer_findings(&packers);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.rule_id, "android_packer_360_jiagu");
        assert_eq!(f.severity, "medium");
        assert_eq!(f.masvs.as_deref(), Some("code-2"));
        assert_eq!(f.owasp.as_deref(), Some("m9"));
    }
}
