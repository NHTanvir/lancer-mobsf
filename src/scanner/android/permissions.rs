// permission risk DB + analyzer

use crate::scanner::ScanFinding;

// ---------------------------------------------------------------------------
// Permission risk levels
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionRisk {
    Dangerous,
    Normal,
    Signature,
    Unknown,
}

// ---------------------------------------------------------------------------
// Permission metadata
// ---------------------------------------------------------------------------

pub struct PermissionInfo {
    pub name: &'static str,
    pub risk_level: PermissionRisk,
    /// "critical" | "high" | "medium" | "low" | "info"
    pub severity: &'static str,
    pub description: &'static str,
    pub cwe: Option<&'static str>,
    pub owasp: Option<&'static str>,
}

// ---------------------------------------------------------------------------
// Static permission database
// ---------------------------------------------------------------------------

static PERMISSION_DB: &[PermissionInfo] = &[
    PermissionInfo {
        name: "android.permission.READ_CONTACTS",
        risk_level: PermissionRisk::Dangerous,
        severity: "medium",
        description: "Allows reading the user's contacts data. Can be used to harvest \
                      personally identifiable information.",
        cwe: Some("CWE-359"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.WRITE_CONTACTS",
        risk_level: PermissionRisk::Dangerous,
        severity: "medium",
        description: "Allows writing to the user's contacts data. Can be used to modify or \
                      delete contacts.",
        cwe: Some("CWE-359"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.READ_CALL_LOG",
        risk_level: PermissionRisk::Dangerous,
        severity: "high",
        description: "Allows reading the device call log. Exposes call history including \
                      phone numbers and duration.",
        cwe: Some("CWE-359"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.WRITE_CALL_LOG",
        risk_level: PermissionRisk::Dangerous,
        severity: "high",
        description: "Allows writing to the device call log. Enables manipulation of \
                      call history records.",
        cwe: Some("CWE-359"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.READ_SMS",
        risk_level: PermissionRisk::Dangerous,
        severity: "high",
        description: "Allows reading SMS messages. Enables access to potentially sensitive \
                      communications including OTP codes.",
        cwe: Some("CWE-359"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.SEND_SMS",
        risk_level: PermissionRisk::Dangerous,
        severity: "high",
        description: "Allows sending SMS messages. Can be abused for premium-rate SMS fraud.",
        cwe: Some("CWE-862"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.RECEIVE_SMS",
        risk_level: PermissionRisk::Dangerous,
        severity: "high",
        description: "Allows receiving SMS messages. Can be used to intercept OTPs and \
                      authentication codes.",
        cwe: Some("CWE-359"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.RECORD_AUDIO",
        risk_level: PermissionRisk::Dangerous,
        severity: "high",
        description: "Allows recording audio with the microphone. Enables covert audio \
                      surveillance.",
        cwe: Some("CWE-359"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.CAMERA",
        risk_level: PermissionRisk::Dangerous,
        severity: "high",
        description: "Allows taking pictures and videos. Enables covert visual surveillance.",
        cwe: Some("CWE-359"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.ACCESS_FINE_LOCATION",
        risk_level: PermissionRisk::Dangerous,
        severity: "high",
        description: "Allows access to precise GPS location. Enables tracking of the \
                      device user.",
        cwe: Some("CWE-359"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.ACCESS_COARSE_LOCATION",
        risk_level: PermissionRisk::Dangerous,
        severity: "medium",
        description: "Allows access to approximate network-based location. Enables \
                      coarse-grained tracking.",
        cwe: Some("CWE-359"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.READ_EXTERNAL_STORAGE",
        risk_level: PermissionRisk::Dangerous,
        severity: "medium",
        description: "Allows reading from external storage. May expose user files and \
                      media.",
        cwe: Some("CWE-312"),
        owasp: Some("m2"),
    },
    PermissionInfo {
        name: "android.permission.WRITE_EXTERNAL_STORAGE",
        risk_level: PermissionRisk::Dangerous,
        severity: "medium",
        description: "Allows writing to external storage. Can be used to drop malicious \
                      files or access user data.",
        cwe: Some("CWE-312"),
        owasp: Some("m2"),
    },
    PermissionInfo {
        name: "android.permission.READ_PHONE_STATE",
        risk_level: PermissionRisk::Dangerous,
        severity: "medium",
        description: "Allows read-only access to phone state (IMEI, phone number, etc.). \
                      Can be used for device fingerprinting.",
        cwe: Some("CWE-359"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.PROCESS_OUTGOING_CALLS",
        risk_level: PermissionRisk::Dangerous,
        severity: "high",
        description: "Allows the app to see the number being dialed during an outgoing \
                      call and redirect or abort it.",
        cwe: Some("CWE-359"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.INSTALL_PACKAGES",
        risk_level: PermissionRisk::Dangerous,
        severity: "critical",
        description: "Allows the app to install other APKs silently. Extremely dangerous — \
                      can be used to install malware.",
        cwe: Some("CWE-272"),
        owasp: Some("m8"),
    },
    PermissionInfo {
        name: "android.permission.DELETE_PACKAGES",
        risk_level: PermissionRisk::Dangerous,
        severity: "high",
        description: "Allows the app to silently delete other installed packages.",
        cwe: Some("CWE-272"),
        owasp: Some("m8"),
    },
    PermissionInfo {
        name: "android.permission.MANAGE_EXTERNAL_STORAGE",
        risk_level: PermissionRisk::Dangerous,
        severity: "high",
        description: "Allows broad access to all files on external and shared storage. \
                      Scoped storage bypass.",
        cwe: Some("CWE-312"),
        owasp: Some("m2"),
    },
    PermissionInfo {
        name: "android.permission.REQUEST_INSTALL_PACKAGES",
        risk_level: PermissionRisk::Dangerous,
        severity: "medium",
        description: "Allows the app to request installation of APKs from unknown sources. \
                      Can be used for malware delivery.",
        cwe: Some("CWE-272"),
        owasp: Some("m8"),
    },
    PermissionInfo {
        name: "android.permission.BIND_ACCESSIBILITY_SERVICE",
        risk_level: PermissionRisk::Dangerous,
        severity: "critical",
        description: "Allows the app to act as an accessibility service. Grants the ability \
                      to observe and interact with all on-screen content including \
                      passwords.",
        cwe: Some("CWE-359"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.USE_FINGERPRINT",
        risk_level: PermissionRisk::Dangerous,
        severity: "medium",
        description: "Allows the app to use fingerprint hardware. Verify biometric \
                      integration follows secure coding guidelines.",
        cwe: None,
        owasp: Some("m4"),
    },
    PermissionInfo {
        name: "android.permission.USE_BIOMETRIC",
        risk_level: PermissionRisk::Dangerous,
        severity: "medium",
        description: "Allows the app to use biometric hardware. Verify biometric \
                      integration follows secure coding guidelines.",
        cwe: None,
        owasp: Some("m4"),
    },
    // Normal permissions
    PermissionInfo {
        name: "android.permission.INTERNET",
        risk_level: PermissionRisk::Normal,
        severity: "info",
        description: "Allows the app to open network sockets. Required for any network \
                      communication.",
        cwe: None,
        owasp: None,
    },
    PermissionInfo {
        name: "android.permission.ACCESS_NETWORK_STATE",
        risk_level: PermissionRisk::Normal,
        severity: "info",
        description: "Allows the app to access information about networks (connectivity).",
        cwe: None,
        owasp: None,
    },
    PermissionInfo {
        name: "android.permission.CHANGE_NETWORK_STATE",
        risk_level: PermissionRisk::Normal,
        severity: "info",
        description: "Allows the app to change network connectivity state.",
        cwe: None,
        owasp: None,
    },
    PermissionInfo {
        name: "android.permission.RECEIVE_BOOT_COMPLETED",
        risk_level: PermissionRisk::Normal,
        severity: "low",
        description: "Allows the app to receive a broadcast when the device finishes \
                      booting. Enables auto-start behaviour.",
        cwe: None,
        owasp: None,
    },
    PermissionInfo {
        name: "android.permission.VIBRATE",
        risk_level: PermissionRisk::Normal,
        severity: "info",
        description: "Allows the app to control the vibrator.",
        cwe: None,
        owasp: None,
    },
    // Additional dangerous permissions
    PermissionInfo {
        name: "android.permission.GET_ACCOUNTS",
        risk_level: PermissionRisk::Dangerous,
        severity: "medium",
        description: "Allows access to the list of accounts in the Accounts Service. \
                      Exposes user account information.",
        cwe: Some("CWE-359"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.READ_CALENDAR",
        risk_level: PermissionRisk::Dangerous,
        severity: "medium",
        description: "Allows reading calendar data. Can expose meeting schedules and \
                      personal information.",
        cwe: Some("CWE-359"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.WRITE_CALENDAR",
        risk_level: PermissionRisk::Dangerous,
        severity: "medium",
        description: "Allows writing to calendar data. Can create, modify, or delete \
                      calendar events.",
        cwe: Some("CWE-359"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.BODY_SENSORS",
        risk_level: PermissionRisk::Dangerous,
        severity: "medium",
        description: "Allows access to data from sensors measuring what is happening \
                      inside the user's body (heart rate, etc.).",
        cwe: Some("CWE-359"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.CALL_PHONE",
        risk_level: PermissionRisk::Dangerous,
        severity: "high",
        description: "Allows the app to initiate phone calls without going through the \
                      dialler UI. Can result in unexpected charges.",
        cwe: Some("CWE-862"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.READ_MEDIA_IMAGES",
        risk_level: PermissionRisk::Dangerous,
        severity: "medium",
        description: "Allows reading image files from shared media storage (API 33+).",
        cwe: Some("CWE-312"),
        owasp: Some("m2"),
    },
    PermissionInfo {
        name: "android.permission.READ_MEDIA_VIDEO",
        risk_level: PermissionRisk::Dangerous,
        severity: "medium",
        description: "Allows reading video files from shared media storage (API 33+).",
        cwe: Some("CWE-312"),
        owasp: Some("m2"),
    },
    PermissionInfo {
        name: "android.permission.READ_MEDIA_AUDIO",
        risk_level: PermissionRisk::Dangerous,
        severity: "medium",
        description: "Allows reading audio files from shared media storage (API 33+).",
        cwe: Some("CWE-312"),
        owasp: Some("m2"),
    },
    PermissionInfo {
        name: "android.permission.PACKAGE_USAGE_STATS",
        risk_level: PermissionRisk::Signature,
        severity: "high",
        description: "Allows the app to collect component usage statistics. Can be used \
                      to track which apps the user is running.",
        cwe: Some("CWE-359"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.SYSTEM_ALERT_WINDOW",
        risk_level: PermissionRisk::Dangerous,
        severity: "high",
        description: "Allows the app to draw over other apps. Can be used for clickjacking \
                      and overlay attacks.",
        cwe: Some("CWE-1021"),
        owasp: Some("m1"),
    },
    PermissionInfo {
        name: "android.permission.WRITE_SETTINGS",
        risk_level: PermissionRisk::Dangerous,
        severity: "medium",
        description: "Allows the app to modify system settings. Can interfere with device \
                      security configuration.",
        cwe: Some("CWE-272"),
        owasp: Some("m8"),
    },
    PermissionInfo {
        name: "android.permission.DISABLE_KEYGUARD",
        risk_level: PermissionRisk::Dangerous,
        severity: "high",
        description: "Allows the app to disable the keyguard and any associated password \
                      security. Undermines device lock screen protection.",
        cwe: Some("CWE-287"),
        owasp: Some("m4"),
    },
    PermissionInfo {
        name: "android.permission.ACCESS_WIFI_STATE",
        risk_level: PermissionRisk::Normal,
        severity: "info",
        description: "Allows the app to access information about Wi-Fi networks.",
        cwe: None,
        owasp: None,
    },
    PermissionInfo {
        name: "android.permission.CHANGE_WIFI_STATE",
        risk_level: PermissionRisk::Dangerous,
        severity: "medium",
        description: "Allows the app to change Wi-Fi connectivity state. Can disconnect \
                      the device or connect to rogue networks.",
        cwe: Some("CWE-940"),
        owasp: Some("m3"),
    },
    PermissionInfo {
        name: "android.permission.BLUETOOTH",
        risk_level: PermissionRisk::Normal,
        severity: "info",
        description: "Allows the app to connect to paired Bluetooth devices.",
        cwe: None,
        owasp: None,
    },
    PermissionInfo {
        name: "android.permission.BLUETOOTH_ADMIN",
        risk_level: PermissionRisk::Dangerous,
        severity: "medium",
        description: "Allows the app to discover and pair Bluetooth devices. Can be used \
                      for Bluetooth-based tracking.",
        cwe: Some("CWE-359"),
        owasp: Some("m3"),
    },
    PermissionInfo {
        name: "android.permission.NFC",
        risk_level: PermissionRisk::Normal,
        severity: "low",
        description: "Allows the app to perform I/O operations over NFC. Verify NFC \
                      data is handled securely.",
        cwe: None,
        owasp: None,
    },
    PermissionInfo {
        name: "android.permission.WAKE_LOCK",
        risk_level: PermissionRisk::Normal,
        severity: "info",
        description: "Allows the app to prevent the processor from sleeping.",
        cwe: None,
        owasp: None,
    },
];

// ---------------------------------------------------------------------------
// Lookup helper
// ---------------------------------------------------------------------------

fn lookup(name: &str) -> Option<&'static PermissionInfo> {
    PERMISSION_DB.iter().find(|p| p.name == name)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Analyse a list of declared permissions and return security findings.
pub fn analyze_permissions(permissions: &[String]) -> Vec<ScanFinding> {
    let mut findings: Vec<ScanFinding> = Vec::new();

    for perm in permissions {
        if let Some(info) = lookup(perm.as_str()) {
            // Only emit findings for Dangerous (and Signature) permissions.
            if info.risk_level == PermissionRisk::Normal {
                // Still emit info for INTERNET so analysts see it.
                if perm == "android.permission.INTERNET" {
                    findings.push(ScanFinding {
                        rule_id: format!("perm_{}", sanitize_rule_id(perm)),
                        title: format!("Permission declared: {}", perm),
                        severity: info.severity.to_string(),
                        description: info.description.to_string(),
                        file_path: Some("AndroidManifest.xml".to_string()),
                        line_number: None,
                        cwe: info.cwe.map(|s| s.to_string()),
                        owasp: info.owasp.map(|s| s.to_string()),
                        masvs: None,
                        evidence: Some(perm.clone()),
                    });
                }
                continue;
            }

            findings.push(ScanFinding {
                rule_id: format!("perm_{}", sanitize_rule_id(perm)),
                title: format!("Dangerous permission declared: {}", perm),
                severity: info.severity.to_string(),
                description: info.description.to_string(),
                file_path: Some("AndroidManifest.xml".to_string()),
                line_number: None,
                cwe: info.cwe.map(|s| s.to_string()),
                owasp: info.owasp.map(|s| s.to_string()),
                masvs: None,
                evidence: Some(perm.clone()),
            });
        } else {
            // Unknown permission – flag as info so analysts review it.
            findings.push(ScanFinding {
                rule_id: format!("perm_unknown_{}", sanitize_rule_id(perm)),
                title: format!("Unknown permission declared: {}", perm),
                severity: "info".to_string(),
                description: format!(
                    "Permission '{}' is not in the known permission database. Verify \
                     whether it is a legitimate system or custom permission.",
                    perm
                ),
                file_path: Some("AndroidManifest.xml".to_string()),
                line_number: None,
                cwe: None,
                owasp: None,
                masvs: None,
                evidence: Some(perm.clone()),
            });
        }
    }

    findings
}

/// Convert a permission name into a lowercase rule-id-safe string.
fn sanitize_rule_id(permission: &str) -> String {
    permission
        .replace('.', "_")
        .replace('-', "_")
        .to_lowercase()
}
