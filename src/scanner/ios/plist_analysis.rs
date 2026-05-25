// Info.plist parsing and security analysis

use std::collections::HashMap;
use anyhow::{Context, Result};
use crate::scanner::ScanFinding;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParsedInfoPlist {
    pub bundle_id: String,
    pub bundle_name: String,
    pub bundle_version: String,
    pub bundle_short_version: String,
    pub minimum_os_version: String,
    pub platform_version: String,
    pub app_transport_security: Option<AtsConfig>,
    pub url_schemes: Vec<String>,
    pub background_modes: Vec<String>,
    pub usage_descriptions: HashMap<String, String>,
    pub associated_domains: Vec<String>,
    pub face_id_usage: Option<String>,
    pub supports_documents: bool,
    pub exported_utis: Vec<String>,
    pub imported_utis: Vec<String>,
    pub query_schemes: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AtsConfig {
    pub allows_arbitrary_loads: bool,
    pub allows_arbitrary_loads_in_web_content: bool,
    pub allows_local_networking: bool,
    pub exception_domains: Vec<AtsExceptionDomain>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AtsExceptionDomain {
    pub domain: String,
    pub allows_insecure_http: bool,
    pub includes_subdomains: bool,
    pub requires_forward_secrecy: bool,
}

pub fn parse_info_plist(plist_bytes: &[u8]) -> Result<ParsedInfoPlist> {
    let value = plist::Value::from_reader(std::io::Cursor::new(plist_bytes))
        .context("Failed to parse Info.plist")?;

    let dict = value.as_dictionary()
        .context("Info.plist root is not a dictionary")?;

    let bundle_id = string_key(dict, "CFBundleIdentifier");
    let bundle_name = string_key(dict, "CFBundleName");
    let bundle_version = string_key(dict, "CFBundleVersion");
    let bundle_short_version = string_key(dict, "CFBundleShortVersionString");
    let minimum_os_version = string_key(dict, "MinimumOSVersion");
    let platform_version = string_key(dict, "DTPlatformVersion");

    // ATS config
    let app_transport_security = dict.get("NSAppTransportSecurity")
        .and_then(|v| v.as_dictionary())
        .map(parse_ats_config);

    // URL schemes from CFBundleURLTypes
    let url_schemes = dict.get("CFBundleURLTypes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_dictionary())
                .filter_map(|d| d.get("CFBundleURLSchemes"))
                .filter_map(|v| v.as_array())
                .flat_map(|schemes| {
                    schemes.iter().filter_map(|s| s.as_string()).map(|s| s.to_string())
                })
                .collect()
        })
        .unwrap_or_default();

    // Background modes
    let background_modes = dict.get("UIBackgroundModes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_string())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    // Usage descriptions: any key ending in "UsageDescription"
    let mut usage_descriptions = HashMap::new();
    for (k, v) in dict.iter() {
        if k.ends_with("UsageDescription") {
            if let Some(s) = v.as_string() {
                usage_descriptions.insert(k.clone(), s.to_string());
            }
        }
    }

    // Associated domains from com.apple.developer.associated-domains entitlement
    // Usually not in Info.plist directly but in entitlements; check anyway
    let associated_domains = dict.get("com.apple.developer.associated-domains")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_string())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    let face_id_usage = dict.get("NSFaceIDUsageDescription")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string());

    let supports_documents = dict.get("UISupportsDocumentBrowser")
        .and_then(|v| v.as_boolean())
        .unwrap_or(false);

    // CFBundleDocumentTypes -> exported UTIs
    let exported_utis = dict.get("CFBundleDocumentTypes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_dictionary())
                .filter_map(|d| d.get("LSItemContentTypes"))
                .filter_map(|v| v.as_array())
                .flat_map(|types| {
                    types.iter().filter_map(|t| t.as_string()).map(|s| s.to_string())
                })
                .collect()
        })
        .unwrap_or_default();

    // UTExportedTypeDeclarations
    let imported_utis = dict.get("UTImportedTypeDeclarations")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_dictionary())
                .filter_map(|d| d.get("UTTypeIdentifier"))
                .filter_map(|v| v.as_string())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    // LSApplicationQueriesSchemes
    let query_schemes = dict.get("LSApplicationQueriesSchemes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_string())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    Ok(ParsedInfoPlist {
        bundle_id,
        bundle_name,
        bundle_version,
        bundle_short_version,
        minimum_os_version,
        platform_version,
        app_transport_security,
        url_schemes,
        background_modes,
        usage_descriptions,
        associated_domains,
        face_id_usage,
        supports_documents,
        exported_utis,
        imported_utis,
        query_schemes,
    })
}

fn string_key(dict: &plist::Dictionary, key: &str) -> String {
    dict.get(key)
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_string()
}

fn parse_ats_config(dict: &plist::Dictionary) -> AtsConfig {
    let allows_arbitrary_loads = dict.get("NSAllowsArbitraryLoads")
        .and_then(|v| v.as_boolean())
        .unwrap_or(false);

    let allows_arbitrary_loads_in_web_content = dict.get("NSAllowsArbitraryLoadsInWebContent")
        .and_then(|v| v.as_boolean())
        .unwrap_or(false);

    let allows_local_networking = dict.get("NSAllowsLocalNetworking")
        .and_then(|v| v.as_boolean())
        .unwrap_or(false);

    let exception_domains = dict.get("NSExceptionDomains")
        .and_then(|v| v.as_dictionary())
        .map(|domains_dict| {
            domains_dict.iter()
                .filter_map(|(domain, v)| {
                    let domain_dict = v.as_dictionary()?;
                    Some(AtsExceptionDomain {
                        domain: domain.clone(),
                        allows_insecure_http: domain_dict
                            .get("NSExceptionAllowsInsecureHTTPLoads")
                            .and_then(|v| v.as_boolean())
                            .unwrap_or(false),
                        includes_subdomains: domain_dict
                            .get("NSIncludesSubdomains")
                            .and_then(|v| v.as_boolean())
                            .unwrap_or(false),
                        requires_forward_secrecy: domain_dict
                            .get("NSExceptionRequiresForwardSecrecy")
                            .and_then(|v| v.as_boolean())
                            .unwrap_or(true), // default is true
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    AtsConfig {
        allows_arbitrary_loads,
        allows_arbitrary_loads_in_web_content,
        allows_local_networking,
        exception_domains,
    }
}

pub fn analyze_info_plist(info: &ParsedInfoPlist) -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    // ATS checks
    match &info.app_transport_security {
        None => {
            findings.push(ScanFinding {
                rule_id: "ios_no_ats".to_string(),
                title: "No App Transport Security (ATS) configuration".to_string(),
                severity: "medium".to_string(),
                description: "The app does not define an NSAppTransportSecurity entry. \
                    Without ATS, the default iOS ATS policy applies, but the absence of \
                    explicit configuration may indicate reliance on weak defaults."
                    .to_string(),
                file_path: Some("Info.plist".to_string()),
                line_number: None,
                cwe: Some("CWE-319".to_string()),
                owasp: None,
                masvs: Some("MASVS-NETWORK-1".to_string()),
                evidence: None,
            });
        }
        Some(ats) => {
            if ats.allows_arbitrary_loads {
                findings.push(ScanFinding {
                    rule_id: "ios_ats_arbitrary_loads".to_string(),
                    title: "ATS allows arbitrary loads (NSAllowsArbitraryLoads=true)".to_string(),
                    severity: "critical".to_string(),
                    description: "NSAllowsArbitraryLoads is set to true, which disables ATS \
                        for all connections. This allows cleartext HTTP traffic and weakens \
                        TLS requirements, exposing the app to man-in-the-middle attacks."
                        .to_string(),
                    file_path: Some("Info.plist".to_string()),
                    line_number: None,
                    cwe: Some("CWE-319".to_string()),
                    owasp: None,
                    masvs: Some("MASVS-NETWORK-1".to_string()),
                    evidence: Some("NSAllowsArbitraryLoads = true".to_string()),
                });
            }

            if ats.allows_arbitrary_loads_in_web_content {
                findings.push(ScanFinding {
                    rule_id: "ios_ats_web_content".to_string(),
                    title: "ATS allows arbitrary loads in web content".to_string(),
                    severity: "high".to_string(),
                    description: "NSAllowsArbitraryLoadsInWebContent is set to true. \
                        This disables ATS for content loaded in web views, allowing \
                        insecure HTTP connections in WKWebView contexts."
                        .to_string(),
                    file_path: Some("Info.plist".to_string()),
                    line_number: None,
                    cwe: Some("CWE-319".to_string()),
                    owasp: None,
                    masvs: Some("MASVS-NETWORK-1".to_string()),
                    evidence: Some("NSAllowsArbitraryLoadsInWebContent = true".to_string()),
                });
            }

            for domain in &ats.exception_domains {
                if domain.allows_insecure_http {
                    findings.push(ScanFinding {
                        rule_id: "ios_ats_exception_domain".to_string(),
                        title: format!("ATS exception domain allows insecure HTTP: {}", domain.domain),
                        severity: "medium".to_string(),
                        description: format!(
                            "The ATS exception domain '{}' has NSExceptionAllowsInsecureHTTPLoads=true, \
                            permitting cleartext HTTP traffic to this domain.",
                            domain.domain
                        ),
                        file_path: Some("Info.plist".to_string()),
                        line_number: None,
                        cwe: Some("CWE-319".to_string()),
                        owasp: None,
                        masvs: Some("MASVS-NETWORK-1".to_string()),
                        evidence: Some(format!(
                            "NSExceptionDomains.{}.NSExceptionAllowsInsecureHTTPLoads = true",
                            domain.domain
                        )),
                    });
                }
            }
        }
    }

    // Minimum OS version
    if !info.minimum_os_version.is_empty() {
        let major = info.minimum_os_version
            .split('.')
            .next()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(99);
        if major < 14 {
            findings.push(ScanFinding {
                rule_id: "ios_minimum_os_old".to_string(),
                title: format!("Minimum iOS version is old: {}", info.minimum_os_version),
                severity: "medium".to_string(),
                description: format!(
                    "The app targets a minimum iOS version of {} which is below 14.0. \
                    Older iOS versions lack important security features and receive no \
                    security patches.",
                    info.minimum_os_version
                ),
                file_path: Some("Info.plist".to_string()),
                line_number: None,
                cwe: None,
                owasp: None,
                masvs: None,
                evidence: Some(format!("MinimumOSVersion = {}", info.minimum_os_version)),
            });
        }
    }

    // URL schemes
    if !info.url_schemes.is_empty() {
        findings.push(ScanFinding {
            rule_id: "ios_url_scheme_registered".to_string(),
            title: format!("Custom URL schemes registered: {}", info.url_schemes.join(", ")),
            severity: "info".to_string(),
            description: "The app registers custom URL schemes. These can be used for \
                deep linking or inter-app communication. Ensure proper validation of \
                incoming URL parameters to prevent URL scheme hijacking."
                .to_string(),
            file_path: Some("Info.plist".to_string()),
            line_number: None,
            cwe: None,
            owasp: None,
            masvs: None,
            evidence: Some(format!("CFBundleURLSchemes: {}", info.url_schemes.join(", "))),
        });
    }

    // Background modes
    if !info.background_modes.is_empty() {
        findings.push(ScanFinding {
            rule_id: "ios_background_modes".to_string(),
            title: format!("Background modes enabled: {}", info.background_modes.join(", ")),
            severity: "info".to_string(),
            description: "The app uses background execution modes. Review each mode \
                to ensure sensitive data is handled securely during background execution."
                .to_string(),
            file_path: Some("Info.plist".to_string()),
            line_number: None,
            cwe: None,
            owasp: None,
            masvs: None,
            evidence: Some(format!("UIBackgroundModes: {}", info.background_modes.join(", "))),
        });
    }

    // Missing camera usage description
    let uses_camera = info.usage_descriptions.contains_key("NSCameraUsageDescription");
    // Check if app might need camera (heuristic: if it accesses photo library it likely uses camera too)
    let uses_photo = info.usage_descriptions.contains_key("NSPhotoLibraryUsageDescription")
        || info.usage_descriptions.contains_key("NSPhotoLibraryAddUsageDescription");
    if uses_photo && !uses_camera {
        findings.push(ScanFinding {
            rule_id: "ios_usage_desc_missing_camera".to_string(),
            title: "NSCameraUsageDescription may be missing".to_string(),
            severity: "medium".to_string(),
            description: "The app declares photo library access but does not declare \
                NSCameraUsageDescription. If the app accesses the camera without \
                this description it will crash on iOS 10+."
                .to_string(),
            file_path: Some("Info.plist".to_string()),
            line_number: None,
            cwe: None,
            owasp: None,
            masvs: None,
            evidence: None,
        });
    }

    // Missing location usage description
    let has_location_always = info.usage_descriptions.contains_key("NSLocationAlwaysUsageDescription")
        || info.usage_descriptions.contains_key("NSLocationAlwaysAndWhenInUseUsageDescription");
    let has_location_when = info.usage_descriptions.contains_key("NSLocationWhenInUseUsageDescription");
    if has_location_always && !has_location_when {
        findings.push(ScanFinding {
            rule_id: "ios_usage_desc_missing_location".to_string(),
            title: "NSLocationWhenInUseUsageDescription is missing".to_string(),
            severity: "medium".to_string(),
            description: "The app requests always-on location but is missing \
                NSLocationWhenInUseUsageDescription. iOS 11+ requires this key even \
                when requesting always-on access."
                .to_string(),
            file_path: Some("Info.plist".to_string()),
            line_number: None,
            cwe: None,
            owasp: None,
            masvs: None,
            evidence: None,
        });
    }

    // Associated domains
    if !info.associated_domains.is_empty() {
        findings.push(ScanFinding {
            rule_id: "ios_associated_domains".to_string(),
            title: format!("Associated domains registered ({})", info.associated_domains.len()),
            severity: "info".to_string(),
            description: "The app uses associated domains for Universal Links or \
                Shared Web Credentials. Ensure the apple-app-site-association file \
                on each domain is properly secured."
                .to_string(),
            file_path: Some("Info.plist".to_string()),
            line_number: None,
            cwe: None,
            owasp: None,
            masvs: None,
            evidence: Some(info.associated_domains.join(", ")),
        });
    }

    // UISupportsDocumentBrowser
    if info.supports_documents {
        findings.push(ScanFinding {
            rule_id: "ios_supports_documents".to_string(),
            title: "App supports document browser (UISupportsDocumentBrowser=true)".to_string(),
            severity: "info".to_string(),
            description: "UISupportsDocumentBrowser is set to true, allowing the Files app \
                to browse this app's documents. Verify that sensitive documents are \
                excluded from public browsing."
                .to_string(),
            file_path: Some("Info.plist".to_string()),
            line_number: None,
            cwe: None,
            owasp: None,
            masvs: None,
            evidence: Some("UISupportsDocumentBrowser = true".to_string()),
        });
    }

    // LSApplicationQueriesSchemes
    if !info.query_schemes.is_empty() {
        findings.push(ScanFinding {
            rule_id: "ios_query_schemes_registered".to_string(),
            title: format!(
                "LSApplicationQueriesSchemes has {} entries",
                info.query_schemes.len()
            ),
            severity: "info".to_string(),
            description: "The app queries for the availability of other apps by URL scheme. \
                This can reveal information about the user's installed apps."
                .to_string(),
            file_path: Some("Info.plist".to_string()),
            line_number: None,
            cwe: None,
            owasp: None,
            masvs: None,
            evidence: Some(info.query_schemes.join(", ")),
        });
    }

    // Exported UTIs
    if !info.exported_utis.is_empty() {
        findings.push(ScanFinding {
            rule_id: "ios_exported_utis".to_string(),
            title: format!("App exports {} UTI document types", info.exported_utis.len()),
            severity: "info".to_string(),
            description: "The app exports document type UTIs via CFBundleDocumentTypes. \
                Ensure sensitive file types are not unintentionally opened by other apps."
                .to_string(),
            file_path: Some("Info.plist".to_string()),
            line_number: None,
            cwe: None,
            owasp: None,
            masvs: None,
            evidence: Some(info.exported_utis.join(", ")),
        });
    }

    findings
}
