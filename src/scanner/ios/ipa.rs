// IPA extraction and provisioning profile parsing

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtractedIpa {
    pub dir: PathBuf,
    pub app_dir: PathBuf,
    pub info_plist_bytes: Vec<u8>,
    pub binary_path: Option<PathBuf>,
    pub entitlements_path: Option<PathBuf>,
    pub provisioning_path: Option<PathBuf>,
    pub framework_dirs: Vec<PathBuf>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProvisioningProfile {
    pub app_id_name: String,
    pub bundle_id: String,
    pub team_name: String,
    pub is_development: bool,
    pub expiry: String,
    pub entitlements: HashMap<String, serde_json::Value>,
    pub aps_environment: Option<String>,
    pub get_task_allow: bool,
}

pub async fn extract_ipa(ipa_path: &Path, dest_dir: &Path) -> Result<ExtractedIpa> {
    let ipa_path = ipa_path.to_path_buf();
    let dest_dir = dest_dir.to_path_buf();

    tokio::fs::create_dir_all(&dest_dir).await
        .context("Failed to create destination directory")?;

    // Run extraction in a blocking thread
    let result = tokio::task::spawn_blocking(move || {
        extract_ipa_sync(&ipa_path, &dest_dir)
    })
    .await
    .context("Extraction task panicked")??;

    Ok(result)
}

fn extract_ipa_sync(ipa_path: &Path, dest_dir: &Path) -> Result<ExtractedIpa> {
    let file = std::fs::File::open(ipa_path)
        .context("Failed to open IPA file")?;
    let mut archive = zip::ZipArchive::new(file)
        .context("Failed to open IPA as zip")?;

    // Extract all files
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let out_path = dest_dir.join(entry.name());

        if entry.is_dir() {
            std::fs::create_dir_all(&out_path)?;
        } else {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut out_file = std::fs::File::create(&out_path)?;
            std::io::copy(&mut entry, &mut out_file)?;
        }
    }

    // Find Payload/*.app directory
    let payload_dir = dest_dir.join("Payload");
    let app_dir = find_app_dir(&payload_dir)
        .context("No .app directory found in Payload/")?;

    // Read Info.plist
    let info_plist_path = app_dir.join("Info.plist");
    let info_plist_bytes = std::fs::read(&info_plist_path)
        .context("Failed to read Info.plist")?;

    // Determine app name from .app directory name
    let app_name = app_dir
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    // Main binary: same name as the .app
    let binary_path = {
        let candidate = app_dir.join(app_name);
        if candidate.exists() && candidate.is_file() {
            Some(candidate)
        } else {
            None
        }
    };

    // Entitlements.plist
    let entitlements_path = {
        let candidate = app_dir.join("Entitlements.plist");
        if candidate.exists() {
            Some(candidate)
        } else {
            None
        }
    };

    // embedded.mobileprovision
    let provisioning_path = {
        let candidate = app_dir.join("embedded.mobileprovision");
        if candidate.exists() {
            Some(candidate)
        } else {
            None
        }
    };

    // Frameworks/*.framework dirs
    let frameworks_dir = app_dir.join("Frameworks");
    let framework_dirs = collect_framework_dirs(&frameworks_dir);

    Ok(ExtractedIpa {
        dir: dest_dir.to_path_buf(),
        app_dir,
        info_plist_bytes,
        binary_path,
        entitlements_path,
        provisioning_path,
        framework_dirs,
    })
}

fn find_app_dir(payload_dir: &Path) -> Option<PathBuf> {
    if !payload_dir.is_dir() {
        return None;
    }
    for entry in std::fs::read_dir(payload_dir).ok()?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if ext == "app" {
                    return Some(path);
                }
            }
        }
    }
    None
}

fn collect_framework_dirs(frameworks_dir: &Path) -> Vec<PathBuf> {
    if !frameworks_dir.is_dir() {
        return Vec::new();
    }
    let mut dirs = Vec::new();
    if let Ok(entries) = std::fs::read_dir(frameworks_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if ext == "framework" {
                        dirs.push(path);
                    }
                }
            }
        }
    }
    dirs
}

/// Parse an embedded.mobileprovision CMS envelope by extracting the embedded XML plist.
pub fn parse_mobileprovision(data: &[u8]) -> Option<ProvisioningProfile> {
    // Find the embedded XML plist inside the CMS SignedData structure
    let start_tag = b"<?xml";
    let end_tag = b"</plist>";

    let start = data.windows(start_tag.len())
        .position(|w| w == start_tag)?;
    let end_search_start = start;
    let end = data[end_search_start..].windows(end_tag.len())
        .position(|w| w == end_tag)
        .map(|p| end_search_start + p + end_tag.len())?;

    let xml_bytes = &data[start..end];

    let plist_value = plist::Value::from_reader(std::io::Cursor::new(xml_bytes)).ok()?;
    let dict = plist_value.as_dictionary()?;

    let app_id_name = dict.get("AppIDName")
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_string();

    let team_name = dict.get("TeamName")
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_string();

    // Bundle ID from Name field or Entitlements
    let bundle_id = dict.get("Entitlements")
        .and_then(|v| v.as_dictionary())
        .and_then(|e| e.get("application-identifier"))
        .and_then(|v| v.as_string())
        .map(|s| {
            // Strip team prefix: "TEAMID.com.example.app" -> "com.example.app"
            if let Some(dot_pos) = s.find('.') {
                s[dot_pos + 1..].to_string()
            } else {
                s.to_string()
            }
        })
        .unwrap_or_default();

    // is_development: ProvisionedDevices key present means dev profile
    let is_development = dict.contains_key("ProvisionedDevices");

    // Expiry date
    let expiry = dict.get("ExpirationDate")
        .and_then(|v| v.as_date())
        .map(|d| {
            let sys_time: std::time::SystemTime = d.into();
            let dt: chrono::DateTime<chrono::Utc> = sys_time.into();
            dt.to_rfc3339()
        })
        .unwrap_or_default();

    // Parse entitlements dict
    let mut entitlements: HashMap<String, serde_json::Value> = HashMap::new();
    let mut aps_environment: Option<String> = None;
    let mut get_task_allow = false;

    if let Some(ent_dict) = dict.get("Entitlements").and_then(|v| v.as_dictionary()) {
        for (k, v) in ent_dict {
            let json_val = plist_value_to_json(v);
            if k == "aps-environment" {
                aps_environment = v.as_string().map(|s| s.to_string());
            }
            if k == "get-task-allow" {
                get_task_allow = v.as_boolean().unwrap_or(false);
            }
            entitlements.insert(k.clone(), json_val);
        }
    }

    Some(ProvisioningProfile {
        app_id_name,
        bundle_id,
        team_name,
        is_development,
        expiry,
        entitlements,
        aps_environment,
        get_task_allow,
    })
}

fn plist_value_to_json(v: &plist::Value) -> serde_json::Value {
    match v {
        plist::Value::Boolean(b) => serde_json::Value::Bool(*b),
        plist::Value::Integer(i) => {
            if let Some(n) = i.as_signed() {
                serde_json::json!(n)
            } else if let Some(n) = i.as_unsigned() {
                serde_json::json!(n)
            } else {
                serde_json::Value::Null
            }
        }
        plist::Value::Real(f) => {
            serde_json::Number::from_f64(*f)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null)
        }
        plist::Value::String(s) => serde_json::Value::String(s.clone()),
        plist::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(plist_value_to_json).collect())
        }
        plist::Value::Dictionary(d) => {
            let map: serde_json::Map<String, serde_json::Value> = d
                .iter()
                .map(|(k, v)| (k.clone(), plist_value_to_json(v)))
                .collect();
            serde_json::Value::Object(map)
        }
        plist::Value::Data(bytes) => serde_json::Value::String(hex::encode(bytes)),
        plist::Value::Date(date) => {
            let sys_time: std::time::SystemTime = (*date).into();
            let dt: chrono::DateTime<chrono::Utc> = sys_time.into();
            serde_json::Value::String(dt.to_rfc3339())
        }
        plist::Value::Uid(uid) => serde_json::json!(uid.get()),
        _ => serde_json::Value::Null,
    }
}
