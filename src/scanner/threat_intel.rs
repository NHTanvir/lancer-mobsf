// Threat intelligence integration: VirusTotal + MalwareBazaar
use crate::scanner::ScanFinding;
use anyhow::Result;
use reqwest::Client;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VtResult {
    pub malicious: u32,
    pub suspicious: u32,
    pub harmless: u32,
    pub undetected: u32,
    pub total: u32,
    pub scan_date: String,
    pub permalink: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MalwareBazaarResult {
    pub query_status: String, // "ok" | "hash_not_found"
    pub md5_hash: Option<String>,
    pub sha256_hash: Option<String>,
    pub file_name: Option<String>,
    pub file_type: Option<String>,
    pub tags: Vec<String>,
    pub signature: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThreatIntelResult {
    pub virustotal: Option<VtResult>,
    pub malwarebazaar: Option<MalwareBazaarResult>,
}

/// Query VirusTotal for a SHA256 hash.
/// Requires VIRUSTOTAL_API_KEY environment variable.
/// Returns Ok(None) if key not set or file not found in VT.
pub async fn query_virustotal(sha256: &str) -> Result<Option<VtResult>> {
    let api_key = match std::env::var("VIRUSTOTAL_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => return Ok(None),
    };

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default();

    let url = format!("https://www.virustotal.com/api/v3/files/{}", sha256);
    let resp = client
        .get(&url)
        .header("x-apikey", &api_key)
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("VirusTotal request failed: {}", e);
            return Ok(None);
        }
    };

    if resp.status().as_u16() == 404 {
        return Ok(None);
    }

    if !resp.status().is_success() {
        tracing::warn!("VirusTotal returned status {}", resp.status());
        return Ok(None);
    }

    let json: serde_json::Value = match resp.json().await {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!("VirusTotal JSON parse error: {}", e);
            return Ok(None);
        }
    };

    let attrs = &json["data"]["attributes"];
    let stats = &attrs["last_analysis_stats"];

    let malicious = stats["malicious"].as_u64().unwrap_or(0) as u32;
    let suspicious = stats["suspicious"].as_u64().unwrap_or(0) as u32;
    let harmless = stats["harmless"].as_u64().unwrap_or(0) as u32;
    let undetected = stats["undetected"].as_u64().unwrap_or(0) as u32;
    let total = malicious + suspicious + harmless + undetected;

    let scan_date = attrs["last_analysis_date"]
        .as_u64()
        .map(|ts| ts.to_string())
        .unwrap_or_default();

    let permalink = format!("https://www.virustotal.com/gui/file/{}", sha256);

    Ok(Some(VtResult {
        malicious,
        suspicious,
        harmless,
        undetected,
        total,
        scan_date,
        permalink,
    }))
}

/// Query MalwareBazaar for a SHA256 hash (no API key required).
pub async fn query_malwarebazaar(sha256: &str) -> Result<Option<MalwareBazaarResult>> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default();

    let body = format!("query=get_info&hash={}", sha256);
    let resp = client
        .post("https://mb-api.abuse.ch/api/v1/")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("MalwareBazaar request failed: {}", e);
            return Ok(None);
        }
    };

    let json: serde_json::Value = match resp.json().await {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!("MalwareBazaar JSON parse error: {}", e);
            return Ok(None);
        }
    };

    let query_status = json["query_status"]
        .as_str()
        .unwrap_or("hash_not_found")
        .to_string();

    if query_status != "ok" {
        return Ok(Some(MalwareBazaarResult {
            query_status,
            md5_hash: None,
            sha256_hash: None,
            file_name: None,
            file_type: None,
            tags: Vec::new(),
            signature: None,
            first_seen: None,
            last_seen: None,
        }));
    }

    let data = &json["data"][0];

    let tags: Vec<String> = data["tags"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    Ok(Some(MalwareBazaarResult {
        query_status,
        md5_hash: data["md5_hash"].as_str().map(|s| s.to_string()),
        sha256_hash: data["sha256_hash"].as_str().map(|s| s.to_string()),
        file_name: data["file_name"].as_str().map(|s| s.to_string()),
        file_type: data["file_type"].as_str().map(|s| s.to_string()),
        tags,
        signature: data["signature"].as_str().map(|s| s.to_string()),
        first_seen: data["first_seen"].as_str().map(|s| s.to_string()),
        last_seen: data["last_seen"].as_str().map(|s| s.to_string()),
    }))
}

/// Run both VT and MalwareBazaar queries, generate findings based on results.
pub async fn analyze_threat_intel(sha256: &str) -> Result<(ThreatIntelResult, Vec<ScanFinding>)> {
    let (vt_result, mb_result) = tokio::join!(
        query_virustotal(sha256),
        query_malwarebazaar(sha256)
    );

    let vt = vt_result.unwrap_or(None);
    let mb = mb_result.unwrap_or(None);

    let mut findings: Vec<ScanFinding> = Vec::new();

    // VirusTotal findings
    if let Some(ref vt) = vt {
        if vt.malicious > 0 {
            findings.push(ScanFinding {
                rule_id: "threat_vt_malicious".to_string(),
                title: "VirusTotal: Malware detected".to_string(),
                severity: "critical".to_string(),
                description: format!(
                    "VirusTotal: {}/{} engines detected malware. See: {}",
                    vt.malicious, vt.total, vt.permalink
                ),
                file_path: None,
                line_number: None,
                cwe: Some("CWE-507".to_string()),
                owasp: None,
                masvs: None,
                evidence: Some(vt.permalink.clone()),
            });
        }

        if vt.suspicious > 5 {
            findings.push(ScanFinding {
                rule_id: "threat_vt_suspicious".to_string(),
                title: "VirusTotal: Multiple engines flagged as suspicious".to_string(),
                severity: "high".to_string(),
                description: format!(
                    "VirusTotal: {} engines flagged as suspicious. See: {}",
                    vt.suspicious, vt.permalink
                ),
                file_path: None,
                line_number: None,
                cwe: Some("CWE-507".to_string()),
                owasp: None,
                masvs: None,
                evidence: Some(vt.permalink.clone()),
            });
        }
    }

    // MalwareBazaar findings
    if let Some(ref mb) = mb {
        if mb.query_status == "ok" {
            let sig = mb
                .signature
                .as_deref()
                .unwrap_or("unknown");
            findings.push(ScanFinding {
                rule_id: "threat_mb_known_malware".to_string(),
                title: "MalwareBazaar: Known malware hash".to_string(),
                severity: "critical".to_string(),
                description: format!(
                    "MalwareBazaar: Known malware (signature: {}). The file hash matches a known malware sample.",
                    sig
                ),
                file_path: None,
                line_number: None,
                cwe: Some("CWE-507".to_string()),
                owasp: None,
                masvs: None,
                evidence: mb.sha256_hash.clone(),
            });
        }
    }

    Ok((ThreatIntelResult { virustotal: vt, malwarebazaar: mb }, findings))
}
