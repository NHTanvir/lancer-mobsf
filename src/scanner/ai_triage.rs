// AI triage summarizer — uses the Claude API to generate intelligent triage
// summaries of scan findings.
//
// Requires ANTHROPIC_API_KEY environment variable. Returns Ok(None) if the key
// is not set so the rest of the pipeline can proceed without it.

use crate::scanner::ScanFinding;
use anyhow::Result;
use reqwest::Client;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TriageSummary {
    pub top_findings: Vec<TopFinding>,
    pub executive_summary: String,
    pub attack_vectors: Vec<String>,
    pub recommended_actions: Vec<String>,
    /// "critical" | "high" | "medium" | "low"
    pub estimated_severity: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TopFinding {
    pub rank: u8,
    pub rule_id: String,
    pub title: String,
    pub exploit_hypothesis: String,
    /// "high" | "medium" | "low"
    pub confidence: String,
}

/// Format up to 30 findings into a compact text block for the prompt.
fn format_findings_for_prompt(findings: &[ScanFinding]) -> String {
    findings.iter().take(30).enumerate().map(|(i, f)| {
        let file_line = match (&f.file_path, f.line_number) {
            (Some(fp), Some(ln)) => format!("   File: {}:{}", fp, ln),
            (Some(fp), None)    => format!("   File: {}", fp),
            _                   => String::new(),
        };
        let evidence = f.evidence.as_deref()
            .map(|e| format!("\n   Evidence: {}", e))
            .unwrap_or_default();
        format!(
            "{}. [{}] {}: {}{}{}\n",
            i + 1,
            f.severity.to_uppercase(),
            f.rule_id,
            f.title,
            if file_line.is_empty() { String::new() } else { format!("\n{}", file_line) },
            evidence,
        )
    }).collect()
}

fn severity_order(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high"     => 1,
        "medium"   => 2,
        "low"      => 3,
        _          => 4,
    }
}

/// Generate AI triage summary for scan findings.
/// Requires ANTHROPIC_API_KEY environment variable.
/// Returns Ok(None) if key not set or on any error.
pub async fn generate_triage(
    findings: &[ScanFinding],
    package_name: &str,
    scan_type: &str,
) -> Result<Option<TriageSummary>> {
    // Step 1: Check for API key — return Ok(None) if missing
    let api_key = match std::env::var("ANTHROPIC_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            tracing::debug!("ANTHROPIC_API_KEY not set; skipping AI triage");
            return Ok(None);
        }
    };

    if findings.is_empty() {
        return Ok(None);
    }

    // Step 2: Sort by severity and build prompt with top 30 findings
    let mut sorted = findings.to_vec();
    sorted.sort_by_key(|f| severity_order(f.severity.as_str()));

    let formatted = format_findings_for_prompt(&sorted);

    let prompt = format!(
        "You are a mobile security researcher. Analyze these security findings from a {scan_type} app ({package_name}) and provide a security triage.\n\n\
FINDINGS:\n{formatted}\n\n\
Respond with a JSON object:\n\
{{\n  \
  \"executive_summary\": \"2-3 sentence overview of the app's security posture\",\n  \
  \"top_findings\": [\n    \
    {{\n      \
      \"rank\": 1,\n      \
      \"rule_id\": \"...\",\n      \
      \"title\": \"...\",\n      \
      \"exploit_hypothesis\": \"How an attacker might exploit this finding\",\n      \
      \"confidence\": \"high|medium|low\"\n    \
    }}\n  \
  ],\n  \
  \"attack_vectors\": [\"list of likely attack vectors\"],\n  \
  \"recommended_actions\": [\"prioritized remediation steps\"],\n  \
  \"estimated_severity\": \"critical|high|medium|low\"\n\
}}\n\n\
Return ONLY valid JSON, no markdown, no explanation.",
        scan_type = scan_type,
        package_name = package_name,
        formatted = formatted,
    );

    // Step 3: POST to Claude API
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .unwrap_or_default();

    let body = serde_json::json!({
        "model": "claude-sonnet-4-6",
        "max_tokens": 2048,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    });

    let resp = match client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", &api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
    {
        Ok(r)  => r,
        Err(e) => {
            tracing::warn!("AI triage request failed: {}", e);
            return Ok(None);
        }
    };

    if !resp.status().is_success() {
        tracing::warn!("AI triage API returned status {}", resp.status());
        return Ok(None);
    }

    // Step 4: Parse response — content[0].text contains the JSON
    let json: serde_json::Value = match resp.json().await {
        Ok(j)  => j,
        Err(e) => {
            tracing::warn!("AI triage JSON parse error: {}", e);
            return Ok(None);
        }
    };

    let text = match json["content"][0]["text"].as_str() {
        Some(t) => t.to_string(),
        None    => {
            tracing::warn!("AI triage: unexpected response shape");
            return Ok(None);
        }
    };

    // Step 5: Parse the JSON into TriageSummary
    match serde_json::from_str::<TriageSummary>(&text) {
        Ok(summary) => Ok(Some(summary)),
        Err(e) => {
            tracing::warn!("AI triage: failed to parse triage JSON: {}", e);
            Ok(None)
        }
    }
}
