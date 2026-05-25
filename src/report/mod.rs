// report module - report generation and templates

use crate::masvs::MasvsReport;
use crate::scanner::android::AndroidScanResult;
use anyhow::Result;
use minijinja::{context, Environment};
use std::path::Path;

const REPORT_TEMPLATE: &str = r#"
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>lancer-mobsf - {{ package_name }} Security Report</title>
  <style>
    body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
    h1 { color: #58a6ff; }
    h2 { color: #79c0ff; border-bottom: 1px solid #30363d; padding-bottom: 6px; }
    .critical { background: #3d1a1a; color: #ff7b7b; padding: 4px 8px; border-radius: 3px; }
    .high { background: #3d2a1a; color: #ffa657; padding: 4px 8px; border-radius: 3px; }
    .medium { background: #3d351a; color: #e3b341; padding: 4px 8px; border-radius: 3px; }
    .low { background: #1a2a3d; color: #58a6ff; padding: 4px 8px; border-radius: 3px; }
    .info { background: #1a2a1a; color: #3fb950; padding: 4px 8px; border-radius: 3px; }
    .pass { background: #1a3d1a; color: #3fb950; padding: 4px 8px; border-radius: 3px; }
    .fail { background: #3d1a1a; color: #ff7b7b; padding: 4px 8px; border-radius: 3px; }
    .partial { background: #3d351a; color: #e3b341; padding: 4px 8px; border-radius: 3px; }
    .nottested { background: #21262d; color: #8b949e; padding: 4px 8px; border-radius: 3px; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th { background: #161b22; padding: 10px; text-align: left; border-bottom: 1px solid #30363d; }
    td { padding: 8px 10px; border-bottom: 1px solid #21262d; vertical-align: top; }
    .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 20px 0; }
    .summary-box { padding: 15px; border-radius: 8px; text-align: center; }
    .summary-box .count { font-size: 2em; font-weight: bold; }
    .evidence { font-family: monospace; font-size: 0.85em; color: #8b949e; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .triage-box { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin: 20px 0; }
    .triage-box p { margin: 8px 0; }
    .triage-tag { display: inline-block; background: #21262d; color: #8b949e; padding: 2px 8px; border-radius: 3px; margin: 2px; font-size: 0.85em; }
    .attack-vec { color: #ffa657; }
    .action-item { color: #3fb950; }
    .cve-table td { font-size: 0.9em; }
  </style>
</head>
<body>
  <h1>lancer-mobsf Security Report</h1>
  <p><strong>Package:</strong> {{ package_name }} v{{ version_name }}<br>
     <strong>SHA256:</strong> {{ sha256 }}<br>
     <strong>Scan ID:</strong> {{ scan_id }}</p>

  <div class="summary-grid">
    <div class="summary-box critical"><div class="count">{{ counts.critical }}</div>Critical</div>
    <div class="summary-box high"><div class="count">{{ counts.high }}</div>High</div>
    <div class="summary-box medium"><div class="count">{{ counts.medium }}</div>Medium</div>
    <div class="summary-box low"><div class="count">{{ counts.low }}</div>Low</div>
    <div class="summary-box info"><div class="count">{{ counts.info }}</div>Info</div>
  </div>

  {% if ai_triage %}
  <h2>AI Triage Analysis</h2>
  <div class="triage-box">
    <p><strong>Estimated Severity:</strong>
      <span class="{{ ai_triage.estimated_severity }}">{{ ai_triage.estimated_severity | upper }}</span>
    </p>
    <p><strong>Executive Summary:</strong><br>{{ ai_triage.executive_summary }}</p>

    {% if ai_triage.attack_vectors %}
    <p><strong>Attack Vectors:</strong><br>
      {% for v in ai_triage.attack_vectors %}
        <span class="triage-tag attack-vec">{{ v }}</span>
      {% endfor %}
    </p>
    {% endif %}

    {% if ai_triage.recommended_actions %}
    <p><strong>Recommended Actions:</strong></p>
    <ol>
      {% for action in ai_triage.recommended_actions %}
      <li class="action-item">{{ action }}</li>
      {% endfor %}
    </ol>
    {% endif %}

    {% if ai_triage.top_findings %}
    <p><strong>Top Findings (AI-ranked):</strong></p>
    <table>
      <tr><th>#</th><th>Rule</th><th>Title</th><th>Exploit Hypothesis</th><th>Confidence</th></tr>
      {% for tf in ai_triage.top_findings %}
      {% if loop.index <= 5 %}
      <tr>
        <td>{{ tf.rank }}</td>
        <td>{{ tf.rule_id }}</td>
        <td>{{ tf.title }}</td>
        <td>{{ tf.exploit_hypothesis }}</td>
        <td><span class="{{ tf.confidence }}">{{ tf.confidence | upper }}</span></td>
      </tr>
      {% endif %}
      {% endfor %}
    </table>
    {% endif %}
  </div>
  {% endif %}

  {% if cve_results %}
  <h2>CVE Correlation — Detected Libraries</h2>
  <table class="cve-table">
    <tr><th>Library</th><th>Version</th><th>CVE Count</th><th>Highest CVSS</th><th>CVE IDs</th></tr>
    {% for lr in cve_results %}
    {% if lr.cves %}
    <tr>
      <td>{{ lr.library.name }}</td>
      <td>{{ lr.library.version }}</td>
      <td>{{ lr.cves | length }}</td>
      <td>{% if lr.highest_cvss %}{{ lr.highest_cvss }}{% else %}—{% endif %}</td>
      <td>
        {% for cve in lr.cves %}
          <span class="triage-tag">{{ cve.cve_id }}</span>
        {% endfor %}
      </td>
    </tr>
    {% endif %}
    {% endfor %}
  </table>
  {% endif %}

  {% if masvs_categories %}
  <h2>MASVS v2 Compliance Score</h2>
  <table>
    <tr><th>Category</th><th>Score</th><th>Status</th><th>Failed Checks</th></tr>
    {% for cat in masvs_categories %}
    <tr>
      <td>{{ cat.name }}</td>
      <td>{{ cat.score_pct }}%</td>
      <td><span class="{{ cat.status_lower }}">{{ cat.status }}</span></td>
      <td>{{ cat.failing_checks_str }}</td>
    </tr>
    {% endfor %}
    <tr style="font-weight:bold">
      <td>Overall</td>
      <td>{{ overall_score_pct }}%</td>
      <td>{{ overall_status }}</td>
      <td></td>
    </tr>
  </table>
  {% endif %}

  <h2>Findings ({{ counts.total }} total)</h2>
  <table>
    <tr><th>Severity</th><th>Rule</th><th>Title</th><th>CWE</th><th>MASVS</th><th>File</th><th>Evidence</th></tr>
    {% for f in findings %}
    <tr>
      <td><span class="{{ f.severity }}">{{ f.severity | upper }}</span></td>
      <td>{{ f.rule_id }}</td>
      <td>{{ f.title }}</td>
      <td>{{ f.cwe | default("") }}</td>
      <td>{{ f.masvs | default("") }}</td>
      <td>{{ f.file_path | default("") }}</td>
      <td class="evidence">{{ f.evidence | default("") }}</td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"#;

/// Build a serde_json::Value list of MASVS category rows for template rendering.
fn masvs_categories_to_json(masvs: &MasvsReport) -> serde_json::Value {
    let cats: Vec<serde_json::Value> = masvs.categories.iter().map(|cat| {
        let score_pct = (cat.score * 100.0).round() as i64;
        let status_str = format!("{}", cat.status);
        let status_lower = status_str.to_lowercase();
        let failing_str = cat.failing_checks.join(", ");
        serde_json::json!({
            "name": cat.name,
            "score_pct": score_pct,
            "status": status_str,
            "status_lower": status_lower,
            "failing_checks_str": failing_str,
        })
    }).collect();
    serde_json::Value::Array(cats)
}

/// Generate HTML report from an AndroidScanResult with optional MASVS scoring.
pub fn render_html_report(result: &AndroidScanResult) -> Result<String> {
    let masvs = result.masvs_report.as_ref().map(|m| m.clone())
        .unwrap_or_else(|| crate::masvs::MasvsReport {
            categories: vec![],
            overall_score: 0.0,
            overall_status: crate::masvs::MasvsStatus::NotTested,
        });
    render_html_report_with_masvs(result, &masvs)
}

/// Generate HTML report from an AndroidScanResult with explicit MASVS report.
pub fn render_html_report_with_masvs(result: &AndroidScanResult, masvs: &MasvsReport) -> Result<String> {
    let mut env = Environment::new();
    env.add_template("report", REPORT_TEMPLATE)?;
    let tmpl = env.get_template("report")?;

    let counts = serde_json::json!({
        "critical": result.finding_counts.critical,
        "high": result.finding_counts.high,
        "medium": result.finding_counts.medium,
        "low": result.finding_counts.low,
        "info": result.finding_counts.info,
        "total": result.finding_counts.total,
    });

    let findings_val = serde_json::to_value(&result.findings)?;
    let masvs_cats = masvs_categories_to_json(masvs);
    let overall_score_pct = (masvs.overall_score * 100.0).round() as i64;
    let overall_status = format!("{}", masvs.overall_status);
    let ai_triage_val = serde_json::to_value(&result.ai_triage)?;
    let cve_results_val = serde_json::to_value(&result.cve_results)?;

    let html = tmpl.render(context! {
        package_name => result.package_name,
        version_name => result.version_name,
        sha256 => result.sha256,
        scan_id => result.scan_id,
        counts => counts,
        findings => findings_val,
        masvs_categories => masvs_cats,
        overall_score_pct => overall_score_pct,
        overall_status => overall_status,
        ai_triage => ai_triage_val,
        cve_results => cve_results_val,
    })?;

    Ok(html)
}

/// Generate HTML report for an iOS scan result with MASVS scoring.
pub fn render_ios_html_report(
    result: &crate::scanner::ios::IosScanResult,
    masvs: &MasvsReport,
) -> Result<String> {
    let mut env = Environment::new();
    env.add_template("report", REPORT_TEMPLATE)?;
    let tmpl = env.get_template("report")?;

    let counts = serde_json::json!({
        "critical": result.finding_counts.critical,
        "high": result.finding_counts.high,
        "medium": result.finding_counts.medium,
        "low": result.finding_counts.low,
        "info": result.finding_counts.info,
        "total": result.finding_counts.total,
    });

    let findings_val = serde_json::to_value(&result.findings)?;
    let masvs_cats = masvs_categories_to_json(masvs);
    let overall_score_pct = (masvs.overall_score * 100.0).round() as i64;
    let overall_status = format!("{}", masvs.overall_status);
    let ai_triage_val = serde_json::to_value(&result.ai_triage)?;
    let cve_results_val = serde_json::to_value(&result.cve_results)?;

    let html = tmpl.render(context! {
        package_name => result.bundle_id,
        version_name => result.version,
        sha256 => result.sha256,
        scan_id => result.scan_id,
        counts => counts,
        findings => findings_val,
        masvs_categories => masvs_cats,
        overall_score_pct => overall_score_pct,
        overall_status => overall_status,
        ai_triage => ai_triage_val,
        cve_results => cve_results_val,
    })?;

    Ok(html)
}

/// Serialize Android scan result to JSON string.
pub fn render_json_report(result: &AndroidScanResult) -> Result<String> {
    let json = serde_json::to_string_pretty(result)?;
    Ok(json)
}

/// Generate PDF report from HTML by shelling out to `weasyprint`.
/// Requires 'weasyprint' in PATH. Returns None if not available.
pub async fn render_pdf_report(html: &str, output_path: &Path) -> Option<Vec<u8>> {
    // Check if weasyprint is available
    let check = tokio::process::Command::new("weasyprint")
        .arg("--version")
        .output()
        .await;

    if check.is_err() || !check.unwrap().status.success() {
        tracing::warn!("weasyprint not found in PATH; PDF export unavailable");
        return None;
    }

    // Write HTML to a temp file
    let tmp_dir = std::env::temp_dir();
    let html_path = tmp_dir.join(format!("mobsf_report_{}.html", uuid_simple()));
    let pdf_path = output_path.to_path_buf();

    if let Err(e) = tokio::fs::write(&html_path, html.as_bytes()).await {
        tracing::warn!("Failed to write temp HTML for PDF: {}", e);
        return None;
    }

    // Run weasyprint <html_file> <pdf_file>
    let result = tokio::process::Command::new("weasyprint")
        .arg(&html_path)
        .arg(&pdf_path)
        .output()
        .await;

    // Clean up temp HTML
    let _ = tokio::fs::remove_file(&html_path).await;

    match result {
        Ok(out) if out.status.success() => {
            match tokio::fs::read(&pdf_path).await {
                Ok(bytes) => Some(bytes),
                Err(e) => {
                    tracing::warn!("Failed to read generated PDF: {}", e);
                    None
                }
            }
        }
        Ok(out) => {
            tracing::warn!(
                "weasyprint failed (exit {:?}): {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            );
            None
        }
        Err(e) => {
            tracing::warn!("Failed to run weasyprint: {}", e);
            None
        }
    }
}

fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    format!("{:08x}", t)
}
