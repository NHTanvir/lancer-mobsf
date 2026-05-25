// report module - report generation and templates

use crate::scanner::android::AndroidScanResult;
use anyhow::Result;
use minijinja::{context, Environment};

const REPORT_TEMPLATE: &str = r#"
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>lancer-mobsf - {{ package_name }} Security Report</title>
  <style>
    body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
    h1 { color: #58a6ff; }
    .critical { background: #3d1a1a; color: #ff7b7b; padding: 4px 8px; border-radius: 3px; }
    .high { background: #3d2a1a; color: #ffa657; padding: 4px 8px; border-radius: 3px; }
    .medium { background: #3d351a; color: #e3b341; padding: 4px 8px; border-radius: 3px; }
    .low { background: #1a2a3d; color: #58a6ff; padding: 4px 8px; border-radius: 3px; }
    .info { background: #1a2a1a; color: #3fb950; padding: 4px 8px; border-radius: 3px; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th { background: #161b22; padding: 10px; text-align: left; border-bottom: 1px solid #30363d; }
    td { padding: 8px 10px; border-bottom: 1px solid #21262d; vertical-align: top; }
    .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 20px 0; }
    .summary-box { padding: 15px; border-radius: 8px; text-align: center; }
    .summary-box .count { font-size: 2em; font-weight: bold; }
    .evidence { font-family: monospace; font-size: 0.85em; color: #8b949e; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
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

/// Generate HTML report from an AndroidScanResult.
pub fn render_html_report(result: &AndroidScanResult) -> Result<String> {
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

    // Serialize findings to serde_json::Value for template rendering
    let findings_val = serde_json::to_value(&result.findings)?;

    let html = tmpl.render(context! {
        package_name => result.package_name,
        version_name => result.version_name,
        sha256 => result.sha256,
        scan_id => result.scan_id,
        counts => counts,
        findings => findings_val,
    })?;

    Ok(html)
}

/// Serialize scan result to JSON string.
pub fn render_json_report(result: &AndroidScanResult) -> Result<String> {
    let json = serde_json::to_string_pretty(result)?;
    Ok(json)
}
