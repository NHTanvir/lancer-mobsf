// Rule engine: loads YAML rules and scans Java/Kotlin source files

use anyhow::{Context, Result};
use regex::Regex;
use std::path::Path;

use crate::scanner::ScanFinding;

/// A single security rule deserialized from YAML.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Rule {
    pub id: String,
    pub message: String,
    #[serde(rename = "type")]
    pub rule_type: String, // "Regex" only for now
    pub pattern: String,
    pub severity: String,
    pub input_case: Option<String>, // "exact" (default) or "lower"
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub masvs: Option<String>,
}

/// Compiled rule: the original Rule plus its compiled Regex.
pub struct RuleEngine {
    rules: Vec<(Rule, Regex)>,
}

impl RuleEngine {
    /// Load and compile rules from YAML content.
    pub fn from_yaml(yaml_content: &str) -> Result<Self> {
        let raw_rules: Vec<Rule> =
            serde_yaml::from_str(yaml_content).context("Failed to parse rules YAML")?;

        let mut rules = Vec::with_capacity(raw_rules.len());
        for rule in raw_rules {
            // Only support Regex type for now; skip others with a warning
            if rule.rule_type != "Regex" {
                tracing::warn!(
                    id = %rule.id,
                    rule_type = %rule.rule_type,
                    "Unsupported rule type – skipping"
                );
                continue;
            }

            let re = Regex::new(&rule.pattern)
                .with_context(|| format!("Bad regex in rule '{}': {}", rule.id, rule.pattern))?;
            rules.push((rule, re));
        }

        Ok(Self { rules })
    }

    /// Scan a single file's content and return all findings.
    pub fn scan_file(&self, file_path: &str, content: &str) -> Vec<ScanFinding> {
        let mut findings: Vec<ScanFinding> = Vec::new();

        // Pre-compute the lowercased content once; reused for "lower" rules.
        let content_lower = content.to_lowercase();

        for (rule, re) in &self.rules {
            let haystack = if rule.input_case.as_deref() == Some("lower") {
                content_lower.as_str()
            } else {
                content
            };

            // Collect unique line numbers that match.
            let mut seen_lines: std::collections::HashSet<i32> =
                std::collections::HashSet::new();

            for mat in re.find_iter(haystack) {
                // Determine 1-based line number of the match start.
                let line_number = (haystack[..mat.start()].matches('\n').count() + 1) as i32;

                // Deduplicate: same rule + same file + same line = one finding.
                if seen_lines.insert(line_number) {
                    // Extract the matching line as evidence.
                    let evidence_line = content
                        .lines()
                        .nth((line_number as usize).saturating_sub(1))
                        .unwrap_or("")
                        .trim()
                        .to_string();

                    findings.push(ScanFinding {
                        rule_id: rule.id.clone(),
                        title: rule.id.clone(),
                        severity: rule.severity.clone(),
                        description: rule.message.clone(),
                        file_path: Some(file_path.to_string()),
                        line_number: Some(line_number),
                        cwe: rule.cwe.clone(),
                        owasp: rule.owasp.clone(),
                        masvs: rule.masvs.clone(),
                        evidence: Some(evidence_line),
                    });
                }
            }
        }

        findings
    }

    /// Recursively scan all files under `dir` whose extension is in `extensions`.
    pub async fn scan_directory(
        &self,
        dir: &Path,
        extensions: &[&str],
    ) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        self.walk_dir(dir, extensions, &mut findings);
        findings
    }

    /// Synchronous recursive directory walk helper.
    fn walk_dir(&self, dir: &Path, extensions: &[&str], findings: &mut Vec<ScanFinding>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!(path = %dir.display(), error = %err, "Cannot read directory");
                return;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                self.walk_dir(&path, extensions, findings);
            } else if path.is_file() {
                let matches_ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|ext| extensions.iter().any(|&want| want == ext))
                    .unwrap_or(false);

                if matches_ext {
                    match std::fs::read_to_string(&path) {
                        Ok(content) => {
                            let path_str = path.to_string_lossy().to_string();
                            let mut file_findings = self.scan_file(&path_str, &content);
                            findings.append(&mut file_findings);
                        }
                        Err(err) => {
                            tracing::warn!(
                                path = %path.display(),
                                error = %err,
                                "Cannot read file"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_YAML: &str = r#"
- id: test_log
  message: "Logging detected"
  type: Regex
  pattern: '\bLog\.(v|d|i|w|e)\s*\('
  severity: info
  input_case: exact
"#;

    #[test]
    fn test_from_yaml_compiles() {
        let engine = RuleEngine::from_yaml(SIMPLE_YAML).unwrap();
        assert_eq!(engine.rules.len(), 1);
    }

    #[test]
    fn test_scan_file_finds_match() {
        let engine = RuleEngine::from_yaml(SIMPLE_YAML).unwrap();
        let content = "Log.d(TAG, \"hello\");\nsome other line\n";
        let findings = engine.scan_file("Test.java", content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "test_log");
        assert_eq!(findings[0].line_number, Some(1));
    }

    #[test]
    fn test_deduplication() {
        let engine = RuleEngine::from_yaml(SIMPLE_YAML).unwrap();
        // Two matches on the same line → still one finding
        let content = "Log.d(TAG, \"a\"); Log.i(TAG, \"b\");\n";
        let findings = engine.scan_file("Test.java", content);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_input_case_lower() {
        const LOWER_YAML: &str = r#"
- id: test_lower
  message: "Case insensitive test"
  type: Regex
  pattern: 'password'
  severity: high
  input_case: lower
"#;
        let engine = RuleEngine::from_yaml(LOWER_YAML).unwrap();
        let content = "String PASSWORD = \"secret\";\n";
        let findings = engine.scan_file("Foo.java", content);
        assert_eq!(findings.len(), 1);
    }
}
