// masvs module - MASVS/OWASP mapping

use crate::scanner::ScanFinding;
use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MasvsCategory {
    pub id: String,
    pub name: String,
    pub description: String,
    pub passed: usize,
    pub failed: usize,
    pub total_checks: usize,
    pub score: f32,
    pub status: MasvsStatus,
    pub failing_checks: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum MasvsStatus {
    Pass,
    Fail,
    Partial,
    NotTested,
}

impl std::fmt::Display for MasvsStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MasvsStatus::Pass => write!(f, "Pass"),
            MasvsStatus::Fail => write!(f, "Fail"),
            MasvsStatus::Partial => write!(f, "Partial"),
            MasvsStatus::NotTested => write!(f, "NotTested"),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MasvsReport {
    pub categories: Vec<MasvsCategory>,
    pub overall_score: f32,
    pub overall_status: MasvsStatus,
}

/// Total check counts per MASVS category (based on defined rules).
fn total_checks_per_category() -> HashMap<&'static str, usize> {
    let mut m = HashMap::new();
    m.insert("storage", 30usize);
    m.insert("crypto", 15usize);
    m.insert("auth", 12usize);
    m.insert("network", 15usize);
    m.insert("platform", 20usize);
    m.insert("code", 15usize);
    m.insert("resilience", 8usize);
    m
}

/// Static category metadata: (id, name, description)
fn category_meta() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("storage",    "MASVS-STORAGE",    "Sensitive data storage and privacy"),
        ("crypto",     "MASVS-CRYPTO",     "Cryptographic practices"),
        ("auth",       "MASVS-AUTH",       "Authentication and session management"),
        ("network",    "MASVS-NETWORK",    "Network communication security"),
        ("platform",   "MASVS-PLATFORM",   "Platform interaction security"),
        ("code",       "MASVS-CODE",       "Code quality and build settings"),
        ("resilience", "MASVS-RESILIENCE", "Anti-tampering and resilience"),
    ]
}

/// Determine the MASVS category id from a masvs field string (e.g. "storage-1", "crypto-4").
fn category_from_masvs_field(masvs_field: &str) -> Option<&'static str> {
    let lower = masvs_field.to_lowercase();
    // Also handle full names like "MASVS-STORAGE-1" or "MASVS-RESILIENCE-3"
    for cat in &["storage", "crypto", "auth", "network", "platform", "code", "resilience"] {
        if lower.contains(cat) {
            return Some(cat);
        }
    }
    // Handle OWASP m7 -> code
    if lower.contains("m7") {
        return Some("code");
    }
    None
}

/// Compute MASVS v2 compliance from a list of findings.
pub fn compute_masvs_score(findings: &[ScanFinding]) -> MasvsReport {
    let totals = total_checks_per_category();
    let metas = category_meta();

    // Track failed rule_ids per category
    let mut failed_checks: HashMap<&'static str, Vec<String>> = HashMap::new();
    // Track all triggered rule_ids per category (for "tested" count)
    let mut triggered: HashMap<&'static str, std::collections::HashSet<String>> = HashMap::new();

    for finding in findings {
        let masvs_field = match &finding.masvs {
            Some(m) => m.as_str(),
            None => continue,
        };
        let cat = match category_from_masvs_field(masvs_field) {
            Some(c) => c,
            None => continue,
        };

        triggered.entry(cat).or_default().insert(finding.rule_id.clone());

        // A finding that is NOT info severity = failed check
        if finding.severity != "info" {
            failed_checks.entry(cat).or_default().push(finding.rule_id.clone());
        }
    }

    let mut categories: Vec<MasvsCategory> = Vec::new();
    let mut score_sum = 0.0f32;
    let mut scored_count = 0usize;

    for (id, name, desc) in &metas {
        let total_checks = *totals.get(id).unwrap_or(&1);
        let failed_list = failed_checks.get(id).cloned().unwrap_or_default();
        let tested = triggered.get(id).map(|s| s.len()).unwrap_or(0);

        let (score, status, passed, failed) = if tested == 0 {
            (0.0f32, MasvsStatus::NotTested, 0usize, 0usize)
        } else {
            let failed_count = failed_list.len();
            // passed = total_checks - failed_count (clamped to 0)
            let passed_count = total_checks.saturating_sub(failed_count);
            let score = passed_count as f32 / total_checks as f32;
            let status = if score >= 0.8 {
                MasvsStatus::Pass
            } else if score >= 0.5 {
                MasvsStatus::Partial
            } else {
                MasvsStatus::Fail
            };
            score_sum += score;
            scored_count += 1;
            (score, status, passed_count, failed_count)
        };

        // Deduplicate failing_checks
        let mut deduped = failed_list.clone();
        deduped.sort();
        deduped.dedup();

        categories.push(MasvsCategory {
            id: id.to_string(),
            name: name.to_string(),
            description: desc.to_string(),
            passed,
            failed,
            total_checks,
            score,
            status,
            failing_checks: deduped,
        });
    }

    let overall_score = if scored_count > 0 {
        score_sum / scored_count as f32
    } else {
        0.0
    };

    let overall_status = if scored_count == 0 {
        MasvsStatus::NotTested
    } else if overall_score >= 0.8 {
        MasvsStatus::Pass
    } else if overall_score >= 0.5 {
        MasvsStatus::Partial
    } else {
        MasvsStatus::Fail
    };

    MasvsReport {
        categories,
        overall_score,
        overall_status,
    }
}
