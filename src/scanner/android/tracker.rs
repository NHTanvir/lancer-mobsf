// Tracker library detection using an Exodus Privacy-style database
use crate::scanner::ScanFinding;
use std::path::PathBuf;

// ─────────────────────────────────────────────────────────────────────────────
// Data model
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrackerEntry {
    pub id: u32,
    pub name: String,
    pub website: String,
    /// Package-prefix pattern (e.g. "com.google.android.gms.analytics")
    pub code_signature: String,
    pub categories: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Embedded tracker database (top-30 from Exodus Privacy)
// ─────────────────────────────────────────────────────────────────────────────

static TRACKER_DB_JSON: &str = r#"[
  {
    "id": 1,
    "name": "Google Analytics",
    "website": "https://analytics.google.com",
    "code_signature": "com.google.android.gms.analytics",
    "categories": ["Analytics"]
  },
  {
    "id": 2,
    "name": "Facebook Ads",
    "website": "https://developers.facebook.com/docs/audience-network",
    "code_signature": "com.facebook.ads",
    "categories": ["Advertisement"]
  },
  {
    "id": 3,
    "name": "Facebook Analytics",
    "website": "https://developers.facebook.com/docs/analytics",
    "code_signature": "com.facebook.analytics",
    "categories": ["Analytics"]
  },
  {
    "id": 4,
    "name": "Amplitude",
    "website": "https://amplitude.com",
    "code_signature": "com.amplitude",
    "categories": ["Analytics"]
  },
  {
    "id": 5,
    "name": "AppsFlyer",
    "website": "https://www.appsflyer.com",
    "code_signature": "com.appsflyer",
    "categories": ["Analytics", "Identification"]
  },
  {
    "id": 6,
    "name": "MixPanel",
    "website": "https://mixpanel.com",
    "code_signature": "com.mixpanel",
    "categories": ["Analytics"]
  },
  {
    "id": 7,
    "name": "Firebase Crashlytics",
    "website": "https://firebase.google.com/products/crashlytics",
    "code_signature": "com.google.firebase.crashlytics",
    "categories": ["Crash reporting"]
  },
  {
    "id": 8,
    "name": "Firebase Analytics",
    "website": "https://firebase.google.com/products/analytics",
    "code_signature": "com.google.firebase.analytics",
    "categories": ["Analytics"]
  },
  {
    "id": 9,
    "name": "Adjust",
    "website": "https://www.adjust.com",
    "code_signature": "com.adjust.sdk",
    "categories": ["Analytics", "Identification"]
  },
  {
    "id": 10,
    "name": "Branch",
    "website": "https://branch.io",
    "code_signature": "io.branch.referral",
    "categories": ["Analytics"]
  },
  {
    "id": 11,
    "name": "Segment",
    "website": "https://segment.com",
    "code_signature": "com.segment.analytics",
    "categories": ["Analytics"]
  },
  {
    "id": 12,
    "name": "OneSignal",
    "website": "https://onesignal.com",
    "code_signature": "com.onesignal",
    "categories": ["Push notifications"]
  },
  {
    "id": 13,
    "name": "Intercom",
    "website": "https://www.intercom.com",
    "code_signature": "io.intercom.android",
    "categories": ["Customer support"]
  },
  {
    "id": 14,
    "name": "Zendesk Core",
    "website": "https://www.zendesk.com",
    "code_signature": "zendesk.core",
    "categories": ["Customer support"]
  },
  {
    "id": 15,
    "name": "Zendesk Support",
    "website": "https://www.zendesk.com",
    "code_signature": "zendesk.support",
    "categories": ["Customer support"]
  },
  {
    "id": 16,
    "name": "Sentry",
    "website": "https://sentry.io",
    "code_signature": "io.sentry",
    "categories": ["Crash reporting"]
  },
  {
    "id": 17,
    "name": "Datadog",
    "website": "https://www.datadoghq.com",
    "code_signature": "com.datadog",
    "categories": ["Analytics", "Crash reporting"]
  },
  {
    "id": 18,
    "name": "New Relic",
    "website": "https://newrelic.com",
    "code_signature": "com.newrelic",
    "categories": ["Analytics"]
  },
  {
    "id": 19,
    "name": "AppDynamics",
    "website": "https://www.appdynamics.com",
    "code_signature": "com.appdynamics",
    "categories": ["Analytics"]
  },
  {
    "id": 20,
    "name": "Braze (Appboy)",
    "website": "https://www.braze.com",
    "code_signature": "com.appboy",
    "categories": ["Analytics", "Marketing"]
  },
  {
    "id": 21,
    "name": "Braze",
    "website": "https://www.braze.com",
    "code_signature": "com.braze",
    "categories": ["Analytics", "Marketing"]
  },
  {
    "id": 22,
    "name": "Leanplum",
    "website": "https://www.leanplum.com",
    "code_signature": "com.leanplum",
    "categories": ["Analytics", "Marketing"]
  },
  {
    "id": 23,
    "name": "Urban Airship",
    "website": "https://www.airship.com",
    "code_signature": "com.urbanairship",
    "categories": ["Push notifications", "Marketing"]
  },
  {
    "id": 24,
    "name": "Google Ads (AdMob)",
    "website": "https://developers.google.com/admob",
    "code_signature": "com.google.android.gms.ads",
    "categories": ["Advertisement"]
  },
  {
    "id": 25,
    "name": "InMobi",
    "website": "https://www.inmobi.com",
    "code_signature": "com.inmobi",
    "categories": ["Advertisement"]
  },
  {
    "id": 26,
    "name": "MoPub",
    "website": "https://www.mopub.com",
    "code_signature": "com.mopub",
    "categories": ["Advertisement"]
  },
  {
    "id": 27,
    "name": "Chartboost",
    "website": "https://www.chartboost.com",
    "code_signature": "com.chartboost",
    "categories": ["Advertisement"]
  },
  {
    "id": 28,
    "name": "Twitter SDK",
    "website": "https://developer.twitter.com",
    "code_signature": "com.twitter.sdk",
    "categories": ["Social"]
  },
  {
    "id": 29,
    "name": "Pinterest SDK",
    "website": "https://developers.pinterest.com",
    "code_signature": "com.pinterest",
    "categories": ["Social"]
  },
  {
    "id": 30,
    "name": "Snapchat SDK",
    "website": "https://kit.snapchat.com",
    "code_signature": "com.snap",
    "categories": ["Social"]
  },
  {
    "id": 31,
    "name": "TikTok / ByteDance",
    "website": "https://www.bytedance.com",
    "code_signature": "com.bytedance",
    "categories": ["Analytics", "Advertisement"]
  },
  {
    "id": 32,
    "name": "TikTok (SS Android)",
    "website": "https://www.bytedance.com",
    "code_signature": "com.ss.android",
    "categories": ["Analytics"]
  },
  {
    "id": 33,
    "name": "Huawei Analytics",
    "website": "https://developer.huawei.com/consumer/en/hms/huawei-analyticskit",
    "code_signature": "com.huawei.hms.analytics",
    "categories": ["Analytics"]
  }
]"#;

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Load the embedded tracker database.
pub fn load_tracker_db() -> Vec<TrackerEntry> {
    serde_json::from_str(TRACKER_DB_JSON).unwrap_or_else(|e| {
        tracing::warn!("Failed to parse embedded tracker DB: {}", e);
        Vec::new()
    })
}

/// Detect tracking libraries by scanning Java file paths for package-name prefixes.
///
/// The decompiled sources directory has files like:
///   `sources/com/google/android/gms/analytics/GoogleAnalytics.java`
/// so the file path itself reveals the package.
pub fn detect_trackers(
    java_files: &[PathBuf],
    tracker_db: &[TrackerEntry],
) -> Vec<ScanFinding> {
    let mut findings: Vec<ScanFinding> = Vec::new();
    // Track which trackers have already been reported (avoid duplicate findings)
    let mut reported: std::collections::HashSet<u32> = std::collections::HashSet::new();

    for file in java_files {
        // Normalise path separators so we can do simple substring matching
        let path_str = file.to_string_lossy().replace('\\', "/");

        for tracker in tracker_db {
            if reported.contains(&tracker.id) {
                continue;
            }
            // Convert package prefix to path fragment (dots → slashes)
            let path_fragment = tracker.code_signature.replace('.', "/");
            if path_str.contains(&path_fragment) {
                reported.insert(tracker.id);
                findings.push(ScanFinding {
                    rule_id: format!("tracker_{}", tracker.id),
                    title: format!("Tracker library detected: {}", tracker.name),
                    severity: "info".to_string(),
                    description: format!(
                        "The app contains the '{}' tracker ({} – {}). \
                        Categories: {}. \
                        Review the privacy policy to ensure adequate disclosure.",
                        tracker.name,
                        tracker.code_signature,
                        tracker.website,
                        tracker.categories.join(", ")
                    ),
                    file_path: Some(file.to_string_lossy().to_string()),
                    line_number: None,
                    cwe: Some("CWE-359".to_string()),
                    owasp: Some("m6".to_string()),
                    masvs: Some("privacy-4".to_string()),
                    evidence: Some(tracker.code_signature.clone()),
                });
            }
        }
    }

    findings
}

/// Convenience: collect all Java/Kotlin files under a directory tree.
pub fn collect_java_files(root: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_recursive(root, &mut out);
    out
}

fn collect_recursive(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_recursive(&p, out);
        } else if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
            if ext == "java" || ext == "kt" {
                out.push(p);
            }
        }
    }
}
