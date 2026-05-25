// Frida script generator — uses the Claude API to generate targeted Frida
// hook scripts based on the class/method inventory extracted from an APK.
//
// Requires ANTHROPIC_API_KEY environment variable. Returns Ok(None) if the key
// is not set so the rest of the pipeline can proceed without it.

use anyhow::Result;
use reqwest::Client;

// ---------------------------------------------------------------------------
// Public data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FridaGeneratorRequest {
    pub scan_id: String,
    /// e.g. "hook all methods returning JWT tokens", "bypass root detection"
    pub intent: String,
    /// e.g. "com.example.auth.*"
    pub class_filter: Option<String>,
    /// e.g. "*Password*" or "*crypto*"
    pub method_filter: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GeneratedFridaScript {
    pub intent: String,
    pub script_content: String,
    pub description: String,
    pub target_classes: Vec<String>,
    pub model: String,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClassInfo {
    pub class_name: String,
    pub methods: Vec<MethodInfo>,
    pub package: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MethodInfo {
    pub name: String,
    pub return_type: String,
    pub params: Vec<String>,
    pub is_static: bool,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Returns true if `text` matches a simple glob pattern (supports leading/trailing `*`).
fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.starts_with('*') && pattern.ends_with('*') {
        let inner = &pattern[1..pattern.len() - 1];
        return text.contains(inner);
    }
    if pattern.starts_with('*') {
        let suffix = &pattern[1..];
        return text.ends_with(suffix);
    }
    if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        return text.starts_with(prefix);
    }
    // Exact match (case insensitive for method names)
    text == pattern
}

/// Filter and format inventory for the prompt.
fn format_inventory(
    inventory: &[ClassInfo],
    class_filter: Option<&str>,
    method_filter: Option<&str>,
) -> String {
    let mut output = String::new();
    let mut class_count = 0usize;

    for class in inventory {
        if class_count >= 50 {
            break;
        }

        // Apply class filter
        if let Some(cf) = class_filter {
            if !glob_match(cf, &class.class_name) && !glob_match(cf, &class.package) {
                continue;
            }
        }

        // Filter methods
        let methods: Vec<&MethodInfo> = class
            .methods
            .iter()
            .filter(|m| {
                if let Some(mf) = method_filter {
                    glob_match(mf, &m.name)
                } else {
                    true
                }
            })
            .collect();

        if methods.is_empty() && method_filter.is_some() {
            continue;
        }

        output.push_str(&format!("Class: {}\n", class.class_name));
        for m in methods.iter().take(10) {
            let static_tag = if m.is_static { "static " } else { "" };
            let params = m.params.join(", ");
            output.push_str(&format!(
                "  {}{}({}) -> {}\n",
                static_tag, m.name, params, m.return_type
            ));
        }
        output.push('\n');
        class_count += 1;
    }

    if output.is_empty() {
        output.push_str("(no matching classes/methods found with the given filters)\n");
    }

    output
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a custom Frida script using Claude AI.
/// Requires ANTHROPIC_API_KEY.
/// Returns Ok(None) if key not set or on any non-fatal error.
pub async fn generate_frida_script(
    req: &FridaGeneratorRequest,
    class_method_inventory: &[ClassInfo],
) -> Result<Option<GeneratedFridaScript>> {
    // Step 1: Check for API key
    let api_key = match std::env::var("ANTHROPIC_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            tracing::debug!("ANTHROPIC_API_KEY not set; skipping Frida script generation");
            return Ok(None);
        }
    };

    // Step 2: Filter and format inventory
    let inventory_text = format_inventory(
        class_method_inventory,
        req.class_filter.as_deref(),
        req.method_filter.as_deref(),
    );

    // Step 3: Build prompt
    let prompt = format!(
        "You are an expert Frida hook script developer for Android reverse engineering.\n\n\
TASK: {intent}\n\n\
APP CLASS/METHOD INVENTORY (filtered):\n{inventory}\n\n\
Generate a Frida JavaScript hook script that accomplishes the task.\n\n\
Requirements:\n\
- Use Java.perform(function() {{ ... }}) wrapper\n\
- Add console.log() for each hook with [lancer-hook] prefix\n\
- Handle errors with try/catch for each hook\n\
- Comments explaining each hook\n\
- Include cleanup/teardown at end if needed\n\
- Script should work with Frida 16+ and Android 10+\n\n\
Respond with JSON:\n\
{{\n  \
  \"script_content\": \"// The complete Frida JS script\",\n  \
  \"description\": \"1-2 sentence description of what the script does\",\n  \
  \"target_classes\": [\"com.example.Class1\", \"com.example.Class2\"],\n  \
  \"warning\": \"Any safety/legal warnings if applicable\"\n\
}}\n\n\
Return ONLY valid JSON.",
        intent = req.intent,
        inventory = inventory_text,
    );

    // Step 4: POST to Claude API
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(90))
        .build()
        .unwrap_or_default();

    let body = serde_json::json!({
        "model": "claude-sonnet-4-6",
        "max_tokens": 4096,
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
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Frida generator request failed: {}", e);
            return Ok(None);
        }
    };

    if !resp.status().is_success() {
        tracing::warn!("Frida generator API returned status {}", resp.status());
        return Ok(None);
    }

    // Step 5: Parse response
    let json: serde_json::Value = match resp.json().await {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!("Frida generator JSON parse error: {}", e);
            return Ok(None);
        }
    };

    let text = match json["content"][0]["text"].as_str() {
        Some(t) => t.to_string(),
        None => {
            tracing::warn!("Frida generator: unexpected response shape");
            return Ok(None);
        }
    };

    // Strip optional markdown fences
    let clean = text.trim();
    let clean = if clean.starts_with("```json") {
        clean.trim_start_matches("```json").trim_end_matches("```").trim()
    } else if clean.starts_with("```") {
        clean.trim_start_matches("```").trim_end_matches("```").trim()
    } else {
        clean
    };

    #[derive(serde::Deserialize)]
    struct ApiResponse {
        script_content: String,
        description: String,
        target_classes: Vec<String>,
        warning: Option<String>,
    }

    match serde_json::from_str::<ApiResponse>(clean) {
        Ok(api_resp) => Ok(Some(GeneratedFridaScript {
            intent: req.intent.clone(),
            script_content: api_resp.script_content,
            description: api_resp.description,
            target_classes: api_resp.target_classes,
            model: "claude-sonnet-4-6".to_string(),
            warning: api_resp.warning,
        })),
        Err(e) => {
            tracing::warn!("Frida generator: failed to parse response JSON: {}", e);
            Ok(None)
        }
    }
}
