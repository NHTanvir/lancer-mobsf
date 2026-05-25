// api module - REST API routes

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::AppState;
use crate::db::{delete_scan, get_findings, get_scan, get_scan_by_hash, list_scans};

// ─────────────────────────────────────────────────────────────────────────────
// Dynamic analysis endpoints
// ─────────────────────────────────────────────────────────────────────────────

/// GET /api/devices — list connected ADB devices
pub async fn list_devices_handler() -> impl IntoResponse {
    match crate::dynamic::adb::AdbClient::list_devices().await {
        Ok(devices) => (StatusCode::OK, Json(json!({"devices": devices}))).into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": format!("adb error: {}", e)})),
        )
            .into_response(),
    }
}

/// POST /api/dynamic/start — start a dynamic analysis session
pub async fn start_dynamic_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<crate::dynamic::DynamicScanRequest>,
) -> impl IntoResponse {
    match crate::dynamic::start_dynamic_session(req, &state.db, &state.broadcast_tx).await {
        Ok(session) => (StatusCode::OK, Json(json!(session))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

/// GET /api/dynamic/:scan_id/screenshot — serve the latest screenshot PNG
pub async fn get_screenshot_handler(
    Path(scan_id): Path<String>,
) -> impl IntoResponse {
    let path = format!("uploads/{}/screenshot.png", scan_id);
    match tokio::fs::read(&path).await {
        Ok(bytes) => axum::response::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "image/png")
            .body(axum::body::Body::from(bytes))
            .unwrap()
            .into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "screenshot not found", "scan_id": scan_id})),
        )
            .into_response(),
    }
}

/// GET /api/scan/:id - return scan status as JSON
pub async fn get_scan_handler(
    Path(scan_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    match get_scan(&state.db, &scan_id).await {
        Ok(Some(scan)) => (StatusCode::OK, Json(json!(scan))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "scan not found", "scan_id": scan_id})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("database error: {}", e)})),
        )
            .into_response(),
    }
}

/// GET /api/scans - return list of recent scans
pub async fn list_scans_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match list_scans(&state.db, 50).await {
        Ok(scans) => (StatusCode::OK, Json(json!(scans))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("database error: {}", e)})),
        )
            .into_response(),
    }
}

/// GET /api/scan/:id/findings - return findings for a scan
pub async fn get_findings_handler(
    Path(scan_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // First verify the scan exists
    match get_scan(&state.db, &scan_id).await {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "scan not found", "scan_id": scan_id})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
                .into_response()
        }
        Ok(Some(_)) => {}
    }

    match get_findings(&state.db, &scan_id).await {
        Ok(findings) => (StatusCode::OK, Json(json!(findings))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("database error: {}", e)})),
        )
            .into_response(),
    }
}

/// Load the AndroidScanResult from uploads/<scan_id>/result.json
async fn load_result(scan_id: &str) -> Result<crate::scanner::android::AndroidScanResult, String> {
    let result_path = format!("uploads/{}/result.json", scan_id);
    let data = tokio::fs::read_to_string(&result_path)
        .await
        .map_err(|e| format!("result.json not found for scan {}: {}", scan_id, e))?;
    serde_json::from_str(&data)
        .map_err(|e| format!("Failed to parse result.json: {}", e))
}

/// GET /api/scan/:id/report - returns HTML report (with MASVS section)
pub async fn get_report_html_handler(
    Path(scan_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Verify scan exists in DB first
    match get_scan(&state.db, &scan_id).await {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "scan not found", "scan_id": scan_id})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
                .into_response()
        }
        Ok(Some(_)) => {}
    }

    let result = match load_result(&scan_id).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": e})),
            )
                .into_response()
        }
    };

    // Use MASVS from result if available, otherwise compute fresh
    let masvs = result.masvs_report.clone().unwrap_or_else(|| {
        crate::masvs::compute_masvs_score(&result.findings)
    });

    match crate::report::render_html_report_with_masvs(&result, &masvs) {
        Ok(html) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to render HTML report: {}", e)})),
        )
            .into_response(),
    }
}

/// GET /api/scan/:id/report.json - returns JSON report
pub async fn get_report_json_handler(
    Path(scan_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Verify scan exists in DB first
    match get_scan(&state.db, &scan_id).await {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "scan not found", "scan_id": scan_id})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
                .into_response()
        }
        Ok(Some(_)) => {}
    }

    let result = match load_result(&scan_id).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": e})),
            )
                .into_response()
        }
    };

    match crate::report::render_json_report(&result) {
        Ok(json_str) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            json_str,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to render JSON report: {}", e)})),
        )
            .into_response(),
    }
}

/// GET /api/scan/:id/report.pdf - returns PDF report (requires weasyprint in PATH)
pub async fn get_report_pdf_handler(
    Path(scan_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Verify scan exists in DB first
    match get_scan(&state.db, &scan_id).await {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "scan not found", "scan_id": scan_id})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
                .into_response()
        }
        Ok(Some(_)) => {}
    }

    let result = match load_result(&scan_id).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": e})),
            )
                .into_response()
        }
    };

    let masvs = result.masvs_report.clone().unwrap_or_else(|| {
        crate::masvs::compute_masvs_score(&result.findings)
    });

    let html = match crate::report::render_html_report_with_masvs(&result, &masvs) {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to render HTML for PDF: {}", e)})),
            )
                .into_response()
        }
    };

    let pdf_path = std::env::temp_dir().join(format!("mobsf_{}.pdf", scan_id));
    match crate::report::render_pdf_report(&html, &pdf_path).await {
        Some(pdf_bytes) => {
            let _ = tokio::fs::remove_file(&pdf_path).await;
            let content_disposition = format!("attachment; filename=\"report_{}.pdf\"", scan_id);
            let response = axum::response::Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/pdf")
                .header(header::CONTENT_DISPOSITION, content_disposition)
                .body(axum::body::Body::from(pdf_bytes))
                .unwrap();
            response.into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "PDF export requires weasyprint to be installed and available in PATH"
            })),
        )
            .into_response(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MobSF-compatible REST API v1
// ─────────────────────────────────────────────────────────────────────────────

/// Check the `Authorization: Token <key>` header against MOBSF_API_KEY env var.
/// If the env var is not set, auth is skipped (dev mode).
fn check_auth(headers: &HeaderMap) -> bool {
    match std::env::var("MOBSF_API_KEY") {
        Err(_) => true, // dev mode: no key configured
        Ok(expected_key) => {
            if let Some(val) = headers.get(header::AUTHORIZATION) {
                if let Ok(s) = val.to_str() {
                    let stripped = s.trim_start_matches("Token").trim();
                    return stripped == expected_key;
                }
            }
            false
        }
    }
}

#[derive(Deserialize)]
pub struct HashQuery {
    pub hash: String,
}

/// POST /api/v1/upload — MobSF-compatible upload (delegates to the existing upload handler)
/// Returns: {"analyzer":"StaticAnalyzer","status":"success","hash":"sha256","scan_type":"apk","file_name":"app.apk"}
pub async fn v1_upload_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    multipart: axum::extract::Multipart,
) -> impl IntoResponse {
    if !check_auth(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Unauthorized. Provide Authorization: Token <key>"})),
        )
            .into_response();
    }

    // Re-use the core upload logic inline (we can't call the existing handler
    // because it returns the wrong response shape; replicate the essential parts).
    use sha2::{Digest, Sha256};
    let mut multipart = multipart;

    while let Ok(Some(field)) = multipart.next_field().await {
        let field_name = field.name().unwrap_or("").to_string();
        if field_name != "file" {
            continue;
        }

        let original_filename = match field.file_name() {
            Some(name) => name.to_string(),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "missing filename"})),
                )
                    .into_response()
            }
        };

        let ext = std::path::Path::new(&original_filename)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let file_type = match ext.as_str() {
            "apk" => "apk",
            "ipa" => "ipa",
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "only .apk and .ipa files are accepted"})),
                )
                    .into_response()
            }
        };

        let data = match field.bytes().await {
            Ok(b) => b,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("failed to read file: {}", e)})),
                )
                    .into_response()
            }
        };

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let sha256 = hex::encode(hasher.finalize());

        let scan_id = uuid::Uuid::new_v4().to_string();
        let upload_dir = format!("uploads/{}", scan_id);
        if let Err(e) = tokio::fs::create_dir_all(&upload_dir).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("failed to create upload dir: {}", e)})),
            )
                .into_response();
        }

        let safe_name = std::path::Path::new(&original_filename)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("upload");
        let file_path = format!("{}/{}", upload_dir, safe_name);
        if let Err(e) = tokio::fs::write(&file_path, &data).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("failed to write file: {}", e)})),
            )
                .into_response();
        }

        let now = chrono::Utc::now().to_rfc3339();
        let scan = crate::db::Scan {
            id: scan_id.clone(),
            filename: original_filename.clone(),
            file_type: file_type.to_string(),
            sha256: sha256.clone(),
            status: crate::db::ScanStatus::Pending.as_str().to_string(),
            created_at: now.clone(),
            updated_at: now,
        };

        if let Err(e) = crate::db::insert_scan(&state.db, &scan).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("failed to insert scan: {}", e)})),
            )
                .into_response();
        }

        return (
            StatusCode::OK,
            Json(json!({
                "analyzer": "StaticAnalyzer",
                "status": "success",
                "hash": sha256,
                "scan_type": file_type,
                "file_name": original_filename,
            })),
        )
            .into_response();
    }

    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": "no file field found in multipart form"})),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct V1ScanBody {
    pub hash: String,
}

/// POST /api/v1/scan — trigger a scan by SHA-256 hash (MobSF compatible)
pub async fn v1_scan_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<V1ScanBody>,
) -> impl IntoResponse {
    if !check_auth(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Unauthorized"})),
        )
            .into_response();
    }

    let scan = match get_scan_by_hash(&state.db, &body.hash).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "scan not found for hash", "hash": body.hash})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
                .into_response()
        }
    };

    // Trigger scan based on file type
    if scan.file_type == "apk" {
        crate::scanner::android::trigger_scan(
            scan.id.clone(),
            state.db.clone(),
            state.broadcast_tx.clone(),
        )
        .await;
    } else if scan.file_type == "ipa" {
        crate::scanner::ios::trigger_scan(
            scan.id.clone(),
            state.db.clone(),
            state.broadcast_tx.clone(),
        )
        .await;
    }

    (
        StatusCode::OK,
        Json(json!({
            "scan_id": scan.id,
            "hash": body.hash,
            "status": "scan triggered",
        })),
    )
        .into_response()
}

/// GET /api/v1/report_json?hash=<sha256> — JSON report (MobSF compatible)
pub async fn v1_report_json_handler(
    Query(params): Query<HashQuery>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !check_auth(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "Unauthorized"}))).into_response();
    }

    let scan = match get_scan_by_hash(&state.db, &params.hash).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "scan not found", "hash": params.hash})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
                .into_response()
        }
    };

    let result = match load_result(&scan.id).await {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response()
        }
    };

    // Inject the hash field into the JSON
    let mut val = match serde_json::to_value(&result) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("serialization error: {}", e)})),
            )
                .into_response()
        }
    };
    if let serde_json::Value::Object(ref mut map) = val {
        map.insert("hash".to_string(), json!(params.hash));
    }

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        val.to_string(),
    )
        .into_response()
}

/// GET /api/v1/scorecard?hash=<sha256> — MASVS scorecard (MobSF compatible)
pub async fn v1_scorecard_handler(
    Query(params): Query<HashQuery>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !check_auth(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "Unauthorized"}))).into_response();
    }

    let scan = match get_scan_by_hash(&state.db, &params.hash).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "scan not found", "hash": params.hash})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
                .into_response()
        }
    };

    let result = match load_result(&scan.id).await {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response()
        }
    };

    let masvs = result
        .masvs_report
        .clone()
        .unwrap_or_else(|| crate::masvs::compute_masvs_score(&result.findings));

    let score_pct = (masvs.overall_score * 100.0).round() as u8;
    let risk_score = result.risk_score;

    (
        StatusCode::OK,
        Json(json!({
            "hash": params.hash,
            "scan_id": scan.id,
            "masvs": masvs,
            "overall_score_pct": score_pct,
            "risk_score": risk_score,
        })),
    )
        .into_response()
}

/// GET /api/v1/scans — list recent scans (MobSF compatible)
pub async fn v1_list_scans_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !check_auth(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "Unauthorized"}))).into_response();
    }

    match list_scans(&state.db, 50).await {
        Ok(scans) => (StatusCode::OK, Json(json!({"count": scans.len(), "content": scans}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("database error: {}", e)})),
        )
            .into_response(),
    }
}

/// DELETE /api/v1/delete_scan?hash=<sha256> — delete a scan (MobSF compatible)
pub async fn v1_delete_scan_handler(
    Query(params): Query<HashQuery>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !check_auth(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "Unauthorized"}))).into_response();
    }

    let scan = match get_scan_by_hash(&state.db, &params.hash).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "scan not found", "hash": params.hash})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
                .into_response()
        }
    };

    // Delete files
    let upload_dir = format!("uploads/{}", scan.id);
    let _ = tokio::fs::remove_dir_all(&upload_dir).await;

    match delete_scan(&state.db, &scan.id).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({"status": "deleted", "hash": params.hash})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("failed to delete scan: {}", e)})),
        )
            .into_response(),
    }
}

/// GET /api/v1/download_pdf?hash=<sha256> — download PDF (MobSF compatible)
pub async fn v1_download_pdf_handler(
    Query(params): Query<HashQuery>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !check_auth(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "Unauthorized"}))).into_response();
    }

    let scan = match get_scan_by_hash(&state.db, &params.hash).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "scan not found", "hash": params.hash})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("database error: {}", e)})),
            )
                .into_response()
        }
    };

    let result = match load_result(&scan.id).await {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response()
        }
    };

    let masvs = result
        .masvs_report
        .clone()
        .unwrap_or_else(|| crate::masvs::compute_masvs_score(&result.findings));

    let html = match crate::report::render_html_report_with_masvs(&result, &masvs) {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to render HTML for PDF: {}", e)})),
            )
                .into_response()
        }
    };

    let pdf_path = std::env::temp_dir().join(format!("mobsf_{}.pdf", scan.id));
    match crate::report::render_pdf_report(&html, &pdf_path).await {
        Some(pdf_bytes) => {
            let _ = tokio::fs::remove_file(&pdf_path).await;
            let content_disposition = format!(
                "attachment; filename=\"report_{}.pdf\"",
                scan.id
            );
            axum::response::Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/pdf")
                .header(header::CONTENT_DISPOSITION, content_disposition)
                .body(axum::body::Body::from(pdf_bytes))
                .unwrap()
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "PDF export requires weasyprint to be installed and available in PATH"
            })),
        )
            .into_response(),
    }
}
