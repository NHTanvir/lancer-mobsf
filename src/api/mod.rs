// api module - REST API routes

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::json;
use std::sync::Arc;

use crate::AppState;
use crate::db::{get_findings, get_scan, list_scans};

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
