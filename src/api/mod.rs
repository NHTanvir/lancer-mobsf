// api module - REST API routes

use axum::{
    extract::{Path, State},
    http::StatusCode,
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
