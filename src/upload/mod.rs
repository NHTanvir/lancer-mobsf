// upload module - file upload handling

use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::AppState;
use crate::db::{insert_scan, Scan, ScanStatus};
use crate::scanner::android;

pub async fn upload_handler(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> impl IntoResponse {
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

        // Check extension
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

        // Read bytes
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

        // SHA256
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let sha256 = hex::encode(hasher.finalize());

        // Generate scan ID
        let scan_id = uuid::Uuid::new_v4().to_string();

        // Store file
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

        // Insert scan row
        let now = chrono::Utc::now().to_rfc3339();
        let scan = Scan {
            id: scan_id.clone(),
            filename: original_filename.clone(),
            file_type: file_type.to_string(),
            sha256: sha256.clone(),
            status: ScanStatus::Pending.as_str().to_string(),
            created_at: now.clone(),
            updated_at: now,
        };

        if let Err(e) = insert_scan(&state.db, &scan).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("failed to insert scan: {}", e)})),
            )
                .into_response();
        }

        // Trigger async scan for APK files
        if file_type == "apk" {
            android::trigger_scan(
                scan_id.clone(),
                state.db.clone(),
                state.broadcast_tx.clone(),
            )
            .await;
        }

        return (
            StatusCode::OK,
            Json(json!({
                "scan_id": scan_id,
                "filename": original_filename,
                "sha256": sha256,
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
