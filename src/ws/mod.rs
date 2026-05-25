// ws module - WebSocket handler

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    response::IntoResponse,
};
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::AppState;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Path(scan_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, scan_id, state))
}

async fn handle_socket(mut socket: WebSocket, scan_id: String, state: Arc<AppState>) {
    let mut rx = state.broadcast_tx.subscribe();

    // Send initial connected message
    let connected_msg = serde_json::json!({
        "type": "connected",
        "scan_id": scan_id,
        "message": "Connected to scan progress feed",
        "percent": 0
    });
    if socket
        .send(Message::Text(connected_msg.to_string()))
        .await
        .is_err()
    {
        return;
    }

    // Forward broadcast messages to this WebSocket client
    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(msg) => {
                        // Only forward messages for this scan_id
                        // Messages are JSON strings; check if they contain the scan_id
                        // For simplicity, broadcast all messages (the client can filter)
                        if socket.send(Message::Text(msg)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
            // Check if client disconnected
            msg = socket.recv() => {
                match msg {
                    Some(Ok(_)) => {} // ignore client messages
                    _ => break,      // client disconnected or error
                }
            }
        }
    }
}

/// Build a progress JSON message suitable for broadcasting.
pub fn progress_message(scan_id: &str, message: &str, percent: u8) -> String {
    serde_json::json!({
        "type": "progress",
        "scan_id": scan_id,
        "message": message,
        "percent": percent
    })
    .to_string()
}

/// Broadcast a progress update for a scan.
pub fn broadcast_progress(tx: &broadcast::Sender<String>, scan_id: &str, message: &str, percent: u8) {
    let msg = progress_message(scan_id, message, percent);
    // Ignore errors (no subscribers is fine)
    let _ = tx.send(msg);
}
