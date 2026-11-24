use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::auth::AuthUser;
use crate::models::*;
use crate::AppState;

const MAX_BLOB_BYTES: usize = 50 * 1024 * 1024;
const KEEP_VERSIONS: i64 = 50;

pub async fn push(
    auth: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<VaultPushRequest>,
) -> impl IntoResponse {
    if body.encrypted_blob.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "encrypted_blob is required"})),
        );
    }

    let blob_bytes = match STANDARD.decode(&body.encrypted_blob) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "encrypted_blob must be valid base64"})),
            )
        }
    };

    if blob_bytes.len() > MAX_BLOB_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({"error": "vault blob exceeds 50 MB limit"})),
        );
    }

    let device: String = {
        let d: String = body.device_name.trim().chars().take(64).collect();
        if d.is_empty() { "unknown".to_string() } else { d }
    };

    let mut outcome: Result<(String, i64), sqlx::Error> = Err(sqlx::Error::PoolClosed);
    for _ in 0..3 {
        let version_id = uuid::Uuid::new_v4().to_string();
        outcome = try_push(&state, &auth.user_id, &version_id, &blob_bytes, &device)
            .await
            .map(|v| (version_id, v));
        match &outcome {
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => continue,
            _ => break,
        }
    }

    match outcome {
        Ok((version_id, version)) => {
            tracing::info!(
                user_id = %auth.user_id,
                version,
                size = blob_bytes.len(),
                "vault pushed"
            );
            (
                StatusCode::CREATED,
                Json(serde_json::to_value(VaultPushResponse { version_id, version }).unwrap()),
            )
        }
        Err(e) => {
            tracing::error!("vault push failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to store vault"})),
            )
        }
    }
}

async fn try_push(
    state: &AppState,
    user_id: &str,
    version_id: &str,
    blob: &[u8],
    device: &str,
) -> Result<i64, sqlx::Error> {
    let mut tx = state.db.begin().await?;
    let version = sqlx::query_scalar::<_, i64>(
        "INSERT INTO vault_versions (id, user_id, encrypted_blob, version, device_name)          SELECT ?, ?, ?, COALESCE(MAX(version), 0) + 1, ? FROM vault_versions WHERE user_id = ?          RETURNING version",
    )
    .bind(version_id)
    .bind(user_id)
    .bind(blob)
    .bind(device)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        "DELETE FROM vault_versions WHERE user_id = ? AND version <=          (SELECT version FROM vault_versions WHERE user_id = ? ORDER BY version DESC LIMIT 1 OFFSET ?)",
    )
    .bind(user_id)
    .bind(user_id)
    .bind(KEEP_VERSIONS)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(version)
}

pub async fn pull(
    auth: AuthUser,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let row = sqlx::query_as::<_, (String, Vec<u8>, i64, String, String)>(
        "SELECT id, encrypted_blob, version, device_name, created_at FROM vault_versions WHERE user_id = ? ORDER BY version DESC LIMIT 1",
    )
    .bind(&auth.user_id)
    .fetch_optional(&state.db)
    .await;

    match row {
        Ok(Some((id, blob, version, device, created_at))) => (
            StatusCode::OK,
            Json(serde_json::to_value(VaultPullResponse {
                version_id: id,
                version,
                encrypted_blob: STANDARD.encode(&blob),
                device_name: device,
                created_at,
            }).unwrap()),
        ),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "no vault found, push one first"})),
        ),
        Err(e) => {
            tracing::error!("vault pull failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to retrieve vault"})),
            )
        }
    }
}

pub async fn history(
    auth: AuthUser,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let rows = sqlx::query_as::<_, (String, i64, String, i64, String)>(
        "SELECT id, version, device_name, LENGTH(encrypted_blob), created_at FROM vault_versions WHERE user_id = ? ORDER BY version DESC LIMIT 50",
    )
    .bind(&auth.user_id)
    .fetch_all(&state.db)
    .await;

    match rows {
        Ok(entries) => {
            let list: Vec<VaultHistoryEntry> = entries
                .into_iter()
                .map(|(id, version, device, size, created_at)| {
                    VaultHistoryEntry {
                        version_id: id,
                        version,
                        device_name: device,
                        blob_size: size,
                        created_at,
                    }
                })
                .collect();
            (StatusCode::OK, Json(serde_json::json!({ "versions": list })))
        }
        Err(e) => {
            tracing::error!("vault history failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to retrieve history"})),
            )
        }
    }
}

pub async fn delete_version(
    auth: AuthUser,
    State(state): State<AppState>,
    Path(version_id): Path<String>,
) -> impl IntoResponse {
    let result = sqlx::query(
        "DELETE FROM vault_versions WHERE id = ? AND user_id = ?",
    )
    .bind(&version_id)
    .bind(&auth.user_id)
    .execute(&state.db)
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            tracing::info!(user_id = %auth.user_id, version_id = %version_id, "vault version deleted");
            (
                StatusCode::OK,
                Json(serde_json::json!({"deleted": true})),
            )
        }
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "version not found or not owned by you"})),
        ),
        Err(e) => {
            tracing::error!("vault delete failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "delete failed"})),
            )
        }
    }
}
