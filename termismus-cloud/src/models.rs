use serde::{Deserialize, Serialize};

// ── Auth ──

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub device_name: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub device_name: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserInfo,
}

#[derive(Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub created_at: String,
}

// ── JWT ──

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub session_id: String,
    pub exp: usize,
}

// ── Vault ──

#[derive(Deserialize)]
pub struct VaultPushRequest {
    pub encrypted_blob: String,
    #[serde(default)]
    pub device_name: String,
}

#[derive(Serialize)]
pub struct VaultPushResponse {
    pub version_id: String,
    pub version: i64,
}

#[derive(Serialize)]
pub struct VaultPullResponse {
    pub version_id: String,
    pub version: i64,
    pub encrypted_blob: String,
    pub device_name: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct VaultHistoryEntry {
    pub version_id: String,
    pub version: i64,
    pub device_name: String,
    pub blob_size: i64,
    pub created_at: String,
}

// ── Generic API response ──

#[derive(Serialize)]
pub struct ApiError {
    pub error: String,
}

impl ApiError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self { error: msg.into() }
    }
}
