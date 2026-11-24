use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

use crate::models::{CloudPullResult, VaultVersion};
use crate::vault::{decrypt_bytes, vault_dir, vault_path};

#[derive(Serialize)]
struct AuthReq {
    email: String,
    password: String,
    device_name: String,
}

#[derive(Deserialize)]
struct UserInfo {
    #[serde(default)]
    #[allow(dead_code)]
    id: String,
    email: String,
    #[serde(default)]
    #[allow(dead_code)]
    created_at: String,
}

#[derive(Deserialize)]
struct AuthResp {
    token: String,
    user: UserInfo,
}

#[derive(Serialize)]
struct PushReq {
    encrypted_blob: String,
    device_name: String,
}

#[derive(Deserialize)]
struct PushResp {
    #[serde(default)]
    #[allow(dead_code)]
    version_id: String,
    version: i64,
}

#[derive(Deserialize)]
struct PullResp {
    #[serde(default)]
    #[allow(dead_code)]
    version_id: String,
    version: i64,
    encrypted_blob: String,
    #[serde(default)]
    device_name: String,
    #[serde(default)]
    created_at: String,
}

#[derive(Deserialize)]
struct HistoryResp {
    versions: Vec<VaultVersion>,
}

#[derive(Deserialize)]
struct ErrorResp {
    error: String,
}

pub struct CloudState {
    pub server_url: String,
    pub token: String,
    pub email: String,
}

pub type CloudStateRef = Arc<Mutex<Option<CloudState>>>;

pub fn new_state() -> CloudStateRef {
    Arc::new(Mutex::new(None))
}

fn cloud_config_path() -> PathBuf {
    vault_dir().join("cloud.json")
}

fn save_cloud_config(url: &str, token: &str, email: &str) {
    let data = serde_json::json!({
        "server_url": url,
        "token": token,
        "email": email,
    });
    let _ = fs::write(cloud_config_path(), serde_json::to_string_pretty(&data).unwrap_or_default());
}

fn load_cloud_config() -> Option<(String, String, String)> {
    let data = fs::read_to_string(cloud_config_path()).ok()?;
    let v: serde_json::Value = serde_json::from_str(&data).ok()?;
    Some((
        v["server_url"].as_str()?.to_string(),
        v["token"].as_str()?.to_string(),
        v["email"].as_str()?.to_string(),
    ))
}

fn http() -> Result<Client, String> {
    Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| format!("http client error: {e}"))
}

fn normalize_server_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().trim_end_matches('/');
    let url = reqwest::Url::parse(trimmed).map_err(|_| "invalid server URL".to_string())?;
    match url.scheme() {
        "https" => {}
        "http" => {
            let host = url.host_str().unwrap_or("");
            if !matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]") {
                return Err("refusing insecure http:// URL for a non-local server - use https:// (your vault blob and login token would travel unencrypted)".into());
            }
        }
        _ => return Err("unsupported URL scheme".into()),
    }
    Ok(trimmed.to_string())
}

fn device_label() -> String {
    std::env::var("COMPUTERNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "TERMISMUS".into())
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn api_error(resp: reqwest::Response, fallback: &str) -> String {
    let status = resp.status();
    match resp.json::<ErrorResp>().await {
        Ok(e) if !e.error.is_empty() => e.error,
        _ => format!("{fallback} (HTTP {status})"),
    }
}

/// Like api_error, but a 401 clears the saved session.
async fn authed_error(state: &crate::AppState, resp: reqwest::Response, fallback: &str) -> String {
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        {
            let mut cloud = state.cloud.lock().await;
            *cloud = None;
        }
        let _ = fs::remove_file(cloud_config_path());
        return "cloud session expired - please log in again".into();
    }
    api_error(resp, fallback).await
}

async fn current_session(state: &crate::AppState) -> Result<(String, String), String> {
    let cloud = state.cloud.lock().await;
    let c = cloud.as_ref().ok_or("not logged in to cloud")?;
    Ok((c.server_url.clone(), c.token.clone()))
}

async fn do_auth(
    state: &crate::AppState,
    endpoint: &str,
    server_url: String,
    email: String,
    password: String,
    fallback: &str,
) -> Result<String, String> {
    let base = normalize_server_url(&server_url)?;
    let resp = http()?
        .post(format!("{base}/api/auth/{endpoint}"))
        .json(&AuthReq {
            email,
            password,
            device_name: device_label(),
        })
        .send()
        .await
        .map_err(|e| format!("connection failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(api_error(resp, fallback).await);
    }
    let auth: AuthResp = resp.json().await.map_err(|e| e.to_string())?;
    let email = auth.user.email;
    save_cloud_config(&base, &auth.token, &email);
    let mut cloud = state.cloud.lock().await;
    *cloud = Some(CloudState {
        server_url: base,
        token: auth.token,
        email: email.clone(),
    });
    Ok(email)
}

#[tauri::command]
pub async fn cloud_register(
    state: tauri::State<'_, crate::AppState>,
    server_url: String,
    email: String,
    password: String,
) -> Result<String, String> {
    do_auth(&state, "register", server_url, email, password, "registration failed").await
}

#[tauri::command]
pub async fn cloud_login(
    state: tauri::State<'_, crate::AppState>,
    server_url: String,
    email: String,
    password: String,
) -> Result<String, String> {
    do_auth(&state, "login", server_url, email, password, "login failed").await
}

#[tauri::command]
pub async fn cloud_restore_session(
    state: tauri::State<'_, crate::AppState>,
) -> Result<Option<String>, String> {
    if let Some((url, token, email)) = load_cloud_config() {
        let url = match normalize_server_url(&url) {
            Ok(u) => u,
            Err(_) => return Ok(None),
        };
        let mut cloud = state.cloud.lock().await;
        *cloud = Some(CloudState {
            server_url: url,
            token,
            email: email.clone(),
        });
        Ok(Some(email))
    } else {
        Ok(None)
    }
}

#[tauri::command]
pub async fn cloud_logout(state: tauri::State<'_, crate::AppState>) -> Result<(), String> {
    let session = {
        let cloud = state.cloud.lock().await;
        cloud.as_ref().map(|c| (c.server_url.clone(), c.token.clone()))
    };
    if let Some((url, token)) = session {
        if let Ok(client) = Client::builder().timeout(Duration::from_secs(5)).build() {
            let _ = client
                .post(format!("{}/api/auth/logout", url.trim_end_matches('/')))
                .bearer_auth(&token)
                .send()
                .await;
        }
    }
    {
        let mut cloud = state.cloud.lock().await;
        *cloud = None;
    }
    let _ = fs::remove_file(cloud_config_path());
    Ok(())
}

#[tauri::command]
pub async fn cloud_status(
    state: tauri::State<'_, crate::AppState>,
) -> Result<Option<String>, String> {
    let cloud = state.cloud.lock().await;
    Ok(cloud.as_ref().map(|c| c.email.clone()))
}

#[tauri::command]
pub async fn cloud_push(
    state: tauri::State<'_, crate::AppState>,
    device_name: String,
) -> Result<String, String> {
    let (server_url, token) = current_session(&state).await?;
    let vault_data = fs::read(vault_path()).map_err(|e| format!("cannot read vault: {e}"))?;
    let b64 = STANDARD.encode(&vault_data);

    let resp = http()?
        .post(format!("{}/api/vault/push", server_url.trim_end_matches('/')))
        .bearer_auth(&token)
        .json(&PushReq {
            encrypted_blob: b64,
            device_name,
        })
        .send()
        .await
        .map_err(|e| format!("push failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(authed_error(&state, resp, "push failed").await);
    }
    let r: PushResp = resp.json().await.map_err(|e| e.to_string())?;
    Ok(format!("vault pushed to cloud (v{})", r.version))
}

fn prune_backups(keep: usize) {
    let mut names: Vec<String> = match fs::read_dir(vault_dir()) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with("vault.bin.bak-"))
            .collect(),
        Err(_) => return,
    };
    names.sort();
    if names.len() > keep {
        for n in &names[..names.len() - keep] {
            let _ = fs::remove_file(vault_dir().join(n));
        }
    }
}

#[tauri::command]
pub async fn cloud_pull(
    state: tauri::State<'_, crate::AppState>,
    master: String,
) -> Result<CloudPullResult, String> {
    let (server_url, token) = current_session(&state).await?;

    let resp = http()?
        .get(format!("{}/api/vault/pull", server_url.trim_end_matches('/')))
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| format!("pull failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(authed_error(&state, resp, "pull failed").await);
    }

    let pull: PullResp = resp.json().await.map_err(|e| e.to_string())?;
    let vault_data = STANDARD
        .decode(&pull.encrypted_blob)
        .map_err(|e| format!("decode error: {e}"))?;

    let hosts = decrypt_bytes(&master, &vault_data).map_err(|_| {
        "cloud vault cannot be decrypted with your current master password - local vault was NOT changed"
            .to_string()
    })?;

    let mut backup_path = None;
    if vault_path().exists() {
        let backup = vault_dir().join(format!("vault.bin.bak-{}", unix_secs()));
        fs::copy(vault_path(), &backup)
            .map_err(|e| format!("cannot back up local vault, aborting: {e}"))?;
        backup_path = Some(backup.to_string_lossy().to_string());
    }
    prune_backups(5);

    let tmp = vault_path().with_extension("cloud-tmp");
    fs::write(&tmp, &vault_data).map_err(|e| e.to_string())?;
    fs::rename(&tmp, vault_path()).map_err(|e| e.to_string())?;

    Ok(CloudPullResult {
        message: format!(
            "vault pulled (v{} from {} at {})",
            pull.version, pull.device_name, pull.created_at
        ),
        hosts,
        backup_path,
    })
}

#[tauri::command]
pub async fn cloud_history(
    state: tauri::State<'_, crate::AppState>,
) -> Result<Vec<VaultVersion>, String> {
    let (server_url, token) = current_session(&state).await?;

    let resp = http()?
        .get(format!("{}/api/vault/history", server_url.trim_end_matches('/')))
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| format!("history failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(authed_error(&state, resp, "history failed").await);
    }

    let history: HistoryResp = resp.json().await.map_err(|e| e.to_string())?;
    Ok(history.versions)
}
