use std::net::SocketAddr;
use std::time::Duration;

use argon2::PasswordVerifier;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, request::Parts, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{async_trait, extract::FromRequestParts, Json};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use password_hash::{PasswordHash, PasswordHasher, SaltString};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::models::*;
use crate::AppState;

const MAX_PASSWORD_BYTES: usize = 1024;
const MIN_PASSWORD_BYTES: usize = 8;
const MAX_EMAIL_LEN: usize = 254;
const MAX_DEVICE_LEN: usize = 64;
const LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);
const REGISTER_WINDOW: Duration = Duration::from_secs(60 * 60);
const TS_FMT: &str = "%Y-%m-%dT%H:%M:%SZ";

fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(ApiError::new(msg))).into_response()
}

fn too_many() -> Response {
    let mut resp = err(StatusCode::TOO_MANY_REQUESTS, "too many attempts, try again later");
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("900"));
    resp
}

fn hash_password(password: &str) -> Result<String, ()> {
    let salt = SaltString::generate(&mut OsRng);
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| ())
}

fn verify_password(password: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    argon2::Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

fn create_token(secret: &[u8], user_id: &str, session_id: &str) -> Result<String, ()> {
    let exp = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::days(30))
        .ok_or(())?
        .timestamp() as usize;
    let claims = Claims {
        sub: user_id.to_string(),
        session_id: session_id.to_string(),
        exp,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|_| ())
}

fn hash_token_for_storage(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn client_ip(addr: &SocketAddr, headers: &HeaderMap, trust_proxy: bool) -> String {
    if trust_proxy {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse::<std::net::IpAddr>().ok())
        {
            return ip.to_string();
        }
    }
    addr.ip().to_string()
}

fn clean_device(raw: &str, default: &str) -> String {
    let d: String = raw.trim().chars().take(MAX_DEVICE_LEN).collect();
    if d.is_empty() {
        default.to_string()
    } else {
        d
    }
}

/// Create a session row and a signed token for it. Err => caller returns 500.
async fn create_session(state: &AppState, user_id: &str, device: &str) -> Result<String, ()> {
    let session_id = uuid::Uuid::new_v4().to_string();
    let token = create_token(&state.jwt_secret, user_id, &session_id)?;
    let token_hash = hash_token_for_storage(&token);
    let expires = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::days(30))
        .ok_or(())?
        .format(TS_FMT)
        .to_string();

    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, device_name, expires_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&session_id)
    .bind(user_id)
    .bind(&token_hash)
    .bind(device)
    .bind(&expires)
    .execute(&state.db)
    .await
    .map_err(|e| tracing::error!("session insert failed: {e}"))?;

    Ok(token)
}

// ── Auth middleware extractor ──

pub struct AuthUser {
    pub user_id: String,
    pub session_id: String,
}

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = (StatusCode, Json<ApiError>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or((
                StatusCode::UNAUTHORIZED,
                Json(ApiError::new("missing or invalid authorization header")),
            ))?;

        let token_data = decode::<Claims>(
            auth_header,
            &DecodingKey::from_secret(&state.jwt_secret),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiError::new("invalid or expired token")),
            )
        })?;

        let token_hash = hash_token_for_storage(auth_header);
        let session_exists = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sessions WHERE id = ? AND token_hash = ? AND expires_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
        )
        .bind(&token_data.claims.session_id)
        .bind(&token_hash)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

        if session_exists == 0 {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ApiError::new("session expired or revoked")),
            ));
        }

        Ok(AuthUser {
            user_id: token_data.claims.sub,
            session_id: token_data.claims.session_id,
        })
    }
}

// ── Handlers ──

pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RegisterRequest>,
) -> Response {
    if !state.allow_registration {
        return err(StatusCode::FORBIDDEN, "registration is disabled on this server");
    }

    let email = body.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') || email.len() > MAX_EMAIL_LEN {
        return err(StatusCode::BAD_REQUEST, "invalid email");
    }
    if body.password.len() < MIN_PASSWORD_BYTES {
        return err(StatusCode::BAD_REQUEST, "password must be at least 8 characters");
    }
    if body.password.len() > MAX_PASSWORD_BYTES {
        return err(StatusCode::BAD_REQUEST, "password too long");
    }

    let ip_key = format!("register-ip:{}", client_ip(&addr, &headers, state.trust_proxy));
    if !state.limiter.check(&ip_key, 5, REGISTER_WINDOW) {
        return too_many();
    }
    state.limiter.hit(&ip_key, REGISTER_WINDOW);

    // NOTE: returning 409 for an existing email allows account enumeration;
    // this is mitigated by the per-IP register rate limit above.
    let existing = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE email = ?")
        .bind(&email)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    if existing > 0 {
        return err(StatusCode::CONFLICT, "email already registered");
    }

    let password = body.password.clone();
    let pw_hash = match tokio::task::spawn_blocking(move || hash_password(&password)).await {
        Ok(Ok(h)) => h,
        _ => return err(StatusCode::INTERNAL_SERVER_ERROR, "failed to hash password"),
    };

    let user_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().format(TS_FMT).to_string();

    let result = sqlx::query(
        "INSERT INTO users (id, email, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&user_id)
    .bind(&email)
    .bind(&pw_hash)
    .bind(&now)
    .bind(&now)
    .execute(&state.db)
    .await;

    if let Err(e) = result {
        if let sqlx::Error::Database(db_err) = &e {
            if db_err.is_unique_violation() {
                return err(StatusCode::CONFLICT, "email already registered");
            }
        }
        tracing::error!("register insert failed: {e}");
        return err(StatusCode::INTERNAL_SERVER_ERROR, "registration failed");
    }

    let device = clean_device(&body.device_name, "registration");
    let token = match create_session(&state, &user_id, &device).await {
        Ok(t) => t,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "registration failed"),
    };

    (
        StatusCode::CREATED,
        Json(AuthResponse {
            token,
            user: UserInfo { id: user_id, email, created_at: now },
        }),
    )
        .into_response()
}

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Response {
    let email = body.email.trim().to_lowercase();
    let ip_key = format!("login-ip:{}", client_ip(&addr, &headers, state.trust_proxy));
    let email_key = format!("login-email:{email}");

    if !state.limiter.check(&ip_key, 30, LOGIN_WINDOW)
        || !state.limiter.check(&email_key, 10, LOGIN_WINDOW)
    {
        return too_many();
    }

    let fail = |state: &AppState| {
        state.limiter.hit(&ip_key, LOGIN_WINDOW);
        state.limiter.hit(&email_key, LOGIN_WINDOW);
        err(StatusCode::UNAUTHORIZED, "invalid email or password")
    };

    if body.password.len() > MAX_PASSWORD_BYTES {
        return fail(&state);
    }

    let row = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id, email, password_hash, created_at FROM users WHERE email = ?",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await;

    let (user_id, user_email, pw_hash, created_at) = match row {
        Ok(Some(r)) => r,
        Ok(None) => return fail(&state),
        Err(e) => {
            tracing::error!("login query failed: {e}");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "login failed");
        }
    };

    let password = body.password.clone();
    let ok = tokio::task::spawn_blocking(move || verify_password(&password, &pw_hash))
        .await
        .unwrap_or(false);
    if !ok {
        return fail(&state);
    }

    state.limiter.reset(&email_key);

    let device = clean_device(&body.device_name, "unknown");
    let token = match create_session(&state, &user_id, &device).await {
        Ok(t) => t,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "login failed"),
    };

    (
        StatusCode::OK,
        Json(AuthResponse {
            token,
            user: UserInfo { id: user_id, email: user_email, created_at },
        }),
    )
        .into_response()
}

pub async fn me(auth: AuthUser, State(state): State<AppState>) -> impl IntoResponse {
    let row = sqlx::query_as::<_, (String, String, String)>(
        "SELECT id, email, created_at FROM users WHERE id = ?",
    )
    .bind(&auth.user_id)
    .fetch_optional(&state.db)
    .await;

    match row {
        Ok(Some((id, email, created_at))) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "id": id,
                "email": email,
                "created_at": created_at,
            })),
        ),
        _ => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "user not found"})),
        ),
    }
}

pub async fn logout(auth: AuthUser, State(state): State<AppState>) -> impl IntoResponse {
    let res = sqlx::query("DELETE FROM sessions WHERE id = ? AND user_id = ?")
        .bind(&auth.session_id)
        .bind(&auth.user_id)
        .execute(&state.db)
        .await;
    match res {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))),
        Err(e) => {
            tracing::error!("logout failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "logout failed"})),
            )
        }
    }
}
