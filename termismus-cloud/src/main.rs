mod auth;
mod db;
mod models;
mod rate_limit;
mod vault_sync;

use std::sync::Arc;
use std::time::Duration;

use axum::routing::{delete, get, post};
use axum::Router;
use rand::RngCore;
use sqlx::SqlitePool;
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub jwt_secret: Arc<Vec<u8>>,
    pub limiter: Arc<rate_limit::RateLimiter>,
    pub allow_registration: bool,
    pub trust_proxy: bool,
}

fn load_jwt_secret() -> anyhow::Result<Vec<u8>> {
    match std::env::var("JWT_SECRET") {
        Ok(s) => {
            if s.len() < 32 {
                anyhow::bail!("JWT_SECRET must be at least 32 bytes");
            }
            Ok(s.into_bytes())
        }
        Err(_) => {
            if std::env::var("TERMISMUS_DEV").as_deref() == Ok("1") {
                let mut buf = vec![0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut buf);
                tracing::warn!(
                    "JWT_SECRET not set: using an ephemeral dev secret; all tokens die on restart"
                );
                Ok(buf)
            } else {
                anyhow::bail!(
                    "JWT_SECRET is not set (set TERMISMUS_DEV=1 for a local dev server with an ephemeral secret)"
                )
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "termismus_cloud=info,tower_http=info".into()),
        )
        .init();

    let jwt_secret = load_jwt_secret()?;

    let allow_registration = !matches!(
        std::env::var("ALLOW_REGISTRATION")
            .unwrap_or_default()
            .trim()
            .to_lowercase()
            .as_str(),
        "0" | "false" | "no" | "off"
    );
    let trust_proxy = matches!(
        std::env::var("TRUST_PROXY")
            .unwrap_or_default()
            .trim()
            .to_lowercase()
            .as_str(),
        "1" | "true"
    );

    let pool = db::init_pool().await?;
    let state = AppState {
        db: pool.clone(),
        jwt_secret: Arc::new(jwt_secret),
        limiter: Arc::new(rate_limit::RateLimiter::new()),
        allow_registration,
        trust_proxy,
    };

    // Periodic cleanup of rate-limit entries and expired sessions.
    {
        let limiter = state.limiter.clone();
        let pool = pool.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(600));
            loop {
                tick.tick().await;
                limiter.prune();
                let _ = sqlx::query(
                    "DELETE FROM sessions WHERE expires_at <= strftime('%Y-%m-%dT%H:%M:%SZ','now')",
                )
                .execute(&pool)
                .await;
            }
        });
    }

    // CORS is irrelevant for the reqwest-based desktop client; kept permissive.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/auth/register", post(auth::register))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/me", get(auth::me))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/vault/push", post(vault_sync::push))
        .route("/api/vault/pull", get(vault_sync::pull))
        .route("/api/vault/history", get(vault_sync::history))
        .route(
            "/api/vault/version/:version_id",
            delete(vault_sync::delete_version),
        )
        // 70 MiB covers base64 overhead of a 50 MiB blob.
        .layer(axum::extract::DefaultBodyLimit::max(70 * 1024 * 1024))
        .layer(cors)
        .with_state(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3200);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("TERMISMUS cloud listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}
