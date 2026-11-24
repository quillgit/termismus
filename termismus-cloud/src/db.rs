use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;

pub async fn init_pool() -> Result<SqlitePool> {
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:termismus.db?mode=rwc".into());

    let opts = SqliteConnectOptions::from_str(&db_url)?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        .busy_timeout(std::time::Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(opts)
        .await?;

    run_migrations(&pool).await?;
    Ok(pool)
}

async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    sqlx::raw_sql(include_str!("../migrations/001_init.sql"))
        .execute(pool)
        .await
        .context("migration failed (duplicate vault versions?)")?;
    tracing::info!("database migrations applied");
    Ok(())
}
