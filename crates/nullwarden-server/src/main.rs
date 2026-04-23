use nullwarden_server::{
    app::build_router,
    auth::{jwt, password, token},
    config::Config,
    db::pool::AppState,
    db::tokens::{SqlxRefreshTokenRepository, SqlxTokenBlocklistRepository},
    db::users::SqlxUserRepository,
    db::vaults::SqlxVaultRepository,
};
use sqlx::migrate::Migrator;
use sqlx_postgres::PgPoolOptions;
use std::{net::SocketAddr, path::Path, sync::Arc};
use tokio::net::TcpListener;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().init();
    let config = Config::from_env()?;

    let db_url = config
        .database_url
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("DATABASE_URL must be set"))?;
    let db = PgPoolOptions::new()
        .max_connections(config.db_max_connections)
        .connect(db_url)
        .await?;

    // Run migrations
    let migrator = Migrator::new(Path::new("./migrations")).await?;
    migrator.run(&db).await?;

    // C-02: Pre-compute dummy hash for timing oracle mitigation
    let dummy_hash = password::hash_password(&config, "dummy_password_never_used_xyz_!@#").await?;

    // Initialize repositories
    let users = Arc::new(SqlxUserRepository { pool: db.clone() });
    let vaults = Arc::new(SqlxVaultRepository { pool: db.clone() });
    let refresh_tokens = Arc::new(SqlxRefreshTokenRepository { pool: db.clone() });
    let token_blocklist = Arc::new(SqlxTokenBlocklistRepository { pool: db.clone() });

    let state = Arc::new(AppState::init(
        config.clone(),
        users,
        vaults,
        refresh_tokens,
        token_blocklist,
        dummy_hash,
    ));

    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            cleanup_state.config.cleanup_interval_secs,
        ));

        loop {
            interval.tick().await;

            if let Err(err) = token::cleanup_expired_tokens(&cleanup_state).await {
                tracing::warn!("failed to clean expired refresh tokens: {err:?}");
            }

            if let Err(err) = jwt::cleanup_blocked_tokens(&cleanup_state).await {
                tracing::warn!("failed to clean expired blocklisted tokens: {err:?}");
            }
        }
    });

    let app = build_router(state);
    let addr: SocketAddr = format!("{}:{}", config.server_host, config.server_port).parse()?;

    info!("nullwarden-server listening on {}", addr);

    if let (Some(cert_path), Some(key_path)) = (&config.tls_cert_path, &config.tls_key_path) {
        use axum_server::tls_rustls::RustlsConfig;
        let tls_config = RustlsConfig::from_pem_file(cert_path, key_path).await?;
        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await?;
    } else {
        warn!("TLS not configured (missing TLS_CERT_PATH or TLS_KEY_PATH). Running in plain HTTP mode — INSECURE!");
        let listener = TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
    }

    Ok(())
}
