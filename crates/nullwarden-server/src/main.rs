use nullwarden_server::{
    app::build_router,
    auth::password,
    config::Config,
    db::pool::AppState,
    db::users::SqlxUserRepository,
    db::vaults::SqlxVaultRepository,
};
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let config = Config::from_env()?;

    let db_url = config.database_url.as_ref().ok_or_else(|| {
        anyhow::anyhow!("DATABASE_URL must be set")
    })?;
    let db = PgPool::connect(db_url).await?;

    // Run migrations
    sqlx::migrate!("./migrations").run(&db).await?;

    // C-02: Pre-compute dummy hash for timing oracle mitigation
    let dummy_hash = password::hash_password(&config, "dummy_password_never_used_xyz_!@#").await?;

    // Initialize repositories
    let users = Arc::new(SqlxUserRepository { pool: db.clone() });
    let vaults = Arc::new(SqlxVaultRepository { pool: db.clone() });

    let state = Arc::new(AppState::init(config.clone(), db, users, vaults, dummy_hash));

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
