mod app;
mod auth;
mod config;
mod db;
mod error;
mod handlers;
mod middleware;

use crate::{app::build_router, config::Config, db::pool::AppState};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let config = Config::from_env()?;
    // Initialize AppState (connects to Supabase/Postgres)
    let state = Arc::new(AppState::new(config.clone()).await?);

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&state.db)
        .await?;

    let app = build_router(state.clone());
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
