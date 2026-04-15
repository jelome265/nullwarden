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
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let config = Config::from_env()?;
    let state = Arc::new(AppState::new(config.clone()));
    let app = build_router(state);
    let addr: SocketAddr = format!("{}:{}", config.server_host, config.server_port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("nullwarden-server listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}
