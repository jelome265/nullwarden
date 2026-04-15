use crate::{
    db::pool::SharedState,
    handlers::{auth, vault},
};
use axum::{
    routing::{get, post},
    Router,
};

pub fn build_router(state: SharedState) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/logout", post(auth::logout))
        .route("/vault", get(vault::get_vault).put(vault::put_vault))
        .with_state(state)
}
