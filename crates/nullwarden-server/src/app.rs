use crate::{
    db::pool::SharedState,
    handlers::{auth, vault},
};
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};

use axum::http::{header, HeaderValue};
use tower_http::set_header::SetResponseHeaderLayer;

pub fn build_router(state: SharedState) -> Router {
    let auth_governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(state.config.rate_limit_auth_requests as u64)
            .burst_size(state.config.rate_limit_auth_requests)
            .finish()
            .unwrap(),
    );

    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(
            "/auth/register",
            post(auth::register).layer(GovernorLayer {
                config: auth_governor_conf.clone(),
            }),
        )
        .route(
            "/auth/login",
            post(auth::login).layer(GovernorLayer {
                config: auth_governor_conf,
            }),
        )
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/logout", post(auth::logout))
        .route("/vault", get(vault::get_vault).put(vault::put_vault))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'"),
        ))
        .with_state(state)
}
