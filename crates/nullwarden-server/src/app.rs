use crate::{
    db::pool::SharedState,
    handlers::{auth, vault},
    middleware::rate_limit::get_auth_rate_limit_layer,
};
use axum::{
    http::{header, HeaderName, HeaderValue},
    routing::{get, post},
    Router,
};
use tower_http::{
    request_id::{MakeRequestUuid, SetRequestIdLayer},
    set_header::SetResponseHeaderLayer,
};

pub fn build_router(state: SharedState) -> Router {
    let auth_rate_limit = get_auth_rate_limit_layer(state.config.rate_limit_auth_requests);
    let x_request_id = HeaderName::from_static("x-request-id");

    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(
            "/auth/register",
            post(auth::register).layer(auth_rate_limit.clone()),
        )
        .route(
            "/auth/login",
            post(auth::login).layer(auth_rate_limit),
        )

        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/logout", post(auth::logout))
        .route("/vault", get(vault::get_vault).put(vault::put_vault))
        .layer(SetRequestIdLayer::new(x_request_id, MakeRequestUuid))
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
