use crate::{
    db::pool::SharedState,
    handlers::{auth, vault},
    middleware::request_id,
};
use axum::{
    extract::DefaultBodyLimit,
    http::{
        header::{self, AUTHORIZATION, CONTENT_TYPE, HeaderValue},
        Method,
    },
    middleware,
    routing::{get, post},
    Router,
};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    set_header::SetResponseHeaderLayer,
};

pub fn build_router(state: SharedState) -> Router {
    // H-09: CORS configuration
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::any()) // In production, restrict to your domain
        .allow_methods([Method::GET, Method::POST, Method::PUT])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE]);

    let api_routes = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/logout", post(auth::logout))
        .route("/vault", get(vault::get_vault).put(vault::put_vault))
        // M-07: Request body size limit (10MB)
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        .layer(middleware::from_fn(request_id::log_request_id))
        .layer(cors)
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
        .with_state(state);

    request_id::add_request_id_layer(api_routes)
}
