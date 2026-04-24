use crate::{
    db::pool::SharedState,
    handlers::{auth, vault},
    middleware::request_id,
};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{
        header::{self, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
        HeaderMap, Method, StatusCode,
    },
    middleware,
    routing::{delete, get, post},
    Router,
};
use ipnet::IpNet;
use std::{net::IpAddr, sync::Arc};
use tower_governor::{
    errors::GovernorError,
    governor::GovernorConfigBuilder,
    key_extractor::{KeyExtractor, PeerIpKeyExtractor},
    GovernorLayer,
};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    set_header::SetResponseHeaderLayer,
};

pub fn build_router(state: SharedState) -> anyhow::Result<Router> {
    let auth_rate_limit_config = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(TrustedProxyKeyExtractor::new(parse_trusted_proxy_cidrs(
                &state.config.trusted_proxy_cidrs,
            )?))
            .period(std::time::Duration::from_secs(
                state.config.rate_limit_auth_window_secs,
            ))
            .methods(vec![Method::POST])
            .burst_size(state.config.rate_limit_auth_requests)
            .finish()
            .expect("rate limit configuration must be valid"),
    );

    let auth_rate_limit = GovernorLayer {
        config: auth_rate_limit_config.clone(),
    };

    let origins = parse_allowed_origins(&state.config.cors_allowed_origins)?;
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
        .allow_origin(AllowOrigin::list(origins));

    let auth_routes = Router::new()
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/user", delete(auth::delete_user))
        .layer(auth_rate_limit);

    let api_routes = Router::new()
        .route("/health", get(health))
        .merge(auth_routes)
        .route("/vault", get(vault::get_vault).put(vault::put_vault))
        .route("/vault/history", delete(vault::purge_vault_history))
        .layer(DefaultBodyLimit::max(1024 * 1024))
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

    Ok(request_id::add_request_id_layer(api_routes))
}

fn parse_allowed_origins(raw: &str) -> anyhow::Result<Vec<HeaderValue>> {
    let mut origins = Vec::new();
    for origin in raw
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
    {
        origins.push(HeaderValue::from_str(origin)?);
    }
    Ok(origins)
}

fn parse_trusted_proxy_cidrs(raw: &str) -> anyhow::Result<Vec<IpNet>> {
    raw.split(',')
        .map(str::trim)
        .filter(|cidr| !cidr.is_empty())
        .map(str::parse::<IpNet>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(anyhow::Error::from)
}

#[derive(Clone)]
struct TrustedProxyKeyExtractor {
    trusted_proxy_cidrs: Arc<Vec<IpNet>>,
}

impl TrustedProxyKeyExtractor {
    fn new(trusted_proxy_cidrs: Vec<IpNet>) -> Self {
        Self {
            trusted_proxy_cidrs: Arc::new(trusted_proxy_cidrs),
        }
    }

    fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        self.trusted_proxy_cidrs
            .iter()
            .any(|cidr| cidr.contains(&ip))
    }

    fn forwarded_ip(&self, headers: &HeaderMap) -> Option<IpAddr> {
        headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| {
                let chain = value
                    .split(',')
                    .map(str::trim)
                    .filter_map(|part| part.parse::<IpAddr>().ok())
                    .collect::<Vec<_>>();
                chain
                    .iter()
                    .rev()
                    .copied()
                    .find(|ip| !self.is_trusted_proxy(*ip))
                    .or_else(|| chain.first().copied())
            })
            .or_else(|| {
                headers
                    .get("x-real-ip")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<IpAddr>().ok())
            })
    }
}

impl KeyExtractor for TrustedProxyKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &axum::http::Request<T>) -> Result<Self::Key, GovernorError> {
        let peer_ip = PeerIpKeyExtractor.extract(req).ok();
        match peer_ip {
            Some(peer_ip) if self.is_trusted_proxy(peer_ip) => self
                .forwarded_ip(req.headers())
                .or(Some(peer_ip))
                .ok_or(GovernorError::UnableToExtractKey),
            Some(peer_ip) => Ok(peer_ip),
            None => self
                .forwarded_ip(req.headers())
                .ok_or(GovernorError::UnableToExtractKey),
        }
    }
}

async fn health(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<&'static str, StatusCode> {
    let Some(expected_token) = state.config.health_check_token.as_ref() else {
        return Err(StatusCode::NOT_FOUND);
    };

    match headers
        .get("X-Health-Token")
        .and_then(|value| value.to_str().ok())
    {
        Some(candidate) if candidate == expected_token.0 => Ok("ok"),
        _ => Err(StatusCode::NOT_FOUND),
    }
}
