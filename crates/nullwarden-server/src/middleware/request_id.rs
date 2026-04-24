use axum::{extract::Request, http::header::HeaderName, middleware::Next, response::Response};
use tower_http::request_id::{MakeRequestUuid, RequestId, SetRequestIdLayer};
use tracing::info;

pub fn add_request_id_layer<S>(router: axum::Router<S>) -> axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let x_request_id = HeaderName::from_static("x-request-id");
    router.layer(SetRequestIdLayer::new(
        x_request_id.clone(),
        MakeRequestUuid,
    ))
}

pub async fn log_request_id(request: Request, next: Next) -> Response {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .and_then(|id: &RequestId| id.header_value().to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    info!(
        method = %request.method(),
        uri = %request.uri(),
        request_id = %request_id,
        "Request started"
    );

    let response = next.run(request).await;

    info!(
        status = %response.status(),
        request_id = %request_id,
        "Request finished"
    );

    response
}
