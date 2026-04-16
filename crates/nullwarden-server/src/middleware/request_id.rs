use axum::http::header::HeaderName;
use axum::Router;
use tower_http::request_id::{MakeRequestUuid, SetRequestIdLayer};

pub fn add_request_id_layer(router: Router) -> Router {
    let x_request_id = HeaderName::from_static("x-request-id");
    router.layer(SetRequestIdLayer::new(x_request_id, MakeRequestUuid))
}
