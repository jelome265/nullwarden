mod support;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use support::test_app_with_limits;
use tower::ServiceExt;

#[tokio::test]
async fn auth_endpoints_are_rate_limited() {
    let app = test_app_with_limits(1, 60).await;

    let first = Request::builder()
        .method(Method::POST)
        .uri("/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"username":"alice","password":"correct horse battery staple"}"#,
        ))
        .unwrap();
    let first = app.clone().oneshot(first).await.unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = Request::builder()
        .method(Method::POST)
        .uri("/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"username":"bob","password":"correct horse battery staple"}"#,
        ))
        .unwrap();
    let second = app.oneshot(second).await.unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
}
