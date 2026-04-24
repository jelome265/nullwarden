mod support;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use support::{test_app, test_app_with_limits};
use tower::ServiceExt;

#[tokio::test]
async fn auth_endpoints_are_rate_limited() {
    let app = test_app_with_limits(1, 60).await;

    let first = Request::builder()
        .method(Method::POST)
        .uri("/auth/register")
        .header("X-Forwarded-For", "198.51.100.10")
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
        .header("X-Forwarded-For", "198.51.100.10")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"username":"bob","password":"correct horse battery staple"}"#,
        ))
        .unwrap();
    let second = app.oneshot(second).await.unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn auth_rate_limit_is_isolated_per_ip() {
    let app = test_app_with_limits(1, 60).await;

    let first = Request::builder()
        .method(Method::POST)
        .uri("/auth/register")
        .header("X-Forwarded-For", "198.51.100.11")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"username":"carol","password":"correct horse battery staple"}"#,
        ))
        .unwrap();
    let first = app.clone().oneshot(first).await.unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = Request::builder()
        .method(Method::POST)
        .uri("/auth/register")
        .header("X-Forwarded-For", "198.51.100.12")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"username":"dave","password":"correct horse battery staple"}"#,
        ))
        .unwrap();
    let second = app.oneshot(second).await.unwrap();
    assert_eq!(second.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn vault_force_pushes_are_rate_limited_per_user() {
    let app = test_app().await;

    let register = Request::builder()
        .method(Method::POST)
        .uri("/auth/register")
        .header("X-Forwarded-For", "198.51.100.30")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"username":"frank","password":"correct horse battery staple"}"#,
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(register).await.unwrap().status(),
        StatusCode::CREATED
    );

    let login = Request::builder()
        .method(Method::POST)
        .uri("/auth/login")
        .header("X-Forwarded-For", "198.51.100.30")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"username":"frank","password":"correct horse battery staple"}"#,
        ))
        .unwrap();
    let login = app.clone().oneshot(login).await.unwrap();
    let body = axum::body::to_bytes(login.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let access_token = json["access_token"].as_str().unwrap();

    let bytes = {
        let data = nullwarden_core::vault::VaultData::default();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = nullwarden_core::vault::VaultStore::new(tmp.path());
        store.save("correct horse battery staple", &data).unwrap();
        std::fs::read(tmp.path()).unwrap()
    };

    for _ in 0..3 {
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/vault")
            .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
            .header("X-Force", "true")
            .body(Body::from(bytes.clone()))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let limited = Request::builder()
        .method(Method::PUT)
        .uri("/vault")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .header("X-Force", "true")
        .body(Body::from(bytes))
        .unwrap();
    let limited = app.oneshot(limited).await.unwrap();
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
}
