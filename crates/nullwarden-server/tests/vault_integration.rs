mod support;

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use support::test_app;
use tower::ServiceExt;

async fn request(
    app: axum::Router,
    request: Request<Body>,
) -> axum::response::Response {
    app.oneshot(request).await.unwrap()
}

#[tokio::test]
async fn login_push_pull_and_conflict_flow_uses_real_router_handlers() {
    let app = test_app().await;

    let register = Request::builder()
        .method(Method::POST)
        .uri("/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"username":"alice","password":"correct horse battery staple"}"#,
        ))
        .unwrap();
    let register = request(app.clone(), register).await;
    assert_eq!(register.status(), StatusCode::CREATED);

    let login = Request::builder()
        .method(Method::POST)
        .uri("/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"username":"alice","password":"correct horse battery staple"}"#,
        ))
        .unwrap();
    let login = request(app.clone(), login).await;
    assert_eq!(login.status(), StatusCode::OK);

    let login_body = to_bytes(login.into_body(), usize::MAX).await.unwrap();
    let login_json: serde_json::Value = serde_json::from_slice(&login_body).unwrap();
    let access_token = login_json["access_token"].as_str().unwrap();

    let first_push = Request::builder()
        .method(Method::PUT)
        .uri("/vault")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::from("vault-v1"))
        .unwrap();
    let first_push = request(app.clone(), first_push).await;
    assert_eq!(first_push.status(), StatusCode::OK);
    let first_push_body = to_bytes(first_push.into_body(), usize::MAX).await.unwrap();
    assert_eq!(first_push_body.as_ref(), b"version=1");

    let second_push = Request::builder()
        .method(Method::PUT)
        .uri("/vault")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .header("X-If-Match", "1")
        .body(Body::from("vault-v2"))
        .unwrap();
    let second_push = request(app.clone(), second_push).await;
    assert_eq!(second_push.status(), StatusCode::OK);
    let second_push_body = to_bytes(second_push.into_body(), usize::MAX).await.unwrap();
    assert_eq!(second_push_body.as_ref(), b"version=2");

    let pull = Request::builder()
        .method(Method::GET)
        .uri("/vault")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::empty())
        .unwrap();
    let pull = request(app.clone(), pull).await;
    assert_eq!(pull.status(), StatusCode::OK);
    assert_eq!(pull.headers()["X-Vault-Version"], "2");
    let pull_body = to_bytes(pull.into_body(), usize::MAX).await.unwrap();
    assert_eq!(pull_body.as_ref(), b"vault-v2");

    let conflict = Request::builder()
        .method(Method::PUT)
        .uri("/vault")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .header("X-If-Match", "1")
        .body(Body::from("stale-write"))
        .unwrap();
    let conflict = request(app, conflict).await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
}
