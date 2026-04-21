mod support;

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use serde_json::{json, Value};
use support::test_app;
use tower::ServiceExt;

async fn json_request(
    app: axum::Router,
    method: Method,
    uri: &str,
    body: Value,
    bearer: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");

    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }

    app.oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn register_login_refresh_logout_flow_blocks_logged_out_access_token() {
    let app = test_app().await;

    let register = json_request(
        app.clone(),
        Method::POST,
        "/auth/register",
        json!({"username": "alice", "password": "correct horse battery staple"}),
        None,
    )
    .await;
    assert_eq!(register.status(), StatusCode::CREATED);

    let login = json_request(
        app.clone(),
        Method::POST,
        "/auth/login",
        json!({"username": "alice", "password": "correct horse battery staple"}),
        None,
    )
    .await;
    assert_eq!(login.status(), StatusCode::OK);

    let login_body: Value =
        serde_json::from_slice(&to_bytes(login.into_body(), usize::MAX).await.unwrap()).unwrap();
    let access_token = login_body["access_token"].as_str().unwrap().to_string();
    let refresh_token = login_body["refresh_token"].as_str().unwrap().to_string();

    let refresh = json_request(
        app.clone(),
        Method::POST,
        "/auth/refresh",
        json!({ "refresh_token": refresh_token }),
        None,
    )
    .await;
    assert_eq!(refresh.status(), StatusCode::OK);

    let refresh_body: Value =
        serde_json::from_slice(&to_bytes(refresh.into_body(), usize::MAX).await.unwrap()).unwrap();
    let rotated_refresh_token = refresh_body["refresh_token"].as_str().unwrap().to_string();

    let logout = json_request(
        app.clone(),
        Method::POST,
        "/auth/logout",
        json!({ "refresh_token": rotated_refresh_token }),
        Some(&access_token),
    )
    .await;
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);

    let blocked = Request::builder()
        .method(Method::GET)
        .uri("/vault")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::empty())
        .unwrap();
    let blocked = app.clone().oneshot(blocked).await.unwrap();
    assert_eq!(blocked.status(), StatusCode::UNAUTHORIZED);

    let refresh_after_logout = json_request(
        app,
        Method::POST,
        "/auth/refresh",
        json!({ "refresh_token": rotated_refresh_token }),
        None,
    )
    .await;
    assert_eq!(refresh_after_logout.status(), StatusCode::UNAUTHORIZED);
}
