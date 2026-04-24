mod support;

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use serde_json::{json, Value};
use support::{test_app, test_app_with_state};
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
        .header("X-Forwarded-For", "198.51.100.20")
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

#[tokio::test]
async fn authenticated_user_can_delete_account() {
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

    let delete = Request::builder()
        .method(Method::DELETE)
        .uri("/auth/user")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::empty())
        .unwrap();
    let delete = app.clone().oneshot(delete).await.unwrap();
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);

    let relogin = json_request(
        app,
        Method::POST,
        "/auth/login",
        json!({"username": "alice", "password": "correct horse battery staple"}),
        None,
    )
    .await;
    assert_eq!(relogin.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_tokens_are_stored_as_sha256_not_argon2_hashes() {
    let (app, state) = test_app_with_state().await;

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
    let refresh_token = login_body["refresh_token"].as_str().unwrap().to_string();

    {
        let state = state.lock().unwrap();
        let stored = state
            .refresh_tokens
            .values()
            .next()
            .expect("login should store a refresh token");
        assert_eq!(stored.secret_hash.len(), 64);
        assert!(!stored.secret_hash.starts_with("$argon2"));
    }

    let refresh = json_request(
        app,
        Method::POST,
        "/auth/refresh",
        json!({ "refresh_token": refresh_token }),
        None,
    )
    .await;
    assert_eq!(refresh.status(), StatusCode::OK);
}
