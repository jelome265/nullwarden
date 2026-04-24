mod support;

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use nullwarden_core::vault::{VaultData, VaultStore};
use support::test_app;
use tower::ServiceExt;

async fn request(app: axum::Router, request: Request<Body>) -> axum::response::Response {
    app.oneshot(request).await.unwrap()
}

fn build_vault_blob(entry_name: &str) -> Vec<u8> {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let store = VaultStore::new(tmp.path());
    let mut data = VaultData::default();
    data.add_entry(
        entry_name.to_string(),
        "alice".to_string(),
        "super-secret-password".to_string(),
        None,
    )
    .unwrap();
    store.save("correct horse battery staple", &data).unwrap();
    std::fs::read(tmp.path()).unwrap()
}

#[tokio::test]
async fn login_push_pull_and_conflict_flow_uses_real_router_handlers() {
    let app = test_app().await;

    let register = Request::builder()
        .method(Method::POST)
        .uri("/auth/register")
        .header("X-Forwarded-For", "198.51.100.21")
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
        .header("X-Forwarded-For", "198.51.100.21")
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

    let vault_v1 = build_vault_blob("entry-v1");
    let first_push = Request::builder()
        .method(Method::PUT)
        .uri("/vault")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::from(vault_v1.clone()))
        .unwrap();
    let first_push = request(app.clone(), first_push).await;
    assert_eq!(first_push.status(), StatusCode::OK);
    let first_push_body = to_bytes(first_push.into_body(), usize::MAX).await.unwrap();
    assert_eq!(first_push_body.as_ref(), b"version=1");

    let vault_v2 = build_vault_blob("entry-v2");
    let second_push = Request::builder()
        .method(Method::PUT)
        .uri("/vault")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .header("X-If-Match", "1")
        .body(Body::from(vault_v2.clone()))
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
    assert_eq!(pull_body.as_ref(), vault_v2.as_slice());

    let conflict = Request::builder()
        .method(Method::PUT)
        .uri("/vault")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .header("X-If-Match", "1")
        .body(Body::from(vault_v1))
        .unwrap();
    let conflict = request(app, conflict).await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn invalid_vault_blob_is_rejected() {
    let app = test_app().await;

    let register = Request::builder()
        .method(Method::POST)
        .uri("/auth/register")
        .header("X-Forwarded-For", "198.51.100.22")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"username":"eve","password":"correct horse battery staple"}"#,
        ))
        .unwrap();
    assert_eq!(
        request(app.clone(), register).await.status(),
        StatusCode::CREATED
    );

    let login = Request::builder()
        .method(Method::POST)
        .uri("/auth/login")
        .header("X-Forwarded-For", "198.51.100.22")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"username":"eve","password":"correct horse battery staple"}"#,
        ))
        .unwrap();
    let login = request(app.clone(), login).await;
    let login_body = to_bytes(login.into_body(), usize::MAX).await.unwrap();
    let login_json: serde_json::Value = serde_json::from_slice(&login_body).unwrap();
    let access_token = login_json["access_token"].as_str().unwrap();

    let invalid_push = Request::builder()
        .method(Method::PUT)
        .uri("/vault")
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::from("not-a-vault"))
        .unwrap();
    let response = request(app, invalid_push).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
