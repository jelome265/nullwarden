use nullwarden_cli::client::sync::SyncClient;
use nullwarden_cli::sync_state::SyncState;
use nullwarden_core::vault::VaultStore;
use tempfile::tempdir;
use std::net::SocketAddr;
use std::sync::Arc;
use axum::{
    routing::{get, put},
    Router,
    Json,
    extract::{State, Path as AxumPath},
    http::{StatusCode, HeaderMap},
};
use serde_json::json;

#[tokio::test]
async fn test_sync_push_pull_flow() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("vault.nwd");
    let master_password = "sync-test-password-123!";
    
    // 1. Create a local vault
    let store = VaultStore::new(&vault_path);
    store.init(master_password).unwrap();
    
    // 2. Setup a mock server
    let mock_vault_blob = Arc::new(tokio::sync::RwLock::new(None::<(u64, Vec<u8>)>));
    let state = mock_vault_blob.clone();
    
    let app = Router::new()
        .route("/vault", get({
            let state = state.clone();
            move |headers: HeaderMap| {
                let state = state.clone();
                async move {
                    let vault = state.read().await;
                    if let Some((version, blob)) = &*vault {
                        let mut res_headers = HeaderMap::new();
                        res_headers.insert("X-Vault-Version", (*version).into());
                        (StatusCode::OK, res_headers, blob.clone())
                    } else {
                        (StatusCode::NOT_FOUND, HeaderMap::new(), vec![])
                    }
                }
            }
        }))
        .route("/vault", put({
            let state = state.clone();
            move |headers: HeaderMap, body: axum::body::Bytes| {
                let state = state.clone();
                async move {
                    let force = headers.get("X-Force").is_some();
                    let expected_version = headers.get("X-If-Match")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok());
                    
                    let mut vault = state.write().await;
                    let current_version = vault.as_ref().map(|(v, _)| *v).unwrap_or(0);
                    
                    if !force && expected_version.is_some() && expected_version.unwrap() != current_version {
                        return (StatusCode::CONFLICT, "version mismatch".to_string());
                    }
                    
                    let new_version = current_version + 1;
                    *vault = Some((new_version, body.to_vec()));
                    (StatusCode::OK, format!("version={}", new_version))
                }
            }
        }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_url = format!("http://{}", addr);
    
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    
    // 3. Push
    let client = SyncClient::new(server_url.clone(), None);
    let mut sync_state = SyncState::load(&vault_path).unwrap();
    
    let new_version = client.push(&vault_path, sync_state.last_version, false).await.expect("push failed");
    assert_eq!(new_version, 1);
    sync_state.last_version = new_version;
    sync_state.save(&vault_path).unwrap();
    
    // 4. Pull on another "device"
    let dir2 = tempdir().unwrap();
    let vault_path2 = dir2.path().join("vault.nwd");
    let mut sync_state2 = SyncState::default();
    
    let (pulled_version, bytes) = client.pull(sync_state2.last_version).await.expect("pull failed");
    assert_eq!(pulled_version, 1);
    std::fs::write(&vault_path2, bytes).unwrap();
    
    // Verify pulled vault
    let store2 = VaultStore::new(&vault_path2);
    let vault2 = store2.unlock(master_password).expect("failed to unlock pulled vault");
    assert_eq!(vault2.entries.len(), 0);
}
