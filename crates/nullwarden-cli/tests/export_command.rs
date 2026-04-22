use nullwarden_cli::commands::export::export_vault;
use nullwarden_core::vault::VaultStore;
use tempfile::tempdir;

#[tokio::test]
async fn export_command_writes_matching_encrypted_backup() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("vault.nw");
    let store = VaultStore::new(&vault_path);
    let master_password = "enterprise-grade-password-123!";

    let mut vault = store.init(master_password).unwrap();
    vault
        .add_entry(
            "example".to_string(),
            "alice".to_string(),
            "super-secret-password".to_string(),
            Some("offline backup test".to_string()),
        )
        .unwrap();
    store.save(master_password, &vault).unwrap();

    let output = export_vault(&vault_path, None).await.unwrap();
    assert_eq!(output, vault_path.with_extension("nwbackup"));

    let original = std::fs::read(&vault_path).unwrap();
    let exported = std::fs::read(&output).unwrap();
    assert_eq!(original, exported);
}
