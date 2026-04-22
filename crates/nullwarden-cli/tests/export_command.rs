use nullwarden_cli::commands::export::export_vault;
use nullwarden_core::vault::VaultStore;
use tempfile::tempdir;

#[tokio::test]
async fn export_command_writes_reencrypted_backup() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("vault.nw");
    let store = VaultStore::new(&vault_path);
    let master_password = "enterprise-grade-password-123!";
    let backup_password = "different-but-still-strong-42";

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

    let output_path = dir.path().join("backup.nw");
    export_vault(&vault_path, &output_path, master_password, backup_password).await.unwrap();

    // Verify it can be unlocked with backup password
    let backup_store = VaultStore::new(&output_path);
    let decrypted = backup_store.unlock(backup_password).expect("should unlock with backup password");
    assert_eq!(decrypted.entries.len(), 1);
    assert_eq!(decrypted.entries[0].title, "example");

    // Verify it CANNOT be unlocked with original master password (unless they are the same)
    let res = backup_store.unlock(master_password);
    assert!(res.is_err(), "should NOT unlock with original master password");
}
