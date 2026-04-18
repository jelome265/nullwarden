use nullwarden_core::vault::VaultStore;
use tempfile::tempdir;

#[test]
fn test_vault_lifecycle_local() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("vault.nw");
    let master_password = "enterprise-grade-password-123!";

    let store = VaultStore::new(&vault_path);

    // Init
    store.init(master_password).unwrap();
    assert!(vault_path.exists());

    // Unlock
    let mut vault = store.unlock(master_password).unwrap();
    assert_eq!(vault.entries.len(), 0);

    // Add
    vault
        .add_entry(
            "test-service".to_string(),
            "test-user".to_string(),
            "test-pass".to_string(),
            Some("test-notes".to_string()),
        )
        .unwrap();
    store.save(master_password, &vault).unwrap();

    // Verify
    let vault = store.unlock(master_password).unwrap();
    assert_eq!(vault.entries.len(), 1);
    let entry = vault.get_entry("test-service").unwrap();
    assert_eq!(entry.username, "test-user");
    assert_eq!(entry.password.0, "test-pass");
    assert_eq!(entry.notes, Some("test-notes".to_string()));

    // Update
    let mut vault = store.unlock(master_password).unwrap();
    vault
        .update_entry("test-service", None, Some("new-pass".to_string()), None)
        .unwrap();
    store.save(master_password, &vault).unwrap();

    // Verify update
    let vault = store.unlock(master_password).unwrap();
    let entry = vault.get_entry("test-service").unwrap();
    assert_eq!(entry.password.0, "new-pass");

    // Delete
    let mut vault = store.unlock(master_password).unwrap();
    vault.delete_entry("test-service").unwrap();
    store.save(master_password, &vault).unwrap();

    // Verify delete
    let vault = store.unlock(master_password).unwrap();
    assert_eq!(vault.entries.len(), 0);
}
