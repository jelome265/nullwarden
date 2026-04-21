use nullwarden_core::vault::VaultStore;
use tempfile::tempdir;

#[test]
fn clear_notes_persists_through_save_and_load() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("vault.nw");
    let store = VaultStore::new(&vault_path);
    let password = "correct horse battery staple";

    let mut vault = store.init(password).unwrap();
    vault.add_entry(
        "example".to_string(),
        "alice".to_string(),
        "super-secret-password".to_string(),
        Some("private notes".to_string()),
    )
    .unwrap();
    store.save(password, &vault).unwrap();

    let mut reloaded = store.unlock(password).unwrap();
    reloaded
        .update_entry("example", None, None, Some(None))
        .unwrap();
    store.save(password, &reloaded).unwrap();

    let final_vault = store.unlock(password).unwrap();
    let entry = final_vault.get_entry("example").unwrap();
    assert_eq!(entry.notes, None);
}
