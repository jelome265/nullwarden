use nullwarden_core::vault::VaultStore;
use tempfile::tempdir;

#[test]
fn test_clear_notes_persistence() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("vault.nwd");
    let store = VaultStore::new(&path);
    let password = "correct-horse-battery-staple-42";

    let mut vault = store.init(password).expect("init");
    vault
        .add_entry(
            "github".to_string(),
            "alice".to_string(),
            "secret".to_string(),
            Some("some notes".to_string()),
        )
        .expect("add");
    store.save(password, &vault).expect("save");

    // Reopen and clear notes
    let mut vault = store.unlock(password).expect("unlock");
    assert_eq!(
        vault.get_entry("github").unwrap().notes,
        Some("some notes".to_string())
    );

    vault
        .update_entry("github", None, None, Some(None))
        .expect("update");
    store.save(password, &vault).expect("save");

    // Reopen and verify notes are cleared
    let vault = store.unlock(password).expect("unlock");
    assert_eq!(vault.get_entry("github").unwrap().notes, None);
}
