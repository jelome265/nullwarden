use nullwarden_core::vault::VaultStore;
use tempfile::tempdir;

#[test]
fn init_add_unlock_delete_cycle() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("vault.nwd");
    let store = VaultStore::new(&path);
    let mut vault = store.init("correct-horse-battery-staple-42").expect("init");
    vault
        .add_entry(
            "github".to_string(),
            "alice".to_string(),
            "secret".to_string(),
            None,
        )
        .expect("add");
    store
        .save("correct-horse-battery-staple-42", &vault)
        .expect("save");

    let mut reopened = store
        .unlock("correct-horse-battery-staple-42")
        .expect("unlock");
    assert_eq!(reopened.entries.len(), 1);
    assert_eq!(
        reopened.get_entry("github").expect("entry").username,
        "alice"
    );
    reopened.delete_entry("github").expect("delete");
    assert!(reopened.get_entry("github").is_none());
}
