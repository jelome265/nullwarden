use nullwarden_core::vault::VaultStore;
use tempfile::tempdir;

#[test]
fn atomic_write_creates_file() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("vault.nwd");
    let store = VaultStore::new(&path);
    store.init("password").expect("init");
    assert!(path.exists());
}
