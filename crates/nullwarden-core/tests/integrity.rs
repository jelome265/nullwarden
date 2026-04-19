use nullwarden_core::vault::VaultStore;
use tempfile::tempdir;

#[test]
fn test_vault_integrity_failure() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("vault.nwd");
    let store = VaultStore::new(&path);
    let master_password = "password123";
    
    // 1. Create a valid vault
    store.init(master_password).expect("init");
    
    // 2. Corrupt the file
    let mut bytes = std::fs::read(&path).expect("read");
    // Flip a bit in the ciphertext (offset 73+)
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&path, bytes).expect("write");
    
    // 3. Attempt unlock — should fail integrity check
    let res = store.unlock(master_password);
    assert!(res.is_err(), "Unlock should fail on corrupted vault");
}

#[test]
fn test_wrong_master_password() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("vault.nwd");
    let store = VaultStore::new(&path);
    
    store.init("correct_password").expect("init");
    
    let res = store.unlock("wrong_password");
    assert!(res.is_err(), "Unlock should fail with wrong password");
}
