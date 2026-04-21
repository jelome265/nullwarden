use nullwarden_core::{vault::VaultData, VaultError};

#[test]
fn add_entry_rejects_duplicate_titles() {
    let mut vault = VaultData::default();
    vault
        .add_entry(
            "example".to_string(),
            "alice".to_string(),
            "super-secret-password".to_string(),
            None,
        )
        .unwrap();

    let err = vault
        .add_entry(
            "example".to_string(),
            "bob".to_string(),
            "another-secret-password".to_string(),
            None,
        )
        .unwrap_err();

    assert!(matches!(err, VaultError::DuplicateEntry));
}
