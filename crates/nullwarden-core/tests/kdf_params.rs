use nullwarden_core::kdf::{derive_key, KdfParams, SALT_LEN};
use nullwarden_core::vault::header::{VaultHeader, VaultHeaderDecodeError};

#[test]
fn kdf_uses_32_byte_key() {
    let salt = [0_u8; SALT_LEN];
    let params = KdfParams::default();
    let key = derive_key(b"password", &salt, params).unwrap();
    assert_eq!(key.as_ref().len(), 32);
}

#[test]
fn kdf_meets_minimum_latency() {
    let salt = [9_u8; SALT_LEN];
    let params = KdfParams::default();
    let start = std::time::Instant::now();
    derive_key(b"testpassword", &salt, params).unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_millis(300),
        "KDF latency {elapsed:?} is below the 300ms minimum — Argon2 params have been weakened"
    );
}

#[test]
fn vault_header_rejects_out_of_bounds_kdf_params() {
    let mut bytes = VaultHeader {
        format_version: VaultHeader::FORMAT_VERSION,
        m_cost: u32::MAX,
        t_cost: 0,
        p_cost: 0,
        salt: [0; SALT_LEN],
        nonce: [0; 24],
    }
    .encode();
    bytes.extend_from_slice(&[0, 1, 2, 3]);

    assert!(matches!(
        VaultHeader::decode(&bytes),
        Err(VaultHeaderDecodeError::InvalidFormat)
    ));
}

#[test]
fn vault_header_reports_unsupported_format_version() {
    let mut bytes = VaultHeader {
        format_version: 2,
        m_cost: 65536,
        t_cost: 3,
        p_cost: 4,
        salt: [0; SALT_LEN],
        nonce: [0; 24],
    }
    .encode();
    bytes.extend_from_slice(&[0, 1, 2, 3]);

    assert!(matches!(
        VaultHeader::decode(&bytes),
        Err(VaultHeaderDecodeError::UnsupportedFormatVersion(2))
    ));
}
