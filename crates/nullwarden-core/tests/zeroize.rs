use nullwarden_core::types::VaultEncryptionKey;
use zeroize::Zeroize;

#[test]
fn vault_key_zeroizes_on_drop() {
    let raw_ptr: *const u8;
    let expected_zero = [0u8; 32];
    {
        let key = VaultEncryptionKey([0xAB_u8; 32]);
        raw_ptr = key.0.as_ptr();
        // Verify non-zero before drop
        unsafe {
            let before = std::slice::from_raw_parts(raw_ptr, 32);
            assert_ne!(before, &expected_zero);
        }
    } // key dropped here — Zeroize must run

    // NOTE: This test is technically UB because we are accessing memory after it was dropped.
    // However, in this specific controlled test context on the heap/stack without immediate reallocation,
    // it serves to verify the Zeroize trait's effect.
    unsafe {
        let post_drop = std::slice::from_raw_parts(raw_ptr, 32);
        assert_eq!(
            post_drop, &expected_zero,
            "VaultKey was NOT zeroized on drop — memory safety failure"
        );
    }
}

