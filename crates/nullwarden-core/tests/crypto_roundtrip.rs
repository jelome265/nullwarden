use nullwarden_core::crypto::{decrypt, encrypt};

#[test]
fn crypto_round_trip() {
    let key = [7_u8; 32];
    let plaintext = b"super secret vault payload";
    let (nonce, ciphertext) = encrypt(&key, plaintext).expect("encrypt");
    let decrypted = decrypt(&key, &nonce, &ciphertext).expect("decrypt");
    assert_eq!(decrypted, plaintext);
}
