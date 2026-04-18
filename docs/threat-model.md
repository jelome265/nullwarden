# Threat Model

## Trust Model
- **Client (Trusted):** All cryptographic operations occur here. Master passwords never leave the client.
- **Server (Untrusted):** Treated as an adversarial, zero-knowledge storage provider. Only stores opaque ciphertext and metadata.
- **Network (Untrusted):** Assumed to be observable. Protected by TLS 1.3.

## Attack Scenarios and Mitigations

### 1. Client Compromise
- **Threat:** Attacker gains access to the user's machine.
- **Mitigation:** "Lock by exit" model ensures secrets don't persist in RAM. OS Keyring used for session tokens.
- **Residual Risk:** Malware can perform keylogging or screen scraping during an active session.

### 2. Server Compromise / Malicious Admin
- **Threat:** Attacker gains full control of the synchronization server.
- **Mitigation:** Zero-knowledge architecture. All vault data is encrypted with keys the server never sees.
- **Impact:** Attacker can delete or refuse to serve data (DoS) but cannot decrypt it.

### 3. Database Leak / Stolen Backup
- **Threat:** The backend database or its backups are leaked.
- **Mitigation:** All sensitive fields (vault blobs, user passwords) are encrypted or hashed with Argon2id. No plaintext secrets stored.

### 4. Weak Master Password
- **Threat:** User chooses a password vulnerable to brute-force.
- **Mitigation:** CLI enforces a zxcvbn score of ≥ 3 during initialization and updates.

### 5. Sync Replay / Rollback
- **Threat:** Attacker replays an old version of the vault to the server.
- **Mitigation:** Version-counter-based conflict detection (409 Conflict) and mandatory `X-If-Match` headers on updates.

### 6. Tampered Vault Blob
- **Threat:** Attacker modifies the encrypted bytes on the server.
- **Mitigation:** XChaCha20-Poly1305 AEAD ensures integrity. Any tampering causes decryption to fail on the client.

### 7. Dependency Compromise
- **Threat:** A library used by NullWarden is compromised.
- **Mitigation:** Pinned dependencies in `Cargo.lock`, `cargo-audit` and `cargo-deny` integrated into CI. Minimal dependency count.
