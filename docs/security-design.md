# Security Design

## 1. Cryptography

### 1.1 Primitives
- **AEAD:** XChaCha20-Poly1305 (192-bit nonce).
- **KDF:** Argon2id (`m=65536`, `t=3`, `p=4`, `salt_len=32`).
- **Hashing:** Argon2id for auth passwords, SHA-256 for token blocklisting.

### 1.2 Key Derivation Flow
1. **Master Password** input by user.
2. **Salt** retrieved from vault header.
3. **Argon2id** derives 32-byte `VaultEncryptionKey`.
4. **Key** used once for encryption/decryption then zeroized.

### 1.3 Randomness
- All nonces and salts generated via `rand::rngs::OsRng` (CSPRNG).

## 2. Secret Management

### 2.1 Zeroization
- All sensitive types (`VaultEncryptionKey`, `SecretString`, `SecretBytes`) implement the `Zeroize` and `ZeroizeOnDrop` traits.
- Plaintext secrets are cleared from memory immediately after use.

### 2.2 Memory Safety
- Implemented in Rust to prevent memory corruption vulnerabilities.
- "Lock by exit" model minimizes the lifetime of secrets in RAM.

### 2.3 Constant-Time Operations
- Cryptographic comparisons and auth password verification use constant-time algorithms to prevent timing side-channel attacks.

## 3. Communication Security
- **TLS 1.3:** Enforced for all client-server communication.
- **JWT:** Used for session management with short lifetimes and mandatory refresh token rotation