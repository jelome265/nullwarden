# Threat Model

- Server compromise must not reveal plaintext vault data.
- Offline brute force is mitigated with Argon2id.
- Ciphertext tampering is detected by XChaCha20-Poly1305 authentication.
