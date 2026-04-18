# ADR-001: XChaCha20-Poly1305 for Vault Encryption

## Status
Accepted

## Context
We need a robust authenticated encryption with associated data (AEAD) algorithm to protect vault contents. The primary requirements are high security at scale, resistance to nonce reuse, and performance across various hardware without requiring specialized instructions (like AES-NI).

## Decision
We chose XChaCha20-Poly1305.

## Rationale
- **192-bit Nonce:** Eliminates the practical risk of nonce collision when generating nonces randomly, even at extremely large scales. Standard ChaCha20 or AES-GCM (96-bit nonces) are more vulnerable to random collision.
- **Software Performance:** Chacha20 is designed for high performance in software-only implementations, unlike AES which relies heavily on hardware acceleration for both speed and timing-attack resistance.
- **Security:** Resistant to timing side-channels and has undergone significant public auditing (libsodium lineage).

## Consequences
- No hardware acceleration required for any target platform.
- Simplified nonce management.
- Incompatible with systems strictly requiring NIST-approved algorithms (like some FIPS environments).
