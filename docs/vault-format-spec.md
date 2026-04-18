# Vault Format Specification

## 1. Binary Layout

The vault file (`vault.nwd`) consists of a fixed-size header followed by an encrypted payload.

| Offset | Length | Field | Description |
|---|---|---|---|
| 0 | 4 | Magic | `0x4E 0x57 0x41 0x52` ("NWAR") |
| 4 | 1 | Version | Format version (currently `0x01`) |
| 5 | 4 | m_cost | Argon2id memory cost (KB) |
| 9 | 4 | t_cost | Argon2id time cost (passes) |
| 13 | 4 | p_cost | Argon2id parallelism cost |
| 17 | 32 | Salt | Random salt for KDF |
| 49 | 24 | Nonce | Random nonce for AEAD |
| 73 | ... | Payload | XChaCha20-Poly1305 ciphertext |

## 2. Serialization
- The plaintext payload is a MessagePack-encoded `VaultData` structure.
- MessagePack is used for compact binary serialization and canonical representation.

## 3. Atomic Updates
- Vault updates follow a "write-then-rename" strategy.
- A temporary file (`vault.nwd.tmp`) is written and fsync'd before being renamed to the target path.
- This ensures the vault is never in a partial or corrupted state on disk.

## 4. Integrity
- Integrity is provided by the Poly1305 MAC tag appended to the ciphertext.
- Decryption MUST fail if the authentication tag verification fails.
