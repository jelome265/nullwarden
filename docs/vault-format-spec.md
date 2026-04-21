# Vault Format Specification

## 1. Binary Layout

The vault file (`vault.nw`) consists of a fixed-size 73-byte header followed immediately by the encrypted payload.
There is no `payload_len` field in the on-disk format.

| Offset | Length | Field | Description |
|---|---|---|---|
| 0 | 4 | Magic | `0x4E 0x57 0x41 0x52` (`NWAR`) |
| 4 | 1 | Version | Format version, currently `0x01` |
| 5 | 4 | `m_cost` | Argon2id memory cost in KiB, little-endian `u32` |
| 9 | 4 | `t_cost` | Argon2id time cost, little-endian `u32` |
| 13 | 4 | `p_cost` | Argon2id parallelism, little-endian `u32` |
| 17 | 32 | Salt | Random per-vault salt |
| 49 | 24 | Nonce | XChaCha20-Poly1305 nonce |
| 73 | ... | Ciphertext | AEAD ciphertext plus authentication tag |

## 2. Serialization

- The plaintext payload is a MessagePack-encoded `VaultData` structure.
- The header is authenticated implicitly because decryption fails if any header-derived key or nonce input is tampered with.

## 3. Atomic Updates

- Vault updates use a write-temp, fsync, rename flow.
- On Unix, the parent directory is fsync'd after rename for stronger durability.

## 4. Integrity

- Integrity is provided by the Poly1305 tag appended to the ciphertext by XChaCha20-Poly1305.
- Decryption must fail if authentication fails or if the header version is unsupported.
