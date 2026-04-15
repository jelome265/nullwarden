# Vault Format Spec

Current prototype format:

- magic: `NWDN`
- version: `0x01`
- Argon2id params: `m_cost`, `t_cost`, `p_cost`
- salt: 32 bytes
- nonce: 24 bytes
- ciphertext: XChaCha20-Poly1305 payload containing MessagePack-encoded `VaultData`
