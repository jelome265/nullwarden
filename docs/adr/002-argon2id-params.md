# ADR-002: Argon2id for Key Derivation

## Status
Accepted

## Context
We need a key derivation function (KDF) to derive vault encryption keys from user-provided master passwords. The KDF must be resistant to both GPU/ASIC brute-force attacks and side-channel analysis.

## Decision
We chose Argon2id with tunable parameters.

## Rationale
- **Memory-Hard and Time-Hard:** Argon2id is the winner of the Password Hashing Competition (2015) and provides superior resistance to parallelized brute-force attacks compared to legacy KDFs like PBKDF2 or bcrypt.
- **Side-Channel Resistance:** The "id" variant combines the data-dependent memory access of Argon2d (resistant to GPU attacks) with the data-independent memory access of Argon2i (resistant to side-channel timing attacks).
- **Tunable:** Allows us to enforce a minimum computational latency (target ≥ 300ms) to make offline cracking economically unfeasible.

## Consequences
- Requires significant memory (64MB default) for key derivation.
- May be slow on extremely resource-constrained embedded devices.
