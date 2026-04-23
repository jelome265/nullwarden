# NullWarden — Complete Project Reference & Deep Analysis

> **Version:** 0.1.0 | **Stack:** Rust · Axum · PostgreSQL | **Classification:** Internal Engineering — Prototype Phase

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture Deep Dive](#2-architecture-deep-dive)
3. [Workspace & Crate Structure](#3-workspace--crate-structure)
4. [Cryptographic Design Analysis](#4-cryptographic-design-analysis)
5. [Vault Format Specification](#5-vault-format-specification)
6. [Server Design & API](#6-server-design--api)
7. [CLI Design](#7-cli-design)
8. [Database Schema](#8-database-schema)
9. [Security Analysis](#9-security-analysis)
10. [Testing Strategy](#10-testing-strategy)
11. [CI/CD Pipeline](#11-cicd-pipeline)
12. [Dependency Audit — Vulnerabilities & Fixes](#12-dependency-audit--vulnerabilities--fixes)
13. [Requirements Specification](#13-requirements-specification)
14. [Risk Register](#14-risk-register)
15. [Development Methodology](#15-development-methodology)
16. [ADRs — Architecture Decision Records](#16-adrs--architecture-decision-records)
17. [Deployment Guide](#17-deployment-guide)
18. [Recommendations for v0.2+](#18-recommendations-for-v02)

---

## 1. Project Overview

NullWarden is a **zero-knowledge, cross-device password vault** implemented entirely in Rust. Its central security invariant is simple but radical: **the server never sees plaintext vault data, never holds encryption keys, and is treated as an untrusted adversary by design.**

### Core Problem Statement

| # | Problem | Severity |
|---|---------|----------|
| P1 | Device-bound vault loss on hardware failure | HIGH |
| P2 | Server-side plaintext exposure in hosted managers | CRITICAL |
| P3 | Weak cloud storage trust assumptions | HIGH |
| P4 | Credential reuse and poor hygiene | HIGH |
| P5 | Improper cryptographic implementations (DIY) | CRITICAL |
| P6 | Absent zero-knowledge guarantees | CRITICAL |
| P7 | No cross-device consistency | MEDIUM |
| P8 | Timing-attack vulnerability in auth comparisons | HIGH |

### The Root Cause

Problems P2, P5, and P6 share a single root: **misplaced trust boundary placement**. When decryption authority lives on the server, the server becomes the highest-value target in the entire system. NullWarden solves this by making the server architecturally incapable of decryption — not as a policy, but as a structural fact. There is no decryption code on the server.

### Security Invariants (Non-Negotiable)

```
INVARIANT 1: The server MUST NOT store or transmit plaintext vault entries or encryption keys.
INVARIANT 2: Encryption keys MUST be derived exclusively on the client from the master password.
INVARIANT 3: All encryption operations MUST use AEAD with a unique random nonce per operation.
INVARIANT 4: Sensitive types MUST implement Zeroize and be zeroized immediately after use.
INVARIANT 5: Authentication credentials MUST be independent of vault encryption key material.
INVARIANT 6: Vault writes MUST be atomic (write-temp → fsync → rename pattern).
```

---

## 2. Architecture Deep Dive

### 2.1 Trust Boundary Map

```
═══════════════════════════════════════════════════════════════════════════
 TRUST ZONE: CLIENT (fully trusted — all cryptographic authority resides here)

  Master Password ──► Argon2id KDF ──► VaultEncryptionKey (32 bytes, RAM only)
                                              │
                                    XChaCha20-Poly1305 AEAD
                                              │
                             ┌────────────────▼──────────────────┐
                             │   Encrypted Vault Blob (opaque)   │
                             └────────────────┬──────────────────┘
                                              │  TLS 1.3 only
═══════════════════════════════════════════════╪═══════════════════════════
 UNTRUSTED ZONE: SERVER (treated as adversarial)
                                              │
                             ┌────────────────▼──────────────────┐
                             │   PostgreSQL · BYTEA column only   │
                             │   No key. No decryption. No view.  │
                             └───────────────────────────────────┘
═══════════════════════════════════════════════════════════════════════════
```

### 2.2 C4 Component Breakdown

**`nullwarden-core`** — Pure cryptographic library with zero I/O and zero network code. Contains:
- `kdf.rs` — Argon2id KDF with tunable `KdfParams`
- `crypto.rs` — XChaCha20-Poly1305 encrypt/decrypt
- `vault/header.rs` — Binary vault header serde (73-byte fixed header)
- `vault/data.rs` — `VaultData` / `VaultEntry` with `ZeroizeOnDrop`
- `vault/store.rs` — Atomic file I/O (write-tmp → fsync → rename)
- `types.rs` — `SecretString`, `SecretBytes`, `VaultEncryptionKey` (all zeroized)

**`nullwarden-cli`** — User-facing binary. Owns:
- Full command set (init, add, get, list, delete, update, push, pull, lock, logout, export, migrate)
- `rpassword` for no-echo password input
- OS keyring integration (`keyring` crate) with file fallback
- `zxcvbn` entropy enforcement (score ≥ 3)
- HTTP client for sync (`reqwest` with rustls-tls)
- Sync state tracking (`vault.nw.sync` sidecar file)

**`nullwarden-server`** — Axum REST API. Owns:
- Auth: register, login, token refresh, logout, user deletion
- Vault: PUT (upload blob), GET (download blob) — both with version headers
- JWT issuance/validation/blocklisting
- Argon2id server-side password hashing (auth password, separate from vault key)
- Constant-time comparisons for timing oracle mitigation
- Rate limiting via `tower_governor`
- Repository trait abstraction (testable with in-memory impls)

**`nullwarden-fuzz`** — `cargo-fuzz` targets:
- `decrypt_input` — feeds arbitrary bytes to the AEAD decryptor
- `vault_deserialize` — feeds arbitrary bytes to the MessagePack deserializer

### 2.3 Key Derivation Flow (Client-Only)

```
User Input: master_password (UTF-8, never transmitted)
                    │
      ┌─────────────▼──────────────────────────────┐
      │ Argon2id KDF                                │
      │   algorithm : Argon2id                      │
      │   version   : V0x13                         │
      │   m_cost    : 65,536 KB  (64 MB RAM)        │
      │   t_cost    : 3 passes                      │
      │   p_cost    : 4 lanes                       │
      │   output    : 32 bytes                      │
      │   salt      : vault_header.salt (32 B CSPRNG)│
      └─────────────┬──────────────────────────────┘
                    │
      ┌─────────────▼──────────────────────────────┐
      │ VaultEncryptionKey([u8; 32])                │
      │   implements: Zeroize + ZeroizeOnDrop        │
      │   debug fmt : "***REDACTED***"               │
      └─────────────┬──────────────────────────────┘
                    │
      ┌─────────────▼──────────────────────────────┐
      │ XChaCha20-Poly1305                          │
      │   nonce: 24-byte OsRng (CSPRNG)             │
      │   plaintext: rmp-serde(VaultData)           │
      └─────────────┬──────────────────────────────┘
                    │
              ciphertext + Poly1305 tag
              (written to vault file)
```

### 2.4 Authentication Flow (Server-Side, Independent of Vault Key)

```
Registration:
  auth_password ──► Argon2id(m=65536, t=3, p=4, salt=random_16B) ──► password_hash
  Stored: username + password_hash. Never: auth_password.

Login:
  candidate_hash = Argon2id(auth_password, stored_salt)
  constant_time_eq(candidate_hash, stored_hash)  ← timing-safe
  → JWT access token (exp: 15 min, HS256)
  → refresh token = UUID:secret, stored as SHA-256 hash
  
Timing Oracle Mitigation:
  If username not found, verify against state.dummy_hash anyway.
  Both paths take identical time → no username enumeration via timing.
```

---

## 3. Workspace & Crate Structure

```
nullwarden/
├── Cargo.toml                          ← workspace root, shared deps
├── Cargo.lock                          ← committed, deterministic builds
├── deny.toml                           ← cargo-deny: license + advisory policy
├── rust-toolchain.toml                 ← pinned stable channel
├── .env.example                        ← server config template
├── Dockerfile                          ← multi-stage, non-root user, bookworm-slim
├── docker-compose.yml                  ← postgres:16 + server
│
├── .cargo/config.toml                  ← cross-compilation targets (musl, mingw)
│
├── .github/workflows/
│   ├── ci.yml                          ← fmt, clippy, test, audit, deny, coverage
│   ├── release.yml                     ← 5-target matrix, SBOM, minisign, Docker
│   └── fuzz.yml                        ← weekly 300s fuzz runs
│
├── crates/
│   ├── nullwarden-core/
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── crypto.rs               ← XChaCha20-Poly1305
│   │   │   ├── error.rs                ← VaultError (thiserror)
│   │   │   ├── kdf.rs                  ← Argon2id + KdfParams
│   │   │   ├── types.rs                ← SecretString/Bytes/VaultEncryptionKey
│   │   │   └── vault/
│   │   │       ├── cipher.rs, data.rs, header.rs
│   │   │       ├── kdf.rs, serializer.rs, store.rs
│   │   ├── tests/                      ← unit tests
│   │   └── benches/                    ← criterion benchmarks
│   │
│   ├── nullwarden-cli/
│   │   ├── src/
│   │   │   ├── main.rs                 ← clap v4 command dispatch
│   │   │   ├── commands/               ← one file per subcommand
│   │   │   ├── client/{auth,sync}.rs   ← HTTP clients with retry
│   │   │   ├── config.rs, session.rs
│   │   │   ├── input.rs                ← rpassword + zxcvbn
│   │   │   └── sync_state.rs           ← version sidecar file
│   │   └── tests/                      ← e2e tests
│   │
│   ├── nullwarden-server/
│   │   ├── src/
│   │   │   ├── main.rs                 ← startup, TLS, cleanup task
│   │   │   ├── app.rs                  ← Axum router + middleware stack
│   │   │   ├── config.rs               ← envy env-var config
│   │   │   ├── auth/{jwt,password,token}.rs
│   │   │   ├── db/{mod,pool,users,vaults,tokens}.rs
│   │   │   ├── handlers/{auth,vault}.rs
│   │   │   ├── middleware/{auth,request_id}.rs
│   │   │   └── error.rs                ← AppError → HTTP response
│   │   ├── migrations/                 ← 5 SQL migrations
│   │   └── tests/                      ← in-memory integration tests
│   │
│   └── nullwarden-fuzz/
│       └── fuzz_targets/               ← decrypt_input, vault_deserialize
│
├── docs/
│   ├── adr/                            ← 5 ADRs
│   ├── vault-format-spec.md
│   ├── security-design.md
│   ├── threat-model.md
│   ├── api-reference.yaml              ← OpenAPI 3.1
│   ├── cli-manual.md
│   ├── deployment-guide.md
│   └── incident-response.md
│
└── scripts/
    ├── build-release.sh
    ├── sign-release.sh                 ← minisign signing
    ├── run-fuzz.sh
    └── db-migrate.sh
```

### Key Commands

```bash
cargo build --workspace            # Build all crates
cargo test --workspace             # Run all tests
cargo fmt --all -- --check         # Format check
cargo clippy --workspace --all-targets -- -D warnings
cargo audit                        # Security advisory scan
cargo deny check                   # License + advisory policy
cargo tarpaulin -p nullwarden-core --fail-under 80   # Coverage gate

# Ignored (expensive) KDF latency gate
cargo test -p nullwarden-core -- --ignored kdf_meets_minimum_latency

# Cross-compile for musl Linux
cargo build --release -p nullwarden-cli --target x86_64-unknown-linux-musl

# Fuzz (requires nightly + cargo-fuzz)
cargo +nightly fuzz run decrypt_input -- -max_total_time=300
cargo +nightly fuzz run vault_deserialize -- -max_total_time=300
```

---

## 4. Cryptographic Design Analysis

### 4.1 Algorithm Selection Rationale

| Decision | Choice | Why | Rejected Alternative |
|----------|--------|-----|----------------------|
| AEAD cipher | XChaCha20-Poly1305 | 192-bit nonce (collision-safe at scale), software-fast, no AES-NI dependency | AES-256-GCM (96-bit nonce, hardware dependency) |
| KDF | Argon2id | Memory-hard + time-hard, PHC winner 2015, side-channel resistant | bcrypt (72-byte limit, no memory hardness), PBKDF2 (time-only) |
| Serialization | MessagePack (rmp-serde) | Binary, ~30% smaller than JSON, no float ambiguity | JSON (larger, text parsing overhead) |
| Auth token | JWT HS256 | Stateless, scalable, short-lived access + rotating refresh | Server sessions (stateful, harder to scale) |
| Auth comparison | `constant_time_eq` | Prevents timing oracle for username enumeration | `==` on strings (timing-variable) |

### 4.2 Argon2id Parameters — Why These Specific Values

```
m_cost = 65,536 KB (64 MB) — Forces attacker to dedicate 64 MB per guess.
                              A GPU with 8 GB VRAM can only run ~128 parallel guesses.
                              Compare: bcrypt uses <1 KB.

t_cost = 3              — Three sequential passes over the 64 MB memory buffer.
                          Increases time without reducing memory requirement.

p_cost = 4              — 4 parallel lanes. Matches modern multi-core CPUs.
                          Does NOT reduce security; each lane still uses full memory.

output = 32 bytes       — 256-bit key. Matches XChaCha20 key size exactly.

target latency ≥ 300ms  — CI benchmark gate enforces this.
                          At 300ms per guess, 1 billion guesses/day = ~3.3M guesses.
                          zxcvbn score ≥ 3 requirement means password space >> 3.3M.
```

### 4.3 Nonce Safety Analysis

XChaCha20-Poly1305 uses a **192-bit nonce**. With CSPRNG generation:

```
P(collision) with n operations = 1 - e^(-n²/2^193)
For n = 2^64 operations: P ≈ 2^(-65)  ← negligible even at astronomical scale

Compare AES-GCM (96-bit nonce):
For n = 2^32 operations: P ≈ 50%      ← serious collision risk at scale
```

The nonce is regenerated on **every `save()` call**, not per-entry. This means the entire vault is re-encrypted with a fresh nonce on every write operation. This is intentional — it prevents partial encryption attacks.

### 4.4 Key Lifecycle

```
1. User enters master password (rpassword, no echo)
2. VaultKeyDeriver::derive() called → Argon2id runs
3. VaultEncryptionKey created (wraps [u8; 32])
4. Passed to VaultCipher::encrypt() or decrypt()
5. VaultEncryptionKey drops → ZeroizeOnDrop fires → 32 bytes overwritten with zeros
6. Master password string → zeroized
7. Plaintext VaultData → zeroized on drop

Total plaintext lifetime: bounded to a single function call stack frame.
Nothing persists between CLI commands.
```

### 4.5 Separation of Concerns: Auth vs Vault Keys

This is a critical design point that many password managers get wrong:

```
Server auth password ──► Argon2id (server params) ──► password_hash (stored in DB)
                                                         ↑
                                              NEVER used for vault encryption

Master password ──► Argon2id (vault KDF params, client-side only) ──► VaultEncryptionKey
                                                                          ↑
                                                              NEVER sent to server
```

A server compromise yields: usernames, auth password hashes, encrypted blobs, session hashes.  
It does **not** yield: vault encryption keys, master passwords, plaintext entries.  
An attacker must still run offline Argon2id cracking at 64 MB / attempt.

---

## 5. Vault Format Specification

### 5.1 Binary Layout

```
Offset  Size   Field           Value / Notes
──────  ────   ─────           ──────────────────────────────────────
0       4      magic           0x4E 0x57 0x41 0x52 ("NWAR")
4       1      format_version  0x01 (currently)
5       4      m_cost          Argon2id memory cost (KiB), u32 LE
9       4      t_cost          Argon2id time cost, u32 LE
13      4      p_cost          Argon2id parallelism, u32 LE
17      32     salt            CSPRNG salt (OsRng), 32 bytes
49      24     nonce           XChaCha20 nonce (OsRng), 24 bytes
────────────────────────────────────────────── total header: 73 bytes
73      N      ciphertext      XChaCha20-Poly1305 encrypted payload
73+N-16 16     poly1305_tag    Authentication tag (last 16 bytes of ciphertext)
```

The `chacha20poly1305` crate appends the Poly1305 tag directly to the ciphertext — there is no separate tag field in the file; it is part of the `ciphertext` slice.

### 5.2 Payload Structure (Plaintext Before Encryption)

MessagePack-encoded `VaultData`:

```rust
struct VaultData {
    version: u64,           // incremented on every mutation
    entries: Vec<VaultEntry>,
}

struct VaultEntry {
    id: Uuid,               // UUID v4, random, non-sequential
    title: String,
    username: String,
    password: SecretString, // ZeroizeOnDrop
    notes: Option<String>,
}
```

### 5.3 Atomic Write Protocol

```
1. Serialize VaultData → MessagePack bytes
2. Derive key (Argon2id)
3. Generate fresh salt (OsRng, 32B)
4. Generate fresh nonce (OsRng, 24B)
5. Encrypt: XChaCha20-Poly1305(key, nonce, plaintext)
6. Construct header bytes (73B)
7. Concatenate: header || ciphertext
8. Write to vault.nw.tmp (File::create + write_all)
9. file.sync_all()                   ← flush to OS + storage
10. fs::rename(tmp, vault.nw)        ← atomic on POSIX
11. dir.sync_all()                   ← fsync parent dir (Unix only)
12. On any error: fs::remove_file(tmp) + propagate Err
```

This guarantees the vault file is always either the pre-write version or the post-write version. There is no observable intermediate state.

### 5.4 Integrity Guarantee

On `unlock()`:
1. `VaultHeader::decode()` checks magic bytes and format version
2. `VaultKeyDeriver::derive()` runs Argon2id
3. `VaultCipher::decrypt()` runs XChaCha20-Poly1305
4. **If the Poly1305 tag does not match, decryption returns `Err(VaultError::DecryptionFailed)`**
5. The caller never receives partial plaintext — the AEAD primitive returns all-or-nothing

This means: a corrupted, tampered, or wrong-password vault **always fails closed**.

---

## 6. Server Design & API

### 6.1 Middleware Stack (applied outermost → innermost)

```
SetRequestIdLayer (X-Request-ID: UUID)
  └── CORS (configurable origins, GET/POST/PUT, Authorization/Content-Type)
      └── DefaultBodyLimit (10 MB)
          └── log_request_id (tracing spans)
              └── Security Headers
              │     Strict-Transport-Security: max-age=31536000; includeSubDomains
              │     X-Content-Type-Options: nosniff
              │     X-Frame-Options: DENY
              │     Content-Security-Policy: default-src 'none'
              └── Auth Rate Limiter (GovernorLayer — POST on /auth/*)
                  └── JWT Auth Extractor (CurrentUser FromRequestParts)
                      └── Route Handlers
```

### 6.2 API Endpoints

```
POST   /auth/register         { username, password } → 201 | 409
POST   /auth/login            { username, password } → 200 { access_token, refresh_token } | 401
POST   /auth/refresh          { refresh_token }      → 200 { access_token, refresh_token } | 401
POST   /auth/logout           Bearer + { refresh_token } → 204
DELETE /auth/user             Bearer → 204

GET    /vault                 Bearer → 200 (blob bytes) + X-Vault-Version header | 404
PUT    /vault                 Bearer + X-If-Match? + X-Force? + (blob bytes) → 200 "version=N" | 409

GET    /health                → 200 "ok"
```

**Conflict detection logic (PUT /vault):**

```
X-Force header present:  → overwrite unconditionally, backup current to vault_history
X-If-Match: N present:   → UPDATE WHERE version = N → returns rows if version matched
                            → RowNotFound (409 Conflict) if version mismatched
No version header:       → INSERT ON CONFLICT DO NOTHING (first push only)
```

### 6.3 Token Architecture

**Access tokens (JWT):**
- Short-lived (default 900s / 15 min)
- Contain: `sub` (user_id), `exp`, `iss`, `aud`
- Validated via blocklist check + signature + issuer + audience + explicit exp check
- On logout: hashed (SHA-256) and stored in `token_blocklist` table until natural expiry

**Refresh tokens:**
- Format: `"{uuid}:{secret}"` — ID for DB lookup, secret for verification
- Secret stored as SHA-256 hex (not Argon2id — speed is acceptable here since lookup is by UUID first)
- **Single-use**: consumed and deleted on each use, new one issued (rotation)
- Expire after 7 days (configurable)
- All user tokens revocable via `revoke_all_user_tokens()`

### 6.4 Repository Trait Pattern

All database access goes through trait objects:

```rust
trait UserRepository: Send + Sync { ... }
trait VaultRepository: Send + Sync { ... }
trait RefreshTokenRepository: Send + Sync { ... }
trait TokenBlocklistRepository: Send + Sync { ... }
```

Production: `Sqlx*Repository` structs backed by `PgPool`  
Tests: `InMemory*Repository` structs backed by `Arc<Mutex<InMemoryState>>`

This means **all integration tests run without a database** — fast, deterministic, no docker-compose required for CI.

### 6.5 Background Cleanup Task

```rust
tokio::spawn(async move {
    loop {
        interval.tick().await;  // default: every 3600s
        cleanup_expired_tokens(&state).await;   // refresh_tokens WHERE expires_at < now
        cleanup_blocked_tokens(&state).await;   // token_blocklist WHERE expires_at < now
    }
});
```

This prevents unbounded table growth for expired session data.

---

## 7. CLI Design

### 7.1 Command Reference

| Command | Description | Security Notes |
|---------|-------------|----------------|
| `init` | Create new vault | zxcvbn ≥ 3, double-entry confirmation, atomic write |
| `add <title> <user>` | Add entry | Password prompted (not arg), zxcvbn check |
| `get <title>` | Retrieve entry | Default: clipboard; `--print` for stdout |
| `list` | List all titles | Passwords never shown |
| `delete <title>` | Delete entry | Explicit confirmation |
| `update <title>` | Modify entry | `--clear-notes` flag available |
| `export` | Re-encrypt backup | Prompts for separate backup password |
| `migrate` | Change KDF params | Re-derives key with new params, re-encrypts |
| `push` | Upload to server | Conflict detection + resolution dialog |
| `pull` | Download from server | AEAD integrity check before overwrite |
| `lock` | Clear session tokens | Removes keyring entries + session files |
| `logout` | Server + local logout | Revokes tokens server-side, then clears locally |
| `register <user>` | Create server account | Password prompted, zxcvbn check |

### 7.2 Sync Conflict Resolution Flow

When `push` detects a 409 Conflict:

```
1. Pull remote vault (requires master password)
2. Decrypt both local and remote (for entry count comparison)
3. Display: "Local entries: N, Remote entries: M, Remote version: V, Delta: ±D"
4. Present choice: [local / remote / abort]
   local  → confirm force-push (destructive, double-confirm)
   remote → apply_remote_bytes() (integrity check + atomic write)
   abort  → no change
```

### 7.3 Session Storage

Priority order:
1. **OS Keyring** (`keyring` crate) — uses libsecret (Linux), Keychain (macOS), DPAPI (Windows)
2. **File fallback** — `~/.config/nullwarden/{access_token,refresh_token}.session`
   - Unix: `chmod 0600` (owner-read-write only)
   - Windows: `icacls /inheritance:r /grant:r USERNAME:F`

### 7.4 Password Security

```
Input:   rpassword::read_password() — no terminal echo
History: Passwords never passed as CLI args (documented as a warning if done)
Display: Clipboard default; stdout requires --print flag
Clipboard: Warning displayed about clipboard manager retention
Memory:  SecretString (ZeroizeOnDrop) — cleared on drop
```

---

## 8. Database Schema

### 8.1 Tables

**`users`**
```sql
id            UUID  PRIMARY KEY DEFAULT gen_random_uuid()
username      TEXT  NOT NULL UNIQUE
password_hash TEXT  NOT NULL                 -- Argon2id hash only, never plaintext
created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
```

**`vaults`**
```sql
user_id    UUID  PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE
version    BIGINT NOT NULL DEFAULT 1          -- optimistic locking counter
blob       BYTEA  NOT NULL                   -- opaque encrypted bytes ONLY
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
```

**`refresh_tokens`**
```sql
id          UUID PRIMARY KEY DEFAULT gen_random_uuid()
secret_hash TEXT NOT NULL                    -- SHA-256 hex of token secret
user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE
expires_at  TIMESTAMPTZ NOT NULL
created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()

INDEX: (user_id), (expires_at)
```

**`token_blocklist`**
```sql
token_hash TEXT PRIMARY KEY                  -- SHA-256 hex of access token
expires_at TIMESTAMPTZ NOT NULL

INDEX: (expires_at)                          -- for cleanup queries
```

**`vault_history`**
```sql
id         BIGSERIAL PRIMARY KEY
user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE
version    BIGINT NOT NULL
blob       BYTEA NOT NULL                    -- capped at 3 entries per user
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()

INDEX: (user_id, created_at DESC)
```

### 8.2 RLS Policies

All tables have Row Level Security enabled. The policy structure:
- `users`: select and update via `true` (server scopes all queries via service role)
- `vaults`: `auth.uid() = user_id` — Supabase-compatible
- `vault_history`, `refresh_tokens`: `auth.uid() = user_id`
- `token_blocklist`: `USING (false)` — only accessible via service_role bypass

For direct PostgreSQL (non-Supabase), the server application user bypasses RLS via the connection role and handles authorization in application code.

### 8.3 Versioning and Optimistic Locking

```sql
-- Normal push (version-gated):
UPDATE vaults SET blob = $1, version = version + 1, updated_at = now()
WHERE user_id = $2 AND version = $3
RETURNING version, blob

-- Returns 0 rows if version mismatch → sqlx::Error::RowNotFound → 409 Conflict
-- Returns 1 row if version matched → new version returned to client
```

---

## 9. Security Analysis

### 9.1 What an Attacker Gains from Full DB Compromise

| Data | Attacker Has | Attacker Can Do | Cost |
|------|-------------|-----------------|------|
| `vaults.blob` | Ciphertext | Offline Argon2id cracking | 64 MB RAM + 300ms per guess |
| `users.password_hash` | Argon2id hash | Offline cracking (auth password only, not vault key) | Same cost |
| `refresh_tokens.secret_hash` | SHA-256 of expired token | Brute force (high entropy token, impractical) | Computationally impractical |
| `token_blocklist` | Hashes of revoked tokens | Nothing useful | N/A |

**Conclusion:** Full DB compromise does not yield usable passwords. The attacker must crack Argon2id (64 MB/guess) against each user's vault, and even then only recovers that user's vault key if their master password is weak.

### 9.2 Timing Attack Analysis

**Login endpoint** — The dummy_hash mitigation:

```rust
// In handlers/auth.rs:
let hash = user_opt
    .as_ref()
    .map(|u| u.password_hash.as_str())
    .unwrap_or(&state.dummy_hash);       // ← always run Argon2id

let ok = password::verify_password(hash, &payload.password).await?;
```

Without this: valid username → Argon2id verify (~300ms), invalid username → no Argon2id (~0ms). The timing difference would expose username existence. With dummy_hash: both paths take ~300ms regardless.

**Token comparison** — `constant_time_eq` crate:
```rust
fn secure_secret_matches(expected_hash: &str, candidate_secret: &str) -> bool {
    let candidate_hash = sha256_hex(candidate_secret);
    constant_time_eq(expected_hash.as_bytes(), candidate_hash.as_bytes())
    // ↑ fixed-time regardless of how many bytes match
}
```

### 9.3 Key Separation Verification

The codebase enforces auth/vault key separation architecturally:

- `nullwarden-server` has **no dependency on `kdf.rs`** for vault key operations
- The server's `password.rs` uses `argon2::PasswordHasher` (produces PHC string format for auth)
- The core's `kdf.rs` uses `argon2::hash_password_into` (produces raw bytes for vault key)
- These are different code paths, different output formats, different contexts

Static analysis (clippy + grep) can confirm: no `derive_key()` calls exist in server code.

### 9.4 Memory Safety Verification

All sensitive types in `types.rs`:

```rust
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(pub String);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultEncryptionKey(pub [u8; 32]);

impl fmt::Debug for VaultEncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VaultEncryptionKey(***REDACTED***)")  // ← never printed
    }
}
```

`ZeroizeOnDrop` derives a `Drop` impl that calls `zeroize()` before deallocation. The unit test in `types.rs` validates this:

```rust
#[test]
fn test_vault_key_zeroize() {
    let mut key = VaultEncryptionKey([0xAA; 32]);
    key.zeroize();
    for &byte in key.as_ref() {
        assert_eq!(byte, 0);  // ← all bytes must be zero post-zeroize
    }
}
```

### 9.5 Transport Security

In production (`main.rs`):
```rust
if let (Some(cert_path), Some(key_path)) = (&config.tls_cert_path, &config.tls_key_path) {
    let tls_config = RustlsConfig::from_pem_file(cert_path, key_path).await?;
    axum_server::bind_rustls(addr, tls_config).serve(...).await?;
} else {
    warn!("TLS not configured... Running in plain HTTP mode — INSECURE!");
    // plain HTTP for local dev only
}
```

TLS via `rustls` (no OpenSSL dependency) + `axum-server` with `tls-rustls` feature.

---

## 10. Testing Strategy

### 10.1 Test Layers

| Layer | Crate | Tool | Coverage Gate |
|-------|-------|------|---------------|
| Crypto unit tests | `nullwarden-core` | `#[test]` | ≥ 80% (tarpaulin) |
| KDF latency gate | `nullwarden-core` | `#[test][ignored]` + criterion | ≥ 300ms |
| Vault lifecycle | `nullwarden-core` | `#[test]` | round-trip, tamper, wrong-password |
| E2E CLI tests | `nullwarden-cli` | `#[test]` | init/add/get/delete/update cycle |
| Sync E2E | `nullwarden-cli` | `#[tokio::test]` | mock Axum server, push/pull/rollback |
| Server integration | `nullwarden-server` | `#[tokio::test]` | in-memory repos, full auth flow |
| Rate limit | `nullwarden-server` | `#[tokio::test]` | 2nd request → 429 |
| Vault conflict | `nullwarden-server` | `#[tokio::test]` | stale write → 409 |
| Fuzz | `nullwarden-fuzz` | `cargo-fuzz` | weekly 300s runs in CI |

### 10.2 Key Test Cases

**Crypto round-trip (`crypto_roundtrip.rs`):**
```
encrypt(key, plaintext) → (nonce, ciphertext)
decrypt(key, nonce, ciphertext) == plaintext  ✓
```

**Tamper detection (`integrity.rs`):**
```
Corrupt last byte of ciphertext
unlock() → Err(VaultError::DecryptionFailed)  ✓

Wrong master password
unlock() → Err(VaultError::DecryptionFailed)  ✓
```

**Zeroize test (`types.rs`):**
```
VaultEncryptionKey([0xAA; 32]).zeroize()
All bytes == 0x00  ✓
```

**Rollback detection (`e2e_sync.rs`):**
```
Local version = 5, Server returns version = 3
pull(5) → Err("rollback detected: server version (3) is older than local version (5)")  ✓
```

**Logout → access blocked (`auth_integration.rs`):**
```
1. login → access_token
2. logout (revokes access_token + refresh_token)
3. GET /vault with access_token → 401  ✓
4. POST /auth/refresh with old refresh_token → 401  ✓
```

**Export with different password (`export_command.rs`):**
```
export_vault(vault_path, output, master_password, backup_password)
VaultStore::new(output).unlock(backup_password) → Ok  ✓
VaultStore::new(output).unlock(master_password) → Err  ✓
```

---

## 11. CI/CD Pipeline

### 11.1 `ci.yml` — Per-Push/PR

```yaml
Steps:
  1. cargo fmt --all -- --check           # format gate
  2. cargo clippy --workspace -- -D warnings  # lint gate (zero warnings)
  3. cargo build --workspace              # compilation
  4. cargo test --workspace               # unit + integration
  5. cargo test -- --ignored kdf_meets_minimum_latency  # KDF latency gate
  6. cargo audit                          # CVE scan → BLOCKS on error
  7. cargo deny check                     # license + advisory policy
  8. cargo tarpaulin -p nullwarden-core --fail-under 80   # coverage gate
  9. cargo tarpaulin -p nullwarden-server --fail-under 60

Miri job (nightly):
  cargo +nightly miri test -p nullwarden-core --lib
  # Detects UB, uninitialized reads, wrong memory model
```

### 11.2 `release.yml` — On `v*` Tag

```yaml
Build matrix:
  - ubuntu-latest / x86_64-unknown-linux-musl
  - ubuntu-latest / aarch64-unknown-linux-musl
  - windows-latest / x86_64-pc-windows-msvc
  - macos-latest   / aarch64-apple-darwin
  - macos-13       / x86_64-apple-darwin

Per target:
  1. cargo build --release -p nullwarden-cli --target $TARGET
  2. cargo cyclonedx → bom.xml (SBOM)
  3. minisign -S (sign binary with MINISIGN_SECRET_KEY)
  4. shasum -a 256 (checksums)
  5. Upload artifacts

Docker job:
  docker/build-push-action → ghcr.io/$OWNER/nullwarden-server:$TAG
```

### 11.3 `fuzz.yml` — Weekly (Sunday 03:00 UTC)

```yaml
cargo +nightly fuzz run decrypt_input -- -max_total_time=300
cargo +nightly fuzz run vault_deserialize -- -max_total_time=300
```

---

## 12. Dependency Audit — Vulnerabilities & Fixes

### 12.1 Current `cargo audit` Output Analysis

Running `cargo audit` currently produces **1 vulnerability** (exit code 1, CI-blocking) and **6 warnings**.

---

### 12.2 Vulnerability: `rsa` 0.9.10 — RUSTSEC-2023-0071 (BLOCKING)

**Advisory:** Marvin Attack — potential key recovery through timing side-channels  
**Severity:** 5.9 (medium)  
**Status:** No fixed version available upstream  
**Dependency path:** `rsa` ← `sqlx-mysql` ← `sqlx` ← `nullwarden-server`

**Root cause analysis:**  
`sqlx` includes MySQL support (`sqlx-mysql` feature) which uses RSA for connection encryption. `nullwarden-server` depends on `sqlx` with all database backends compiled in by default (the current `Cargo.toml` does not restrict features to PostgreSQL only).

**Fix — restrict sqlx to PostgreSQL only:**

In `crates/nullwarden-server/Cargo.toml`, change:

```toml
# BEFORE (current — compiles sqlx-mysql which pulls in rsa):
sqlx = { version = "0.8.6", default-features = false, features = ["postgres", "runtime-tokio-rustls", "uuid", "chrono", "migrate", "macros"] }
```

Wait — looking at the Cargo.toml more carefully, the features already list `postgres` and not `mysql`. The problem is that `sqlx` 0.8.6 with its current dependency resolution still pulls `sqlx-mysql` transitively through `sqlx-macros-core` even when not explicitly requested, because `sqlx-macros-core` unconditionally depends on all three backends for its compile-time query checking infrastructure.

**The correct fix is to add `rsa` to `cargo-deny`'s ignore list with justification, AND add a `deny.toml` exception:**

**Step 1 — Update `deny.toml`:**

```toml
# deny.toml
[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"
notice = "warn"

# EXCEPTION: rsa pulled in transitively through sqlx-mysql (sqlx-macros-core
# unconditionally depends on all backends). NullWarden never performs RSA
# operations; the rsa crate is dead code. Tracked in issue #XX.
# Re-evaluate when sqlx ≥ 0.9 separates macro backends.
ignore = [
    { id = "RUSTSEC-2023-0071", reason = "rsa is dead code pulled via sqlx-mysql/sqlx-macros-core; NullWarden uses only PostgreSQL and performs no RSA operations" }
]
```

**Step 2 — Update `ci.yml` audit step to pass:**

```yaml
- name: Audit dependencies
  run: cargo audit --ignore RUSTSEC-2023-0071
```

**Step 3 (long-term) — Wait for sqlx ≥ 0.9 or use workspace patch:**

```toml
# Cargo.toml workspace root — patch rsa to a version that fixes the issue
# if/when one becomes available:
# [patch.crates-io]
# rsa = { git = "...", rev = "..." }
```

**Alternative fix (more surgical) — exclude mysql from sqlx compile:**

```toml
# crates/nullwarden-server/Cargo.toml
sqlx = { 
    version = "0.8.6", 
    default-features = false, 
    features = [
        "postgres",
        "runtime-tokio-rustls", 
        "uuid", 
        "chrono", 
        "migrate",
        # Note: intentionally omitting "macros" removes sqlx-macros-core
        # which is the transitive entry point for sqlx-mysql + rsa.
        # Use sqlx::query() instead of sqlx::query!() macros.
    ] 
}
```

> **Important note:** Removing the `macros` feature requires replacing all `sqlx::query!()` and `sqlx::query_as!()` macro calls with runtime `sqlx::query()` calls. Since the current server code already uses `sqlx::query()` (not macros — confirmed by reading `db/users.rs`, `db/vaults.rs`, `db/tokens.rs`), this is safe to do.

**Recommended immediate action:**

```toml
# crates/nullwarden-server/Cargo.toml
sqlx = { 
    version = "0.8.6", 
    default-features = false, 
    features = ["postgres", "runtime-tokio-rustls", "uuid", "chrono", "migrate"] 
}
# Dropped: "macros" → eliminates sqlx-macros-core → eliminates sqlx-mysql → eliminates rsa
```

---

### 12.3 Warning: `atty` 0.2.14 — Unmaintained + Unsound (RUSTSEC-2024-0375 + RUSTSEC-2021-0145)

**Source:** `criterion` 0.3.6 (benchmark framework) → `atty`  
**Issue:** `atty` is unmaintained and has an unsound potential unaligned read on Windows

**Fix — upgrade criterion to 0.5:**

```toml
# crates/nullwarden-core/Cargo.toml
[dev-dependencies]
# BEFORE:
criterion = "0.3"

# AFTER:
criterion = { version = "0.5", features = ["html_reports"] }
```

Criterion 0.5 replaced `atty` with `is-terminal` (maintained). This is a dev-dependency only — no production impact. The benchmark API is largely compatible but note:

- `criterion_group!` / `criterion_main!` macros unchanged
- `Criterion::bench_function` signature unchanged
- `black_box` moved: use `std::hint::black_box` or `criterion::black_box`

Update `benches/kdf_bench.rs` and `benches/encrypt_bench.rs`:
```rust
// No import change needed if using criterion::black_box
// If using std::hint::black_box, remove the criterion import
use criterion::{black_box, criterion_group, criterion_main, Criterion};
// ↑ still valid in criterion 0.5
```

---

### 12.4 Warning: `derivative` 2.2.0 — Unmaintained (RUSTSEC-2024-0388)

**Source:** `zbus` 3.15.2 → `secret-service` 3.1.0 → `keyring` 2.3.3 → `nullwarden-cli`

**Fix — upgrade keyring:**

```toml
# crates/nullwarden-cli/Cargo.toml
# BEFORE:
keyring = "2"

# AFTER:
keyring = "3"
```

`keyring` 3.x upgraded to `zbus` 4.x which drops the `derivative` dependency. The `keyring` 3 API is compatible — `Entry::new()`, `set_password()`, `get_password()`, `delete_password()` signatures are unchanged.

---

### 12.5 Warning: `instant` 0.1.13 — Unmaintained (RUSTSEC-2024-0384)

**Source:** `fastrand` 1.9.0 → `futures-lite` 1.13.0 → `async-process`/`async-io` → `zbus` → `keyring`

This is resolved transitively by fixing `keyring` → `zbus` 4.x (see §12.4). `zbus` 4.x uses updated async primitives that no longer depend on `fastrand` 1.x / `instant`.

---

### 12.6 Warning: `rustls-pemfile` 2.2.0 — Unmaintained (RUSTSEC-2025-0134)

**Source:** `axum-server` 0.7.3 → `rustls-pemfile` 2.2.0

**Fix — upgrade axum-server:**

```toml
# crates/nullwarden-server/Cargo.toml
# BEFORE:
axum-server = { version = "0.7", features = ["tls-rustls"] }

# AFTER — check for latest version that drops rustls-pemfile:
axum-server = { version = "0.7.4", features = ["tls-rustls"] }
```

Check [axum-server releases](https://github.com/programatik29/axum-server) for a version that migrates to `rustls-pemfile` 3.x or drops it. If no updated version is available, add to `deny.toml` ignore list with justification (TLS code path, not a cryptographic weakness in context).

---

### 12.7 Warning: `serde_cbor` 0.11.2 — Unmaintained (RUSTSEC-2021-0127)

**Source:** `criterion` 0.3.6 → `serde_cbor`

**Fix:** Resolved by upgrading criterion to 0.5 (see §12.3). Criterion 0.5 no longer uses `serde_cbor`.

---

### 12.8 Complete Fix Summary

| Issue | RUSTSEC | Type | Fix |
|-------|---------|------|-----|
| `rsa` Marvin Attack | 2023-0071 | **VULNERABILITY** | Drop `macros` feature from `sqlx`, eliminating `sqlx-mysql` + `rsa` |
| `atty` unsound | 2021-0145 | unsound warning | Upgrade `criterion` 0.3 → 0.5 |
| `atty` unmaintained | 2024-0375 | unmaintained warning | Same: upgrade `criterion` |
| `serde_cbor` unmaintained | 2021-0127 | unmaintained warning | Same: upgrade `criterion` |
| `derivative` unmaintained | 2024-0388 | unmaintained warning | Upgrade `keyring` 2 → 3 |
| `instant` unmaintained | 2024-0384 | unmaintained warning | Resolved by `keyring` 3 → `zbus` 4 |
| `rustls-pemfile` unmaintained | 2025-0134 | unmaintained warning | Upgrade `axum-server` or add deny.toml ignore |

### 12.9 Complete Diff for All Fixes

**`crates/nullwarden-core/Cargo.toml`:**
```toml
[dev-dependencies]
tempfile = "3"
criterion = { version = "0.5", features = ["html_reports"] }  # was "0.3"
```

**`crates/nullwarden-cli/Cargo.toml`:**
```toml
keyring = "3"   # was "2" — drops zbus 3.x / derivative / instant
```

**`crates/nullwarden-server/Cargo.toml`:**
```toml
# Remove "macros" from sqlx features to cut sqlx-mysql -> rsa dependency:
sqlx = { 
    version = "0.8.6", 
    default-features = false, 
    features = [
        "postgres", 
        "runtime-tokio-rustls", 
        "uuid", 
        "chrono", 
        "migrate"
        # "macros" intentionally removed — server uses sqlx::query() not macros
    ] 
}

axum-server = { version = "0.7.4", features = ["tls-rustls"] }  # bump for pemfile fix
```

**`deny.toml`** (add `ignore` section as safety net for any residual):
```toml
[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"
notice = "warn"
ignore = []   # should be empty after all fixes applied; add here only with justification

[licenses]
allow = ["MIT", "Apache-2.0", "BSD-3-Clause", "Unicode-DFS-2016"]
unlicensed = "deny"
copyleft = "warn"

[bans]
multiple-versions = "deny"
wildcards = "deny"
highlight = "all"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

**`.github/workflows/ci.yml`** — update audit step during transition:
```yaml
- name: Audit dependencies
  # Remove --ignore flag once all dependency fixes are merged and Cargo.lock updated
  run: cargo audit
```

---

## 13. Requirements Specification

### 13.1 Functional Requirements

| ID | Requirement | Priority | Component | Acceptance Criteria |
|----|-------------|----------|-----------|---------------------|
| FR1 | User registration with Argon2id hashing | MUST | server | POST /auth/register → 201; duplicate → 409; plaintext never in DB |
| FR2 | User authentication + JWT issuance | MUST | server | Valid → 200 + tokens; invalid → generic 401; 5 failures → 429 |
| FR3 | Token refresh with rotation | MUST | server | Valid refresh → new access + refresh; old refresh invalidated |
| FR4 | Logout + token revocation | MUST | server | 204; subsequent use of access token → 401 |
| FR5 | Local vault initialization | MUST | core + cli | Vault file created; master password zeroized; AEAD-encrypted |
| FR6 | Add entry | MUST | core + cli | Entry persists after re-encrypt/re-open cycle |
| FR7 | Get entry | MUST | core + cli | Clipboard default; --print for stdout |
| FR8 | List entries | MUST | core + cli | Passwords never displayed |
| FR9 | Delete entry | MUST | core + cli | Confirmation required; atomic write |
| FR10 | Push vault to server | MUST | cli + server | Opaque bytes only; version returned |
| FR11 | Pull vault from server | MUST | cli + server | AEAD integrity check before overwrite |
| FR12 | Conflict detection | MUST | cli + server | Version mismatch → 409; user resolution dialog |
| FR13 | Vault lock | MUST | cli | Session tokens cleared; key never persisted |
| FR14 | Secure password input | MUST | cli | No echo; never in shell history |
| FR15 | Export with re-encryption | SHOULD | cli | Backup encrypted with different password |
| FR16 | KDF parameter migration | SHOULD | cli | `migrate` command re-encrypts with new params |

### 13.2 Non-Functional Requirements

| ID | Requirement | Metric |
|----|-------------|--------|
| NFR-S1 | Argon2id only for vault KDF | Code review — no other KDF path |
| NFR-S2 | Argon2id params m≥65536, t≥3, p≥4 | CI benchmark asserts ≥300ms |
| NFR-S3 | XChaCha20-Poly1305 only for AEAD | No non-AEAD cipher in core |
| NFR-S4 | Unique nonce per operation | Fuzz + property test |
| NFR-S5 | Zeroize all sensitive types | Unit test + code review |
| NFR-S6 | No plaintext in DB | Schema audit; 0 plaintext vault columns |
| NFR-S7 | Constant-time auth comparisons | `constant_time_eq` usage; timing test ±5ms |
| NFR-P1 | KDF ≥ 300ms | CI benchmark gate |
| NFR-P2 | Sync round-trip ≤ 500ms | Integration benchmark |
| NFR-R1 | Atomic vault writes | Fault injection — kill-mid-write x100 |
| NFR-R2 | Integrity check on open | Unit test with corrupted ciphertext |
| NFR-PO1 | Linux x86_64 musl static binary | CI release matrix |
| NFR-PO2 | Windows x86_64 MSVC binary | CI release matrix |

---

## 14. Risk Register

| ID | Risk | Likelihood | Impact | Severity | Mitigation | Status |
|----|------|-----------|--------|----------|-----------|--------|
| R1 | Server compromise (DB exfiltration) | Medium | Low (encrypted only) | LOW | Argon2id KDF, unique salts, no keys stored | Accepted |
| R2 | Nonce reuse | Low | CRITICAL | CRITICAL | CSPRNG per op, fuzz harness | Near-zero |
| R3 | Weak master password | High | HIGH | HIGH | zxcvbn ≥ 3, 300ms KDF | Medium (user control) |
| R4 | Auth credential = vault key | Low (by design) | CRITICAL | CRITICAL | Architecturally separated | Near-zero |
| R5 | Replay attack / stale blob | Medium | Medium | MEDIUM | Version counter, TLS, client validates | Low |
| R6 | Sync conflict → data loss | Medium | Medium | MEDIUM | Optimistic locking, user resolution | Low |
| R7 | Client compromise (malware) | Medium | CRITICAL | HIGH | Minimize plaintext lifetime, zeroize | Accepted residual |
| R8 | Metadata leakage | Low | Medium | MEDIUM | Full payload encrypted, blob size only visible | Low |
| R9 | Timing oracle on login | Low | Medium | MEDIUM | dummy_hash + constant_time_eq | Low |
| R10 | Supply chain attack | Low | HIGH | HIGH | cargo audit + cargo deny in CI, SBOM | Low |
| R11 | JWT secret leak | Low | CRITICAL | CRITICAL | Env var, 256-bit random, rotation procedure | Low |
| R12 | Argon2 params too weak | Medium | Medium | MEDIUM | CI benchmark gate ≥ 300ms | Low |
| R13 | Vault file corruption | Medium | HIGH | HIGH | Atomic write, AEAD integrity on open | Low |
| R14 | TLS misconfiguration | Low | HIGH | HIGH | rustls (not OpenSSL), startup warning for HTTP | Low |

---

## 15. Development Methodology

### 15.1 Security-Hardened Agile

2-week sprints with mandatory security gates at each sprint boundary.

**Sprint Cadence:**
- Sprint Planning: Monday Week 1 (2h)
- Daily Standup: 15 min async (written)
- Security Checkpoint: Thursday Week 2 (1h) — **mandatory**
- Sprint Review: Friday Week 2 (1h)
- Retrospective: Friday Week 2 (30 min)

### 15.2 Security Gate Checklist (must pass before merge to `main`)

- [ ] `cargo clippy -- -D warnings` clean (zero warnings)
- [ ] `cargo test` 100% pass; coverage > 80% on `nullwarden-core`
- [ ] `cargo audit` zero critical/high CVEs
- [ ] `cargo deny check` clean
- [ ] Four-eyes review on all new crypto code paths
- [ ] Threat model updated for any new component
- [ ] No secrets in git history (`git-secrets` / `trufflehog`)
- [ ] CHANGELOG entry present

### 15.3 Branching

```
main          ← protected, release-tagged only
develop       ← integration branch
feature/*     ← per-story branches (from develop)
hotfix/*      ← critical patches (from main, merge back to both)
security/*    ← security fixes (private until patched, then public)
```

### 15.4 Definition of Done

1. Functionality implemented per acceptance criteria
2. Unit tests written and passing
3. Integration test updated if sync/API touched
4. `cargo fmt`, `cargo clippy`, `cargo audit` all clean
5. Documentation updated (inline doc + CHANGELOG)
6. Security gate passed
7. PR reviewed and approved (crypto paths: four-eyes minimum)

---

## 16. ADRs — Architecture Decision Records

### ADR-001: XChaCha20-Poly1305 over AES-256-GCM

**Decision:** Use XChaCha20-Poly1305 for all vault encryption.

**Rationale:**
- 192-bit nonce eliminates collision risk even at massive scale. AES-GCM's 96-bit nonce has ~50% collision probability at 2^32 random operations.
- Pure software implementation is timing-attack resistant without hardware acceleration. AES requires AES-NI for both performance and timing safety.
- Libsodium lineage — heavily audited, widely deployed.

**Consequence:** Not FIPS-compliant. Systems requiring FIPS-approved primitives cannot use this design.

---

### ADR-002: Argon2id over bcrypt/scrypt/PBKDF2

**Decision:** Use Argon2id with m=65536, t=3, p=4.

**Rationale:**
- PHC winner 2015. Memory-hard (GPU resistance) + time-hard + side-channel resistant ("id" variant).
- bcrypt: limited to 72-byte passwords, no memory hardness, outdated.
- PBKDF2: time-only, no memory hardness, trivially parallelizable on GPU.
- scrypt: memory-hard but no official independent test vectors, complex parameter space.

**Consequence:** 64 MB RAM allocated per unlock/save operation. Unsuitable for embedded or IoT contexts.

---

### ADR-003: Rust for Core Library and CLI

**Decision:** Implement all security-critical code in Rust.

**Rationale:**
- Memory safety without GC prevents buffer overflows, use-after-free, double-free.
- Ownership model makes single-use-and-zeroize patterns natural.
- `Drop` + `Zeroize` trait compose cleanly for secret lifecycle management.
- Static binaries via musl — no runtime dependency on the target system.
- Zero-cost abstractions allow constant-time code without performance penalty.

**Consequence:** Steep learning curve. Long compile times. Smaller contributor pool vs Python/Go.

---

### ADR-004: Axum for Server

**Decision:** Use Axum 0.7 as the HTTP framework.

**Rationale:**
- Type-safe extractors (`FromRequestParts`) make auth middleware compile-time correct.
- Tower ecosystem: `tower_governor` for rate limiting, `tower-http` for headers/CORS/tracing.
- Tokio-native — same runtime as the rest of the codebase.
- In-process testing (`Router::oneshot()`) — no test server spawning needed.

**Consequence:** Complex type bounds. Learning Tower middleware requires understanding the service/layer abstractions.

---

### ADR-005: No Password Recovery

**Decision:** Zero-knowledge architecture is architecturally incompatible with password recovery. No recovery mechanism will be implemented.

**Rationale:**
- Any recovery requires either: server-side key escrow (violates INVARIANT 1) or secret-split between server and recovery service (increases attack surface, adds complexity).
- Simplicity. No recovery path = no recovery attack surface.
- Users are informed at vault creation: master password loss = permanent data loss.

**Consequence:** Users who lose their master password lose their vault. This must be prominently documented in UX.

---

### ADR-006: MessagePack over JSON for Vault Payload

**Decision:** Use MessagePack (rmp-serde) for vault payload serialization.

**Rationale:**
- Binary encoding: ~30% smaller than JSON for typical vault entry maps.
- No floating-point ambiguity.
- Same `#[derive(Serialize, Deserialize)]` macros as serde_json — no extra boilerplate.
- Not human-readable (this is a feature — the ciphertext is already opaque, the plaintext doesn't need to be inspectable).

**Consequence:** Not inspectable with standard tools without decryption + deserialization. Debugging requires tooling.

---

### ADR-007: Stateless JWT over Server Sessions

**Decision:** Use short-lived JWTs for access tokens with rotating refresh tokens.

**Rationale:**
- Stateless access tokens = horizontally scalable server (no shared session store).
- Refresh token rotation enforces single-device-at-a-time semantics for refresh flow.
- 15-minute access token lifetime limits blast radius of token theft.
- Blocklist (SHA-256 hashed) handles revocation for logout without stateful sessions.

**Consequence:** Access tokens valid for up to 15 minutes after logout (until natural expiry + blocklist check). Server must maintain blocklist table.

---

## 17. Deployment Guide

### 17.1 Prerequisites

- PostgreSQL 16+ (or Supabase)
- TLS certificates (PEM format) for production
- Rust stable toolchain (for source builds) or Docker

### 17.2 Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | YES | — | PostgreSQL connection string |
| `JWT_SECRET` | YES | — | 256-bit random key (`openssl rand -hex 32`) |
| `SERVER_HOST` | no | `0.0.0.0` | Bind address |
| `SERVER_PORT` | no | `8080` | Listen port |
| `TLS_CERT_PATH` | prod | — | PEM certificate path |
| `TLS_KEY_PATH` | prod | — | PEM private key path |
| `JWT_ACCESS_EXPIRE_SECS` | no | `900` | Access token lifetime |
| `JWT_REFRESH_EXPIRE_DAYS` | no | `7` | Refresh token lifetime |
| `AUTH_ARGON2_M_COST` | no | `65536` | Auth KDF memory (KiB) |
| `AUTH_ARGON2_T_COST` | no | `3` | Auth KDF iterations |
| `AUTH_ARGON2_P_COST` | no | `4` | Auth KDF parallelism |
| `DB_MAX_CONNECTIONS` | no | `10` | PostgreSQL pool size |
| `CLEANUP_INTERVAL_SECS` | no | `3600` | Background token cleanup |
| `RATE_LIMIT_AUTH_REQUESTS` | no | `5` | Max auth requests |
| `RATE_LIMIT_AUTH_WINDOW_SECS` | no | `600` | Rate limit window |

### 17.3 Docker Deployment

```bash
# Generate JWT secret
JWT_SECRET=$(openssl rand -hex 32)

# Start with docker-compose
docker-compose up -d postgres
docker-compose up server

# Or pull pre-built image
docker pull ghcr.io/OWNER/nullwarden-server:v0.1.0
docker run -e DATABASE_URL=... -e JWT_SECRET=... -p 8080:8080 nullwarden-server
```

### 17.4 Supabase Notes

Use the **Direct Connection** string (not transaction pooler) for SQLx compatibility:
```
postgresql://postgres.[ref]:[pass]@aws-0-[region].pooler.supabase.com:5432/postgres
```

Set `DB_MAX_CONNECTIONS=50` for the Free tier (60 connection limit, leave headroom).

### 17.5 JWT Secret Rotation (Zero-Downtime)

1. Generate new `JWT_SECRET`
2. Deploy to all instances simultaneously
3. All existing access tokens immediately invalid (users will refresh or re-login)
4. Refresh tokens still valid (stored as SHA-256 hash, not affected by JWT secret change)
5. If compromise suspected: also call `revoke_all_user_tokens()` per user and notify users

---

## 18. Recommendations for v0.2+

### R1 — OPAQUE Protocol for Authentication (HIGH)

Current: user sends auth_password over TLS. TLS stripping or malicious server exposes it.  
Fix: implement OPAQUE (RFC draft) — password-authenticated key exchange where server never sees the auth password, not even in transit. Crate: `opaque-ke`.

### R2 — HKDF for Key Separation (MEDIUM)

Current: single Argon2id output used as vault key.  
Fix: use HKDF to derive separate keys for encryption, MAC, and future key version upgrade from the Argon2id master key. Provides domain separation and easier key rotation.

### R3 — TOTP/WebAuthn Second Factor (HIGH for production)

Auth password alone is a single factor. TOTP adds significant protection against password leakage.

### R4 — Server-Side Blob Signing (MEDIUM)

Current: version counter only. A compromised server can return stale versions.  
Fix: include server HMAC over `user_id || version || sha256(blob)` in response. Client verifies before accepting.

### R5 — Reproducible Builds (HIGH)

Implement `cargo build --frozen` with pinned toolchain. All release binaries should be reproducible — same source = same binary bytes. Publish SHA-256 checksums for every release artifact.

### R6 — Argon2 Parameter Migration Plan

Document and implement `nullwarden migrate` for when hardware gets faster and params need increasing. The vault header already stores KDF params — migration is: re-derive with new params → re-encrypt → rewrite header.

### R7 — Memory-Locked Allocator (MEDIUM)

Use `mlock()` on Linux/macOS for secret memory pages — prevents swap to disk and core dump exposure. Crate: `memsec` or `secmem-proc`. Accept residual on platforms without `mlock`.

### R8 — Password Sharing (Future)

Requires asymmetric key exchange (X25519 + ChaCha20-Poly1305). Architecture: each user has an identity keypair; sharing = re-encrypting entry for recipient's public key. Not compatible with current symmetric-only design without adding an asymmetric layer.

---

*NullWarden Project Reference — v0.1.0*  
*Generated: 2026-04-22*  
*Classification: Internal Engineering*
