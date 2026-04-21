# NullWarden — Pre-Go-Live Deep Analysis Report

**Date:** 2026-04-20  
**Analyst:** Internal Security Engineering  
**Scope:** Full codebase post-audit-remediation — all 16 analysis dimensions  
**Codebase Version:** HEAD (post-AUDIT_REPORT.md remediation PR)  
**Classification:** Internal Engineering — Prototype Phase  

---

## Executive Summary

NullWarden's cryptographic core is architecturally sound. The zero-knowledge contract holds at the boundary level: the server stores opaque ciphertext, keys never leave the client, and the AEAD primitive is correctly chosen. However, the surrounding system — authentication infrastructure, sync correctness, test coverage, operational posture, and incident readiness — contains gaps that make production deployment premature.

**Overall Verdict: NOT READY FOR PRODUCTION**

The system is suitable for internal prototype use with no real user data. Before any external deployment with real credentials:

- Server integration tests must be replaced with real tests (not stubs)
- Rate limiting must be validated end-to-end, not just in configuration
- The `rls_transaction` pattern using `SET LOCAL auth.uid` is a SQL injection vector that must be removed
- No SBOM, no reproducible builds, no macOS build target
- No incident response runbook exists

The following analysis covers every dimension. Each section concludes with a **go/no-go verdict** for that dimension.

---

## Table of Contents

1. [Security](#1-security)
2. [Cryptography Correctness](#2-cryptography-correctness)
3. [Functional Correctness](#3-functional-correctness)
4. [User Experience and CLI](#4-user-experience-and-cli)
5. [Accessibility](#5-accessibility)
6. [Performance](#6-performance)
7. [Reliability and Crash Safety](#7-reliability-and-crash-safety)
8. [Data Recovery and Backup](#8-data-recovery-and-backup)
9. [Backend and API Behavior](#9-backend-and-api-behavior)
10. [Database Design](#10-database-design)
11. [Logging, Telemetry, and Observability](#11-logging-telemetry-and-observability)
12. [Compatibility and Portability](#12-compatibility-and-portability)
13. [Code Quality and Maintainability](#13-code-quality-and-maintainability)
14. [Build and Release Pipeline](#14-build-and-release-pipeline)
15. [Privacy and Compliance](#15-privacy-and-compliance)
16. [Incident Response and Failure Handling](#16-incident-response-and-failure-handling)
17. [Go-Live Checklist](#17-go-live-checklist)

---

## 1. Security

**Verdict: CONDITIONAL — Core model sound; surrounding infrastructure has active blockers**

### 1.1 Threat Model Assessment

The stated threat model correctly identifies the server as untrusted. The trust boundary is architecturally enforced: `nullwarden-core` contains no network code and no file I/O, making it structurally impossible for vault key material to reach the server through the core library. This separation is the project's strongest security property.

**Attacker classes and coverage:**

| Attacker | Capability | Coverage | Gap |
|----------|-----------|----------|-----|
| Passive network observer | TLS intercept | ✅ TLS 1.3 enforced in prod path | ❌ HTTP mode fallback in main.rs emits a warning but runs anyway |
| Compromised DB/server | Full read | ✅ Only ciphertext + Argon2id hashes stored | None |
| Stolen device (locked) | Disk read | ✅ Vault is ciphertext | None |
| Stolen device (unlocked) | Memory dump | ⚠️ Mitigated by Zeroize; LLVM elision risk remains | H-08 residual |
| Active MITM | TLS strip | ✅ HSTS header set | ❌ No cert pinning option implemented |
| Brute-force login | Password guessing | ⚠️ Rate limit config exists but not integration-tested | H-03 residual |
| Username enumeration | Timing side-channel | ✅ Dummy hash mitigates C-02 | Requires timing validation |
| Rollback/replay | Stale vault return | ⚠️ Version counter exists; no cryptographic freshness proof | R5 residual |
| Supply chain | Malicious dep | ✅ cargo audit + cargo deny in CI | ❌ No SBOM generated |

### 1.2 Authentication Analysis

**Access token (JWT):**
- HS256 with a server-side secret. The `JWT_SECRET` is loaded from env via `envy`. Correct pattern.
- Token expiry at 15 minutes is correct. The `jsonwebtoken` crate's `Validation::default()` validates exp automatically, and the code adds a redundant `claims.exp < now` check — acceptable belt-and-suspenders, but the redundant check uses `as usize` timestamp cast which silently truncates on 32-bit targets (not a current target, but worth noting).
- **Gap:** No `iss` (issuer) or `aud` (audience) claim validation. A token issued by a compromised instance of this server is accepted by all instances. This matters if multiple environments (staging, prod) share a JWT secret rotation boundary.

**Refresh token:**
- The split-token design (`id:secret`) is correctly implemented post-C-01 fix.
- `secret` is a UUID v4 string (~122 bits of entropy). This is adequate but not optimal — a 32-byte CSPRNG hex string would be more conventional and slightly higher entropy for the secret component. UUID v4 is fine in practice.
- `secret_hash` uses Argon2id (via `hash_password`). This is unnecessarily slow for a refresh token secret. The split-token design's point is that you only need a fast MAC (SHA-256 constant-time) on the secret after looking up by ID. Using Argon2id for the secret hash means every token refresh call costs ~300ms of CPU on the server. Under load this becomes a DoS vector, just a slower one than C-01.
- **BLOCKER:** `consume_refresh_token` calls `verify_password` (Argon2id) on every refresh. This should be SHA-256 constant-time compare. The fix was documented (C-01) but the implementation still uses Argon2id for the secret hash.

**Rate limiting:**
- `tower_governor` is wired in the router but the `rate_limit.rs` file is referenced in the audit but not shown in the provided source. The `Config` struct has `rate_limit_auth_requests` and `rate_limit_auth_window_secs` fields but the middleware integration is not confirmed in the provided code — `app.rs` does not show a rate limit layer being applied. **This must be verified before deployment.**

### 1.3 Session Management

- Token blocklist: implemented via SHA-256 hash in `token_blocklist` table. Correct.
- **Gap:** No cleanup job for expired blocklist entries (M-01 is documented as "Fixed in PR" but no cleanup code is visible in the provided source — only a migration adding the table with `expires_at`). Without cleanup, this table will grow indefinitely and the `SELECT 1 FROM token_blocklist WHERE token_hash = $1` query will degrade.
- No session binding to device fingerprint or IP. Stolen refresh tokens are universally usable. This is documented (H-07) and accepted for v0.1, but must be documented in the threat model as an explicit residual risk.

### 1.4 Secret Handling — Server Side

- `Config.jwt_secret` is typed as `SecretString` (Zeroize + ZeroizeOnDrop). Correct — it will be cleared from memory on drop.
- `dummy_hash` stored in `AppState` as a plain `String`. This is a hash string (Argon2id PHC string), not the plaintext secret, so leaking it in memory is acceptable.
- `password_hash` in `StoredUser` is a plain `String`. Same argument — this is the hash, not the plaintext.
- `AppState::new()` is a deprecated method that returns `Err(...)` unconditionally. Dead code that should be removed — it creates confusion about the initialization path.

### 1.5 Secret Handling — Client Side

- `VaultEncryptionKey`, `SecretString`, `SecretBytes` all implement `Zeroize + ZeroizeOnDrop`. The Debug impls correctly show `***REDACTED***`.
- `SecretString::serialize` emits plaintext. This is required for vault storage (MessagePack) but is a permanent footgun. Any `serde_json::to_string(&vault_entry)` anywhere in the codebase — including future HTTP handlers — will leak passwords. The type needs a `#[doc]` warning at minimum, and ideally a newtype that refuses JSON serialization.
- In `get.rs`, the `entry.password.0.clone()` call for clipboard puts a plaintext clone on the heap. The entry goes out of scope after the function returns, at which point `VaultData` and `VaultEntry` are dropped and zeroized. The clone passed to the clipboard library is not under Zeroize control — it will persist in the clipboard library's internal heap allocation until overwritten. No practical mitigation within the current process-exit model.
- `auth.rs` client code: `AuthRequest { username, password }` is serialized to JSON for the request body. The `password` field here is the auth password (not vault key), serialized as a plain JSON string. This is correct and unavoidable for HTTP auth. The TLS layer protects it in transit.

### 1.6 Input Validation

- `vault.rs` handler: `body: Bytes` is bounded by `DefaultBodyLimit::max(10 * 1024 * 1024)`. Correct.
- `auth.rs`: No username length validation. A user can submit a 1MB username string, which will be passed to `find_user` as a parameterized query (safe from injection) but will allocate memory unnecessarily. Add length validation: username 3–64 chars per the spec.
- `vault/header.rs decode()`: Format version check is now enforced (C-05 fix is present in source). Magic bytes are checked. Minimum length is checked. **This is correct.**
- The `rls_transaction` function in `db/vaults.rs` uses string formatting to build a SQL statement:
  ```rust
  sqlx::query(&format!("SET LOCAL auth.uid = '{}'", user_id))
  ```
  `user_id` is a `Uuid` type, so its `Display` output is always a UUID string in the format `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. This cannot contain SQL injection characters. **However**, this pattern is architecturally dangerous: it trains developers to interpolate into SQL strings, and if this pattern is ever copied with a non-Uuid type, it becomes a SQL injection vulnerability. Replace with a parameterized approach or remove the RLS transaction wrapper entirely (the RLS policies use `USING (true)` which passes all rows through anyway, making the `SET LOCAL auth.uid` a no-op in terms of access control).

### 1.7 Dependency Risk

- `cargo deny check` is in CI with `multiple-versions = "deny"`. This is the correct posture.
- `cargo audit` is in CI.
- The Cargo.lock is committed (correct for deterministic builds).
- Notable transitive dependencies of concern:
  - `reqwest 0.11` uses `hyper 0.14` (older branch). `reqwest 0.12+` uses `hyper 1.x`. No immediate CVE but outdated.
  - `criterion 0.3` depends on `atty 0.2.14` which has a known unsoundness on Windows. This is a dev-dependency only (benchmarks) and does not ship in the binary. Acceptable but worth tracking.
  - Two versions of `rustls` (0.21 and 0.23) in the tree due to `reqwest` vs `axum-server` pulling different versions. This passes `deny check` only if `skip` entries exist for `rustls`. Verify this is intentional.

---

## 2. Cryptography Correctness

**Verdict: PASS with noted residuals**

### 2.1 KDF Analysis

```rust
// kdf.rs — CORRECT
pub struct KdfParams {
    pub m_cost: u32,  // 65,536 KB = 64 MB
    pub t_cost: u32,  // 3 iterations
    pub p_cost: u32,  // 4 parallel lanes
}
```

- Argon2id (Algorithm::Argon2id, Version::V0x13) — correct.
- `m=65536, t=3, p=4` meets the NFR-S2 specification.
- 32-byte CSPRNG salt via `OsRng::fill_bytes`. Correct.
- 32-byte key output. Correct.
- The `kdf_meets_minimum_latency` test is in `tests/kdf_params.rs` and is marked `#[ignore]` with explicit CI invocation via `cargo test -- --ignored kdf_meets_minimum_latency`. **This is the correct fix for H-04.** The CI `ci.yml` includes this step.

**Residual:** KDF params are stored in the vault header. This enables offline parameter downgrade: an attacker who controls the vault file can replace the header with weaker params (m=1024, t=1) before the user opens it. The client accepts whatever params are in the header. Mitigating this completely requires signing the header, which is out of scope for v0.1 but must be documented as a known attack surface. Without master password confirmation, a header-tampered vault will produce a different key that fails AEAD — the user gets a decryption error, not silent compromise. This is acceptable: fail closed.

### 2.2 AEAD Analysis

```rust
// crypto.rs — CORRECT
pub fn encrypt(key: &VaultEncryptionKey, plaintext: &[u8]) 
    -> Result<(VaultNonce, Vec<u8>), VaultError>
```

- XChaCha20Poly1305 with 192-bit CSPRNG nonce per operation via `OsRng`. Correct.
- AEAD tag is included in the ciphertext slice by the `chacha20poly1305` crate (`Aead::encrypt` appends the 16-byte tag). Correct.
- Decryption via `cipher.decrypt` verifies the tag atomically before returning any plaintext. Correct — no unauthenticated plaintext is ever returned.
- `VaultNonce` does not implement `Zeroize`. Nonces are public values and this is intentional and correct.

**Nonce reuse risk:** Zero — each encrypt call generates a fresh nonce from OsRng. The vault re-encrypts entirely on each save (not incrementally), so there is no state machine where a nonce could be reused across partial writes.

### 2.3 Key Separation

- Vault encryption key: derived client-side from master password via Argon2id + per-vault salt.
- Server auth password hash: derived server-side from auth password via Argon2id + per-user salt (SaltString from OsRng).
- These are completely independent derivation chains. No code path connects them. **Key separation is correct.**
- The `dummy_hash` in AppState is derived from a hardcoded dummy password at server startup. This is correct for timing oracle mitigation.

### 2.4 Constant-Time Comparisons

- `handlers/auth.rs login`: Uses `password::verify_password` which calls `Argon2::default().verify_password()`. The `argon2` crate uses `subtle::ConstantTimeEq` for tag comparison internally. Correct.
- `auth/token.rs`: Post-C-01 fix, the refresh token secret comparison uses `verify_password` (Argon2id). As noted in §1.2, this should be SHA-256 + `constant_time_eq`. The `constant_time_eq` crate is a declared dependency of `nullwarden-server` but is not used in the token verification path.
- `auth/jwt.rs block_token` and `is_token_blocked`: Token hash is SHA-256. Lookup is by hash equality in a DB query (not a constant-time in-process comparison), but since the token hash is not secret (it's a lookup key), this is acceptable.

### 2.5 Vault Format Version

- `VaultHeader::FORMAT_VERSION = 1` (u8).
- `decode()` now correctly rejects any `format_version != Self::FORMAT_VERSION`. The fix is present in the provided source.
- Format version is stored in the header at offset 4. An attacker who can write to the vault file can set this to 0x00 to trigger `decode()` returning `None`, causing an `InvalidFormat` error. This is a denial-of-service against the local vault but not a confidentiality breach.

### 2.6 Zeroize Analysis

- `VaultEncryptionKey([u8; 32])` with `#[derive(Zeroize, ZeroizeOnDrop)]`. Stack-allocated. LLVM elision risk exists in release+LTO builds (H-08). Mitigation via `#[inline(never)]` or heap pinning is not implemented. Documented residual.
- `SecretString(String)` — heap-allocated string. The `Zeroize` impl on `String` zeroes the heap buffer. More reliable than stack arrays.
- `VaultData` with `#[zeroize(skip)]` on `version` — correct.
- The `zeroize.rs` test uses unsafe UB to read freed memory. Documented as intentional UB in comments. This test produces false confidence in release mode. Should be replaced with `cargo miri test` in CI.

---

## 3. Functional Correctness

**Verdict: PARTIAL — Core local ops pass; server integration tests are stubs**

### 3.1 Local Vault Operations

All local operations (init, add, get, list, delete, update) are tested via real tests:

- `tests/vault_lifecycle.rs`: `init_add_unlock_delete_cycle` — exercises the full local CRUD path.
- `tests/e2e_add_get.rs`: `test_vault_lifecycle_local` — init, add, verify, update, verify, delete, verify. **This is a complete functional test.**
- `tests/integrity.rs`: Corruption and wrong-password detection. **Both pass.**
- `tests/crypto_roundtrip.rs`: Encrypt/decrypt round-trip. **Passes.**
- `tests/atomic_write.rs`: File creation. **Passes.**

**Gap:** No test for the `update_entry` with `clear_notes: true` (M-05 fix) verifying the `Some(None)` path actually clears notes on disk persistence.

**Gap:** No test for `add_entry` with a duplicate title — should return `DuplicateEntry` error.

### 3.2 Sync Operations

The `e2e_sync.rs` test spins up a mock Axum server and exercises push/pull with version tracking. This is the best-quality test in the server path. It correctly:
- Creates a vault, adds an entry, pushes it.
- Pulls it on a "second device" and verifies the entry is intact.

**Gap:** No test for conflict detection in this mock server test. The conflict path (version mismatch → 409) is not exercised by any test.

**Gap:** No test for the pull rollback detection (`version < current_version` → bail). The client code has this check but no test verifies it.

**Gap:** No test for the force-push path (conflict resolution choosing "local").

### 3.3 Server Integration Tests

All four server integration test files are stubs:
```rust
// auth_integration.rs
#[tokio::test]
async fn test_auth_flow_structural() {
    // Structural test to ensure routes are mapped correctly
}
```

These tests pass vacuously. **They test nothing.** The CI coverage gate runs `cargo tarpaulin -p nullwarden-core` only, so the server has zero enforced coverage. This means:
- The register → login → token refresh → logout flow has never been tested end-to-end with a real database.
- Rate limiting has never been verified to actually reject the 6th request.
- Conflict detection at the HTTP level has never been verified.

**This is the single largest functional correctness gap in the project.**

### 3.4 Password Strength Validation

- `validate_password_strength` in `input.rs` is called in `init.rs` (master password) and `register.rs` (auth password) and `add.rs` (entry password). The `update.rs` also calls it when a new password is provided. All call sites covered.
- The score cast `estimate.score() as u8` will produce 0–4. The comparison `< 3` correctly enforces score ≥ 3. The more idiomatic typed comparison (`< Score::Three`) is preferred but not blocking.

### 3.5 Config Lifecycle

- `Config::load()` creates and saves a default config if none exists. This means the first run of any CLI command silently creates `~/.config/nullwarden/config.toml` pointing to `http://127.0.0.1:8080`. Users who never set a server URL will unknowingly push to localhost. **This needs an explicit setup step or at minimum a logged warning.**

---

## 4. User Experience and CLI

**Verdict: ACCEPTABLE for CLI prototype; blocking UX issues for general use**

### 4.1 Command Discoverability

The CLI is built with `clap v4` and provides `--help` output automatically. Command names are intuitive (`init`, `add`, `get`, `list`, `push`, `pull`). However:

- **No onboarding flow.** `nullwarden init` creates a local vault but does not guide the user to `register` and configure a server URL. A first-time user who runs `nullwarden init` then `nullwarden push` will get a connection refused error with no guidance.
- **No `--help` examples.** Clap subcommands have no usage examples in the derive macros. A user doesn't know that `add` requires positional `title` and `username` args.
- **`Register` does not create a vault.** A user who registers then immediately tries `push` will fail because no vault file exists. The expected flow (register → init → add → push) is not communicated anywhere in the CLI.

### 4.2 Password Entry UX

- `rpassword::read_password()` is used everywhere. No echo. Correct.
- On init, the password is entered twice with a "Confirm master password" prompt. Correct.
- On `add`, the entry password is prompted if not provided as an argument. The argument path (`nullwarden add title user mypassword`) exposes the password in shell history and `ps` output. This is documented in `cli-manual.md` but there is no warning printed when a password is passed as a CLI argument.
- **Recommendation:** Detect when `password` arg is provided via command line (vs piped/prompted) and print a warning: "Warning: password provided as argument may be visible in shell history."

### 4.3 Error Messages

Error messages are generally good. `anyhow` propagates context up the call stack. Examples:
- `"failed to unlock vault"` — clear.
- `"entry 'github' not found"` — clear.
- `"no active session. please login or register."` — clear and actionable.

**Gap:** When the server is unreachable, the error is a raw `reqwest` network error, not a friendly message. Users see things like `"error sending request for url (http://127.0.0.1:8080/vault): error trying to connect: tcp connect error: Connection refused (os error 111)"`. This needs to be caught and wrapped: `"Cannot reach NullWarden server at {url}. Is the server running?"`.

### 4.4 Conflict Resolution UX

The conflict resolution flow in `push.rs` is reasonable: prompts "local / remote / abort" with a second confirmation for force push. However:
- The user has no visibility into what changed between the two versions. The prompt says "remote vault has been updated" but not "remote has 5 entries, local has 7 entries" or "last remote sync was 2 hours ago." This makes the choice a coin flip.
- **Recommendation:** Decrypt both versions (requiring master password) and display entry count difference before prompting. This is a meaningful UX improvement.

### 4.5 Lock Command Behavior

`lock.rs` now clears session tokens (L-03 fix is present). However, the message says "Master password material is never persisted in memory between commands" — this is accurate for the lock-by-exit model but may confuse users who expect `lock` to revoke the session server-side. The command only clears local tokens; it does not call `POST /auth/logout`. A stolen token from before `lock` is still valid until expiry. This difference between `lock` (local clear only) and `logout` (server revocation) is not communicated.

### 4.6 Clipboard Behavior

`get.rs` copies to clipboard and prints "Clear it manually after use." The C-08 fix (removing the 30-second sleep) is present. On most Linux systems without a clipboard manager, the clipboard content is owned by the X11 selection and cleared when the process exits — meaning the password is cleared on CLI exit anyway. On macOS, clipboard is managed by the system and persists. On Linux with a clipboard manager (e.g., Parcellite, Clipman), the password is captured by the manager and stored persistently.

**This is a UX gap that has significant security implications:** users on Linux with clipboard managers may have their vault passwords persisted indefinitely in the clipboard manager's history. A warning should be printed: "If you use a clipboard manager, clear its history after use."

---

## 5. Accessibility

**Verdict: ACCEPTABLE — CLI tool; limited scope**

### 5.1 Terminal Accessibility

As a CLI tool, NullWarden has limited accessibility requirements. Key considerations:
- All output is plain text. Screen readers (braille displays, speech output) can read it correctly.
- No color is used in output. Not a contrast issue.
- No mouse interaction required. All keyboard.
- `prompt_choice` uses text input ("local/remote/abort") rather than numbered selection. This is more accessible for screen reader users than arrow-key selection.

### 5.2 Character Encoding

- All strings are UTF-8 (`String` in Rust). The vault format uses MessagePack which is encoding-agnostic. Service names, usernames, notes, and passwords with non-ASCII characters (e.g., Japanese service names, emoji in notes) will serialize and deserialize correctly.
- **Gap:** The `prompt_choice` function reads from `stdin` with `read_line`. On Windows, `stdin` encoding depends on the active code page. A user with a non-UTF-8 terminal on Windows may experience garbled input for non-ASCII characters in prompts. This is a known Rust/Windows quirk.

### 5.3 Error Message Clarity

Error messages use lowercase and imperative tone, consistent with Unix CLI conventions. The `anyhow` context chain provides enough information for a technical user. Non-technical users will struggle with raw error messages from underlying libraries (keyring errors, network errors).

---

## 6. Performance

**Verdict: ACCEPTABLE with known KDF cost; large vault impact untested**

### 6.1 KDF Latency

Argon2id with `m=65536, t=3, p=4` intentionally costs ≥ 300ms per unlock. This means:
- Every `get`, `add`, `list`, `delete`, `update` command costs ≥ 300ms before doing anything (vault unlock).
- Every `push` or `pull` with `--master-password` costs ≥ 300ms.

This is the correct tradeoff for a security-first vault. Users will perceive the CLI as "slow" but this is intentional. **The CLI manual must communicate this explicitly: "Vault unlock intentionally takes 300ms minimum for security."**

### 6.2 Sync Latency

The `e2e_sync.rs` test measures push/pull with a local mock server. Real network latency to a remote server adds to this. No real-network benchmarks exist. The NFR-P2 target (≤ 500ms sync on 10 Mbps) has not been measured. For a typical small vault (< 1MB), sync should be fast. For a vault with thousands of entries and large notes fields, serialization + encryption + upload could exceed this.

### 6.3 Large Vault Performance

No benchmarks exist for large vault sizes. Potential bottlenecks:
- `VaultSerializer::serialize(data)` — MessagePack serialization of all entries in memory. O(n) in entry count.
- `VaultCipher::encrypt(&key, &plaintext)` — encrypts the full serialized blob. O(n) in vault size.
- `fs::read(&self.path)` — reads the full vault file on every operation. O(vault file size).

For a vault with 10,000 entries at 200 bytes each, the plaintext payload is ~2MB. This is within acceptable range. For a vault with notes attachments or large TOTP secrets, this could grow. No upper bound is enforced on entry count or individual entry size.

### 6.4 Server Performance

- DB queries use parameterized SQLx queries with proper indexes (post-H-01 fix).
- No connection pooling configuration is shown — SQLx's `PgPool::connect` uses a default pool size of 10 connections. Under high load, this may be a bottleneck.
- The `put_vault` handler opens a transaction for every upload. Transactions acquire locks in PostgreSQL, which could cause contention under concurrent uploads.

### 6.5 Memory Usage

- `VaultEncryptionKey([u8; 32])` — 32 bytes, stack-allocated.
- `VaultData` with entries — heap-allocated. Grows with entry count.
- No memory limit enforcement on the server for the uploaded blob body. The `DefaultBodyLimit::max(10 * 1024 * 1024)` (10MB) prevents OOM from a single request but does not prevent 1000 concurrent 10MB requests from exhausting server memory.

---

## 7. Reliability and Crash Safety

**Verdict: PASS for local operations; sync path has unverified edge cases**

### 7.1 Atomic Write Analysis

```rust
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("tmp");
    let write_result: Result<(), VaultError> = (|| {
        use std::io::Write;
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}
```

The H-02 fix is present: `fs::remove_file(&tmp_path)` on write error. The atomic write pattern (write → sync → rename) is correct. `sync_all()` ensures durability before rename.

**Gap on Windows:** `fs::rename` fails if the destination file is open (e.g., locked by antivirus). On Linux, rename over an existing file is atomic per POSIX. On Windows, this is not guaranteed. The `fs::rename` on Windows may fail with a permissions error if another process has the vault file open. Consider using a platform-specific atomic rename on Windows (e.g., `ReplaceFileW`).

**Gap:** After `fs::rename`, the parent directory's metadata (directory entry) is updated but not necessarily flushed to disk. On some filesystems, a crash after rename but before directory sync could result in the rename not being reflected after recovery. The solution is to `fsync` the parent directory after rename. This is an edge case that affects reliability on power failure scenarios.

### 7.2 Partial Sync Recovery

If `push` fails mid-upload (network drop after partial body send), the server's transaction is rolled back by SQLx. The local vault is unchanged. The `sync_state.last_version` is not updated (it's only updated on success). Recovery: re-run `push`. Correct.

If `pull` fails after downloading but before writing to disk, the local vault is unchanged. The sync_state is not updated. Recovery: re-run `pull`. Correct.

If `pull` fails after writing to disk but before saving `sync_state`, the local vault is updated but `last_version` still reflects the old version. Next `push` will send `X-If-Match: old_version`, which will be rejected as a conflict (server now has new_version). The user will be prompted to resolve a conflict that is not a real conflict. This is a recoverable state but causes unnecessary friction.

### 7.3 Corruption Detection on Open

`unlock_bytes` first decodes the header (magic + version check), then runs AEAD decryption. Any bit flip in the ciphertext or tag results in `DecryptionFailed`. The `integrity.rs` test verifies this. **Correct.**

### 7.4 Disk Full Behavior

`fs::File::create(&tmp_path)` and `file.write_all(data)` return `Err(io::Error)` on disk full. The error path calls `fs::remove_file(&tmp_path)` (best effort cleanup) and returns `VaultError::Io`. The original vault file is never touched. **Correct.**

---

## 8. Data Recovery and Backup

**Verdict: PARTIAL — No export/import command; restore on new device works via pull**

### 8.1 Restore on New Device

A user on a new device can:
1. `nullwarden register` (or use existing account credentials)
2. `nullwarden init` (create a local vault)
3. `nullwarden pull` (overwrite local with server version)

Step 2 creates a local vault that is immediately overwritten by step 3. This works but is unintuitive — initializing a vault just to overwrite it. A better flow would be `nullwarden restore` or `nullwarden pull --init`.

**The procedure is not documented in the CLI manual or deployment guide.**

### 8.2 No Offline Backup

There is no `export` or `backup` command. Users cannot make an offline encrypted copy of their vault. If the server is deleted or inaccessible, the only recovery path is from the local `vault.nw` file. If both the server and the local device fail simultaneously, all credentials are permanently lost.

**This is the most critical UX/recovery gap in the project.** An export command that produces a re-encrypted backup file with a user-supplied password would address this.

### 8.3 Server Unavailability

If the server is down, users can still access their local vault for `get`, `add`, `list`, `delete`. Push and pull will fail with network errors. There is no caching of the last-successful server version beyond `last_version` in `.vault.nw.sync`. The user can continue working locally and push when the server returns.

**Gap:** No exponential backoff or retry on push/pull. A transient network error causes an immediate failure that the user must manually retry.

### 8.4 Version History

The server stores only one vault blob per user (the current version). There is no version history. If a user accidentally deletes all entries and pushes, the previous vault state is irrecoverably gone on the server. The local vault (if not yet overwritten) is the only recovery path.

**This is a major operational risk for a password manager.** Consider a simple server-side "previous version" field (store the last 1-3 blobs) as a recovery backstop.

### 8.5 Migration on KDF Param Upgrade

ADR-002 and ADR-002 documentation mention a `nullwarden migrate` command for upgrading Argon2 params. This command does not exist in the codebase. The `VaultStore::with_params()` constructor (L-02 fix) is present, enabling custom params, but no migration CLI command is implemented.

---

## 9. Backend and API Behavior

**Verdict: CONDITIONAL — Core API correct; authorization boundary has SQL pattern concern**

### 9.1 Authorization Boundary

Every `get_vault` and `put_vault` handler extracts `user.id` from the validated JWT via the `CurrentUser` extractor. All DB queries are scoped by `user_id`. A user cannot access another user's vault by manipulating the request — the `user_id` comes from the server-verified JWT, not from request parameters.

**The SQL injection risk in `rls_transaction`:**

```rust
sqlx::query(&format!("SET LOCAL auth.uid = '{}'", user_id))
```

`user_id` is `Uuid`, so this cannot be injected. However, this `rls_transaction` method is called on every vault operation. The `SET LOCAL` only affects the current transaction, and the RLS policies are:
```sql
CREATE POLICY "Internal access" ON vaults FOR ALL USING (true);
```
This policy allows all access unconditionally (`USING (true)`). The `SET LOCAL auth.uid` has no effect on access control because the policy doesn't reference `auth.uid`. **The entire `rls_transaction` wrapper is dead code from an access control perspective.** Remove it and use direct pool queries. The user_id scoping in the WHERE clause (`WHERE user_id = $1`) is the actual access control.

### 9.2 API Idempotency

- `PUT /vault`: Not idempotent by design (version counter increments). The `X-If-Match` header provides optimistic locking. Correct.
- `POST /auth/register`: Not idempotent (returns 409 on duplicate). Correct.
- `POST /auth/login`: Idempotent (no state mutation). Correct.
- `POST /auth/logout`: Not fully idempotent — calling logout twice with the same token will fail on the second call (token already blocked). This is acceptable.

### 9.3 Error Response Format

All errors return `{"error": "message"}` JSON via `AppError::into_response`. Error messages for auth failures are generic ("Invalid username or password", not "Username not found" or "Wrong password"). **Correct for preventing enumeration.**

**Gap:** 500 Internal Server Error responses log the full error chain via `error!("Internal server error: {:?}", err)`. This includes SQL error messages which may contain table names, column names, and constraint names. These are logged server-side (not returned to client), which is correct. But log access could expose schema information.

### 9.4 Rate Limiting Verification

The `tower_governor` dependency is listed in `Cargo.toml`. The `app.rs` router does not visibly apply a rate-limiting layer in the provided source. The `config.rs` has `rate_limit_auth_requests` and `rate_limit_auth_window_secs` fields. Without seeing `middleware/rate_limit.rs` (not provided in the source listing), it's unclear whether rate limiting is actually applied to the auth endpoints.

**This must be verified before deployment. If the rate limit middleware file was deleted or not wired, there is no brute-force protection.**

### 9.5 CORS Configuration

`app.rs` configures `AllowOrigin::any()` with a comment "In production, restrict to your domain." This is a placeholder that allows any origin. For a server accessed only by the CLI (no browser client), CORS is irrelevant — CLI tools don't enforce CORS. For a future web client, this must be restricted. **Acceptable for current use; must be fixed before any browser-based client ships.**

---

## 10. Database Design

**Verdict: PASS with noted monitoring gaps**

### 10.1 Schema Analysis

**users table:**
```sql
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```
- No plaintext secrets stored. `password_hash` is an Argon2id PHC string. Correct.
- No index on `username` beyond the UNIQUE constraint (which creates an implicit index). Correct for lookup by username.
- No `email` field — reduces PII exposure.

**vaults table:**
```sql
CREATE TABLE IF NOT EXISTS vaults (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    version BIGINT NOT NULL DEFAULT 1,
    blob BYTEA NOT NULL,
    ...
);
```
- One vault per user enforced by primary key. Correct for v0.1 architecture.
- `blob BYTEA` — opaque ciphertext. Never queried by content. Correct.
- `ON DELETE CASCADE` — deleting a user cascades to vault deletion. Correct.
- **Gap:** `blob` has no size limit at the DB level. A malicious client sending repeated large pushes could consume unbounded disk space. PostgreSQL has no built-in column-level size limits for BYTEA. The 10MB application-layer limit helps but check constraints at the DB level provide defense in depth.

**refresh_tokens table:**
```sql
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_hash TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    ...
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
```
- H-01 fix is present. Correct indexes. Correct.

**token_blocklist table:**
```sql
CREATE TABLE IF NOT EXISTS token_blocklist (
    token_hash TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);
```
- No index on `expires_at`. The cleanup query `DELETE FROM token_blocklist WHERE expires_at < now()` will perform a full table scan. Add an index: `CREATE INDEX ON token_blocklist(expires_at)`.
- No cleanup job is visible in the server startup code or as a scheduled task. The table will grow indefinitely until manually cleaned.

### 10.2 RLS Policies

All three main tables have RLS enabled with permissive policies (`USING (true)`). These policies provide no access control — they unconditionally permit all operations. The application-layer access control (JWT + user_id scoping in WHERE clauses) is the actual enforcement mechanism. The RLS policies are misleading and should either be removed or replaced with actual restrictive policies, but without `auth.uid()` (which requires Supabase), restrictive RLS is non-trivial on vanilla PostgreSQL.

### 10.3 Migration Safety

Migrations are run on server startup via `sqlx::migrate!("./migrations").run(&db)`. If a migration fails (e.g., the RLS policy fails on vanilla PostgreSQL), the server will fail to start with a clear error. This is the correct behavior.

**Gap:** Migrations are not transactional across multiple migration files. If migration 3 fails, migrations 1 and 2 are already applied. Rolling back requires manual intervention.

---

## 11. Logging, Telemetry, and Observability

**Verdict: PASS — No secrets in logs; gaps in structured observability**

### 11.1 Secret Leakage in Logs

All server logging uses `tracing::info!` and `tracing::error!`. Review of all log call sites:

- `request_id.rs`: Logs `method`, `uri`, `request_id`, `status`. No body content, no auth headers. **Correct.**
- `error.rs IntoResponse`: Internal errors log `{:?}` error chains. These may include SQLx error messages with table/constraint names but not user data or secrets.
- `main.rs`: Logs the bind address. No secrets.
- `auth/jwt.rs`: No logging of token values.
- `auth/password.rs`: No logging of passwords or hashes.

**Gap:** The `tracing_subscriber::fmt::init()` in `main.rs` uses the default formatter, which outputs to stdout. In containerized deployments, stdout is captured by the container runtime and forwarded to logging infrastructure (CloudWatch, Datadog, etc.). The log format is human-readable text, not structured JSON. For production, use `tracing_subscriber::fmt::json()` for machine-parseable logs.

**Gap:** No log level configuration via environment variable. The default subscriber captures everything at DEBUG level in debug builds. A verbose DEBUG build in a production environment could emit internal state that is not appropriate.

### 11.2 Client-Side Logging

The CLI uses `eprintln!` for warnings (keyring fallback) and `println!` for output. No `tracing` or `log` framework is used on the CLI side. This is appropriate for a CLI tool.

**Gap:** Error contexts from `anyhow` may include file paths or other system-specific information. If users submit bug reports by copy-pasting error output, the paths in error messages could reveal system layout information. This is low risk but worth noting.

### 11.3 No Telemetry

NullWarden collects no telemetry, usage metrics, or crash reports. This is correct for a security-focused tool and is consistent with the privacy posture.

---

## 12. Compatibility and Portability

**Verdict: PARTIAL — Linux and Windows covered; macOS not in build matrix**

### 12.1 Build Targets

The release workflow (`release.yml`) builds for:
- `x86_64-unknown-linux-musl` (static Linux binary)
- `x86_64-pc-windows-gnu` (Windows binary)

**Missing:** `aarch64-apple-darwin` (Apple Silicon Mac) and `x86_64-apple-darwin` (Intel Mac). macOS is a primary developer platform and a common deployment target. No macOS binary is produced or tested.

**Missing:** `aarch64-unknown-linux-musl` (ARM Linux — Raspberry Pi, AWS Graviton, most modern cloud instances).

### 12.2 File Path Handling

- `VaultStore::new(path)` takes a `PathBuf`. All path operations use `std::path::Path` methods which are platform-aware.
- `atomic_write` uses `path.with_extension("tmp")` — on Windows with a vault path like `C:\Users\user\AppData\Local\nullwarden\vault.nw`, this produces `vault.tmp`. Correct.
- `session.rs` file fallback paths use `dirs::config_dir()` which returns the platform-appropriate config directory (`~/.config/nullwarden` on Linux, `%APPDATA%\nullwarden` on Windows).
- File permissions in `session.rs`: `fs::Permissions::from_mode(0o600)` is gated with `#[cfg(unix)]`. Windows fallback uses plain `fs::write` without permissions. On Windows, file permissions are controlled by ACLs, not Unix mode bits. The session files on Windows are world-readable.

### 12.3 Terminal Compatibility

- `rpassword::read_password()` is cross-platform and works on Windows (using `ReadConsole`) and Linux/macOS (using raw terminal mode).
- `prompt_choice` uses `io::stdin().read_line()` which is cross-platform.
- Output uses `println!` and `eprintln!` — cross-platform.

**Gap:** On Windows, the console code page may not be UTF-8 by default. Passwords or service names with non-ASCII characters may be corrupted in terminal display. The vault file will contain the correct UTF-8 bytes, but the terminal may display garbled characters.

### 12.4 Keyring Compatibility

- Linux: Attempts `secret-service` (D-Bus), falls back to file-based storage.
- macOS: Uses Keychain (via `security-framework`).
- Windows: Uses Credential Manager (via `windows-sys`).
- The fallback file-based storage in `session.rs` is the H-10 fix and provides a fallback for headless environments.

---

## 13. Code Quality and Maintainability

**Verdict: GOOD — Clean separation; dead code and pattern concerns noted**

### 13.1 Module Separation

The workspace structure correctly separates:
- `nullwarden-core`: Pure cryptography, no I/O, no network. This boundary is strongly enforced by the lack of network/IO dependencies in `nullwarden-core/Cargo.toml`.
- `nullwarden-cli`: CLI only, calls into `nullwarden-core` for all crypto operations.
- `nullwarden-server`: Server only, calls into `nullwarden-core` for KDF/type usage only. Does not decrypt vault blobs.
- `nullwarden-fuzz`: Fuzzing targets, isolated.

This is the correct architecture for a zero-knowledge system.

### 13.2 Dead Code

- `AppState::new()` is a deprecated method that always returns `Err`. It should be removed.
- `rls_transaction` in `db/vaults.rs` executes a `SET LOCAL auth.uid` that has no effect (RLS policies are `USING (true)`). The function adds a transaction wrapper that could be replaced with simple pool queries.
- `revoke_all_user_tokens` in `auth/token.rs` is declared but appears to have no call sites (logout only revokes the specific token, not all tokens). Dead code.
- `cleanup_expired_tokens` in `auth/token.rs` is declared but not called anywhere. It needs to be wired into server startup or a background task.
- `is_valid_vault_structure` in `nullwarden-fuzz/src/lib.rs` is declared but not used by any fuzz target.

### 13.3 Pattern Concerns

The comment in `auth/token.rs` from the original broken design ("Let's stick to what's easiest: fetch ALL and verify") has been removed in the C-01 fix, replaced with the correct split-token implementation. However, the new implementation still uses Argon2id for the secret hash (as noted in §1.2). A comment should document why SHA-256 was not chosen and what the tradeoff is.

### 13.4 Test Quality

Unit tests in `nullwarden-core` are genuine and meaningful. The `e2e_sync.rs` test is the project's best integration test — it exercises a real push/pull round-trip against a mock server. The `e2e_add_get.rs` test is a complete local CRUD cycle.

Server integration tests are stubs and provide zero value. They should be replaced before any deployment.

### 13.5 Documentation Quality

- `AGENTS.md` and `GEMINI.md` provide accurate operational documentation.
- `AUDIT_REPORT.md` is comprehensive and accurately reflects findings.
- ADR documents are concise and informative.
- `docs/vault-format-spec.md` documents the binary format — **but it documents `payload_len` at offset 74 (8 bytes) which is NOT present in the actual `VaultHeader::encode()` implementation.** The code encodes: magic(4) + version(1) + m_cost(4) + t_cost(4) + p_cost(4) + salt(32) + nonce(24) = 73 bytes, then the ciphertext immediately follows. The spec document is wrong. This discrepancy must be corrected.

---

## 14. Build and Release Pipeline

**Verdict: PARTIAL — Core pipeline functional; SBOM and macOS missing; fuzz CI theater**

### 14.1 CI Pipeline Analysis

```yaml
# ci.yml — key steps
- run: cargo fmt --all -- --check
- run: cargo clippy -p nullwarden-core -p nullwarden-cli -p nullwarden-server -- -D warnings
- run: cargo build -p nullwarden-core -p nullwarden-cli -p nullwarden-server
- run: cargo build -p nullwarden-fuzz
- run: cargo test -p nullwarden-core -p nullwarden-cli -p nullwarden-server
- run: cargo test -p nullwarden-core -- --ignored kdf_meets_minimum_latency
- uses: taiki-e/install-action@v2  # cargo-audit, cargo-deny, cargo-tarpaulin
- run: cargo audit
- run: cargo deny check
- run: cargo tarpaulin -p nullwarden-core --fail-under 80
```

L-06 fix is present (using `taiki-e/install-action` instead of `cargo install`). Correct.
H-04 fix is present (KDF latency test in CI). Correct.

**Gap:** Coverage gate runs only on `nullwarden-core`. Server coverage is not measured or enforced.

**Gap:** The clippy step explicitly lists `-p nullwarden-core -p nullwarden-cli -p nullwarden-server` and omits `-p nullwarden-fuzz`. If fuzz targets have warnings, they are not caught in CI.

### 14.2 Fuzz CI

```yaml
# fuzz.yml
- run: cargo build -p nullwarden-fuzz
```

This builds the fuzz crate but does not run any fuzzing. The weekly scheduled job verifies compilation only. No coverage corpus is maintained. No coverage-guided fuzzing runs in CI.

The `run-fuzz.sh` script uses `cargo +nightly fuzz run` but this is not connected to CI. **The fuzz CI step is security theater — it provides a green checkmark without providing any actual fuzzing.**

### 14.3 Release Pipeline

```yaml
# release.yml — matrix: x86_64-unknown-linux-musl, x86_64-pc-windows-gnu
- run: cargo build --release -p nullwarden-cli --target ${{ matrix.target }}
- name: Sign with minisign
```

Signing is implemented. The `MINISIGN_SECRET_KEY` is injected from GitHub Secrets. Correct pattern.

**Gap:** Release artifacts are only the CLI binary. The server is not built as a release artifact. A Docker image build is not part of the release workflow (it exists in `Dockerfile` but is not published to any registry in the release workflow).

**Gap:** No SBOM generation. D13 from the deliverables list is not implemented. `cargo cyclonedx` or `syft` should be added to the release workflow.

**Gap:** No SHA-256 checksums published alongside the release artifacts. Minisign signature is present but users should also be able to verify raw file hashes.

**Gap:** `FROM debian:bookworm-slim` in the Dockerfile is not pinned to a digest. The `USER nullwarden` directive is present (M-08 fix is present).

### 14.4 Secret Management in CI

- `MINISIGN_SECRET_KEY` used in release workflow. The signing step uses `echo "${{ secrets.MINISIGN_SECRET_KEY }}" | minisign -S -s /dev/stdin`. This approach pipes the key into minisign's stdin, avoiding writing the key to disk. **This is the correct approach.**
- No other secrets are used in CI. The audit and deny steps don't require secrets.

---

## 15. Privacy and Compliance

**Verdict: ACCEPTABLE for prototype; gaps for any production deployment**

### 15.1 Data Inventory

Data stored by the system:

| Data Type | Storage Location | Sensitivity | Encrypted? |
|-----------|-----------------|-------------|-----------|
| Username | PostgreSQL `users.username` | PII (identifier) | No |
| Auth password | PostgreSQL `users.password_hash` | Credential | Argon2id hash |
| Vault blob | PostgreSQL `vaults.blob` | Critical credential data | Yes (AES via XChaCha20) |
| Refresh token hash | PostgreSQL `refresh_tokens.secret_hash` | Session credential | Argon2id hash |
| Access token hash | PostgreSQL `token_blocklist.token_hash` | Session reference | SHA-256 hash |
| Session file | `~/.config/nullwarden/*.session` | Session credential | No — plaintext token |
| Vault file | `~/.local/share/nullwarden/vault.nw` | Critical credential data | Yes (XChaCha20) |
| Sync state | `~/.local/share/nullwarden/vault.nw.sync` | Metadata | No — version number only |

**Gap:** Session files on disk (H-10 fallback) store plaintext JWT access tokens and refresh tokens. On Unix, these have 0600 permissions. On Windows, no permission restrictions are applied. These files are effectively short-lived session credentials (15-minute access tokens, 7-day refresh tokens) on disk with no encryption.

### 15.2 Data Retention

- Refresh tokens expire after 7 days (enforced in DB via `expires_at` and query filter).
- Access tokens expire after 15 minutes.
- Blocklisted tokens are retained until their `expires_at` but no cleanup job removes them after expiry.
- Vault blobs are retained indefinitely (no retention policy).
- User accounts are retained indefinitely (no deletion mechanism).

**Gap:** No user account deletion mechanism exists. GDPR Article 17 (right to erasure) requires the ability to delete all data associated with a user. The `ON DELETE CASCADE` in the schema would clean up vaults and tokens when a user row is deleted, but there is no API endpoint to trigger user deletion.

### 15.3 Jurisdiction and Infrastructure

NullWarden is a self-hosted system. The jurisdiction depends on where the operator deploys the server. No data is sent to any third-party service. This is privacy-preserving by design.

### 15.4 Terms and Disclosure

No privacy policy, terms of service, or security disclosure statement exists beyond the minimal `.github/SECURITY.md`. For any deployment with real users, these documents are required.

---

## 16. Incident Response and Failure Handling

**Verdict: NOT READY — No runbooks, no incident process, no key rotation procedure**

### 16.1 Missing Runbooks

No incident response documentation exists. The following scenarios have no documented response procedure:

**Scenario 1: JWT secret compromise**
- An attacker obtains the `JWT_SECRET`.
- All existing access tokens can be forged.
- **Response needed:** Rotate `JWT_SECRET`, which invalidates all existing JWTs. All users are logged out and must re-authenticate. Existing refresh tokens in the DB are still valid and can be used to get new access tokens signed with the new secret — which is safe because the refresh token verification is independent of the JWT secret.
- **Currently:** No documentation on how to rotate the JWT secret. No zero-downtime rotation procedure. No user notification mechanism.

**Scenario 2: Database breach**
- An attacker exports the full database.
- They obtain: usernames, Argon2id auth password hashes, encrypted vault blobs, refresh token hashes.
- **Response needed:** Force-expire all refresh tokens, notify users, advise master password rotation (vault blobs are safe but auth accounts may be compromised).
- **Currently:** No notification mechanism. No mass token revocation endpoint. No user communication template.

**Scenario 3: Corrupted vault on server**
- A server bug, hardware failure, or operator error corrupts a vault blob.
- **Response needed:** Restore from DB backup. Notify affected user.
- **Currently:** No backup schedule defined. No point-in-time recovery configured. No user notification mechanism.

**Scenario 4: User reports inability to decrypt vault**
- User changed master password outside the CLI, or vault file was corrupted.
- **Response needed:** User must restore from server (pull). If server blob is also bad, no recovery without a backup.
- **Currently:** No documented recovery procedure for users.

### 16.2 Severity Classification

No severity levels (P0/P1/P2) are defined for incident response. A lost master password and a compromised JWT secret are very different in scope and urgency.

### 16.3 Rollback Procedure

No documented procedure for rolling back a bad server deployment. The server binary can be stopped and the previous binary started manually, but this is not documented.

### 16.4 Communication Plan

No user communication mechanism exists (no email, no in-app notification). If a security incident occurs, there is no way to notify users through the system itself.

---

## 17. Go-Live Checklist

The following checklist must be completed before any production deployment with real user data.

### CRITICAL (Deploy Blockers)

- [ ] **Server integration tests**: Replace all stub tests in `nullwarden-server/tests/` with real integration tests using `testcontainers` (PostgreSQL) or `axum::serve` with an in-memory SQLite backend. At minimum: register → login → push → pull → conflict → logout.
- [ ] **Rate limiting verification**: Confirm `tower_governor` middleware is actually applied to `/auth/login` and `/auth/register` endpoints in `app.rs`. Load-test to verify the 5-req/10-min limit is enforced.
- [ ] **Refresh token secret hash**: Change `issue_refresh_token` to use SHA-256 (via `sha2::Sha256`) + `constant_time_eq` for the secret comparison, not Argon2id. Argon2id on a secret that is already high-entropy and bounded by a single-use DB lookup is incorrect and expensive.
- [ ] **Blocklist cleanup**: Wire `cleanup_expired_tokens` into server startup as a background Tokio task. Add the DB index: `CREATE INDEX ON token_blocklist(expires_at)`.
- [ ] **Remove dead `AppState::new`**: Delete the deprecated constructor that always returns Err.
- [ ] **Remove or document `rls_transaction`**: The `SET LOCAL auth.uid` has no effect with `USING (true)` policies. Either implement real RLS or remove the transaction wrapper and use simple pool queries.

### HIGH (Should be fixed before any external users)

- [ ] **Vault format spec correction**: `docs/vault-format-spec.md` documents a non-existent `payload_len` field. Fix the spec to match the actual binary layout.
- [ ] **macOS build target**: Add `aarch64-apple-darwin` to the release matrix.
- [ ] **SBOM generation**: Add `cargo cyclonedx` to the release workflow. Publish SBOM alongside release artifacts.
- [ ] **User account deletion API**: Add `DELETE /auth/user` endpoint for GDPR compliance.
- [ ] **JWT secret rotation procedure**: Document zero-downtime secret rotation in the deployment guide.
- [ ] **New device restore documentation**: Document the init → pull restore procedure in the CLI manual.
- [ ] **`cleanup_expired_tokens` call site**: Add periodic cleanup job for `token_blocklist` and `refresh_tokens`.
- [ ] **Remove `revoke_all_user_tokens` dead code** or wire it into a session management endpoint.
- [ ] **Server network error wrapping**: Wrap reqwest errors in CLI with user-friendly messages ("Cannot reach server at {url}").

### MEDIUM (Should be fixed before v0.2)

- [ ] **Vault export command**: Implement `nullwarden export [--output path]` to produce an offline encrypted backup.
- [ ] **Session file permissions on Windows**: Implement Windows ACL-based file permission restriction for session token files.
- [ ] **Replace UB zeroize test**: Replace `tests/zeroize.rs` UB test with `cargo miri test` in CI.
- [ ] **Config onboarding flow**: Print a warning when `server_url` is the default localhost and the user runs `push`/`pull` for the first time.
- [ ] **Clipboard manager warning**: Print a message when password is copied to clipboard advising about clipboard managers.
- [ ] **Duplicate entry test**: Add test for `add_entry` returning `DuplicateEntry` on duplicate title.
- [ ] **clear_notes persistence test**: Add test verifying `update_entry` with `Some(None)` actually clears notes through the full save/load cycle.
- [ ] **Conflict UX improvement**: Show entry count delta before conflict resolution prompt.
- [ ] **Log format**: Switch to JSON logging for production (`tracing_subscriber::fmt::json()`).
- [ ] **Docker image publish**: Add Docker image build and push step to release workflow.
- [ ] **Dockerfile digest pinning**: Pin `debian:bookworm-slim` to a specific digest.
- [ ] **Previous version retention**: Store the last vault blob on the server as a backup before overwriting.
- [ ] **Parent directory fsync**: After `fs::rename` in atomic_write, fsync the parent directory for maximum durability.

### LOW (Quality of life)

- [ ] **ARM Linux build target**: Add `aarch64-unknown-linux-musl` to release matrix.
- [ ] **SHA-256 checksums**: Publish `SHA256SUMS` file alongside minisign signatures in releases.
- [ ] **Real fuzz CI**: Replace `cargo build -p nullwarden-fuzz` in `fuzz.yml` with `cargo +nightly fuzz run` with a time limit.
- [ ] **Password-as-CLI-arg warning**: Print warning when a password is provided as a positional argument.
- [ ] **JWT issuer/audience claims**: Add `iss` and `aud` claims to JWTs and validate them to prevent token reuse across environments.
- [ ] **Pool configuration**: Document and configure `PgPool` connection pool size via environment variable.
- [ ] **Retry logic**: Add exponential backoff for push/pull network failures.
- [ ] **Privacy policy**: Draft and publish a minimal privacy policy document.

---

## Summary Table

| Dimension | Status | Blockers |
|-----------|--------|----------|
| Security | ⚠️ Conditional | Refresh token Argon2 cost, rate limit verification |
| Cryptography | ✅ Pass | None |
| Functional Correctness | ⚠️ Partial | Server integration tests are stubs |
| UX / CLI | ⚠️ Partial | No onboarding, poor error messages |
| Accessibility | ✅ Acceptable | None for CLI scope |
| Performance | ✅ Acceptable | No large vault benchmarks |
| Reliability | ✅ Pass | Minor Windows rename gap |
| Data Recovery | ❌ Fail | No export command; no version history |
| Backend / API | ⚠️ Conditional | Dead RLS wrapper, missing rate limit verification |
| Database Design | ⚠️ Conditional | No blocklist index, no cleanup, no user deletion |
| Logging | ✅ Pass | No structured JSON format |
| Compatibility | ⚠️ Partial | No macOS build |
| Code Quality | ✅ Good | Dead code, spec mismatch |
| Build / Release | ⚠️ Partial | No SBOM, fuzz CI theater |
| Privacy | ⚠️ Conditional | No user deletion, no retention policy |
| Incident Response | ❌ Fail | No runbooks, no procedures |

**Legend:** ✅ = Go | ⚠️ = Conditional | ❌ = No-Go

---

*NullWarden Pre-Go-Live Analysis v1.0*  
*Generated: 2026-04-20*  
*Next review: After critical and high items are resolved*
