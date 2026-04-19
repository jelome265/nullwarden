# NullWarden — Deep Security & Code Audit Report

**Date:** 2026-04-19  
**Auditor:** Internal Security Engineering  
**Scope:** Full codebase — `nullwarden-core`, `nullwarden-cli`, `nullwarden-server`, `nullwarden-fuzz`, CI/CD, Dockerfile, migrations  
**Commit:** HEAD  

---

## Summary

NullWarden has a sound cryptographic foundation. The primitives are correct: Argon2id KDF, XChaCha20-Poly1305 AEAD, per-operation CSPRNG nonces, Zeroize on sensitive types. The zero-knowledge architecture is architecturally correct — the server stores opaque ciphertext only. However, surrounding infrastructure contains severe implementation defects that undermine the security guarantees: a DoS-class O(n) token scan with Argon2, a timing oracle on login, a blocking CLI thread, broken fuzz harness configuration, and critical operational mistakes in Docker and migrations. All must be fixed before any deployment.

**Findings: 8 CRITICAL · 11 HIGH · 9 MEDIUM · 6 LOW**

---

## Table of Contents

1. [Cryptographic Core Review](#1-cryptographic-core-review)
2. [CRITICAL Findings](#2-critical-findings)
3. [HIGH Findings](#3-high-findings)
4. [MEDIUM Findings](#4-medium-findings)
5. [LOW Findings](#5-low-findings)
6. [Code Quality & Architecture](#6-code-quality--architecture)
7. [CI/CD & Supply Chain](#7-cicd--supply-chain)
8. [Remediation Summary](#8-remediation-summary)

---

## 1. Cryptographic Core Review

### 1.1 KDF (kdf.rs) — PASS with notes

```rust
// Correct: Argon2id, proper params, CSPRNG salt
pub fn derive_key(password: &[u8], salt: &[u8; SALT_LEN], params: KdfParams) -> Result<VaultEncryptionKey, VaultError>
```

Argon2id with `m=65536, t=3, p=4` is correct. Salt is 32 bytes, key output is 32 bytes. No weaknesses in the KDF itself.

**Note:** The bench guard in `kdf_bench.rs` panics if `< 300ms` but `cargo bench` is not executed in CI (`ci.yml` has no bench step). The guard is dead code in practice. See finding H-04.

### 1.2 AEAD (crypto.rs) — PASS

```rust
// Correct: XChaCha20Poly1305 with CSPRNG nonce per operation
pub fn encrypt(key: &VaultEncryptionKey, plaintext: &[u8]) -> Result<(VaultNonce, Vec<u8>), VaultError>
```

192-bit nonce per operation from `OsRng`. No nonce reuse risk. AEAD tag is included in the ciphertext slice by the chacha20poly1305 crate.

### 1.3 Vault Header (header.rs) — FAIL: format_version not validated

```rust
pub fn decode(input: &[u8]) -> Option<(Self, usize)> {
    // ...
    let format_version = input[4];  // Any byte accepted — no version check
    // ...
}
```

A malformed vault file with `format_version = 0xFF` is silently accepted and processed. See finding C-05.

### 1.4 Vault Store (store.rs) — PASS with notes

Atomic write via `write-tmp → sync_all → rename` is correct. The error path does not clean up the `.tmp` file. See finding H-06.

### 1.5 Zeroize (types.rs) — PASS

`VaultEncryptionKey`, `SecretString`, `SecretBytes` all implement `Zeroize + ZeroizeOnDrop`. The zeroize test at `tests/zeroize.rs` uses `unsafe` to read freed memory (documented UB) but the intent is correct. Replace with `miri` or `valgrind` in CI for production. `VaultNonce` intentionally does not zeroize (nonces are public).

---

## 2. CRITICAL Findings

### C-01 — O(n) Argon2 Scan on Refresh Token Validation — DoS / Timing Oracle

**File:** `crates/nullwarden-server/src/auth/token.rs:consume_refresh_token`  
**Severity:** CRITICAL — Denial of Service + Timing Side-Channel  

```rust
// BROKEN: fetches ALL refresh tokens from DB, runs Argon2 on each
let rows = sqlx::query("SELECT token_hash, user_id FROM refresh_tokens")
    .fetch_all(&state.db)
    .await;

for row in rows {
    let hash: String = row.get("token_hash");
    if verify_password(&hash, token).await.unwrap_or(false) { ... }
}
```

**Impact:**  
- An attacker sending rapid refresh requests causes the server to run Argon2id verification against every stored token in the database for each request. At 300ms per Argon2 call × N tokens, this is catastrophically slow. With 1,000 users × 2 sessions each = 2,000 Argon2 calls per refresh attempt.  
- Additionally, the verification time correlates with the token's position in the result set, creating a timing oracle that leaks token ordering.

**Root cause:** Argon2 uses a random salt embedded in the PHC string, so you cannot compute a hash and look it up by hash. The original developer attempted to use Argon2 for tokens where it is architecturally inappropriate.

**Fix:** Use a split-token design. Issue tokens as `{id}:{secret}` where `id` is stored in plain (indexed) and only `secret` is hashed with a fast MAC (HMAC-SHA256 or SHA-256 with constant-time compare). The client stores the full `{id}:{secret}`, the server looks up by `id` in O(1) and verifies `secret` in constant time.

```rust
// Fixed design
pub async fn issue_refresh_token(state: &SharedState, user_id: Uuid) -> anyhow::Result<String> {
    let token_id = Uuid::new_v4();
    let secret = generate_secret_bytes(); // 32 random bytes, hex-encoded
    let secret_hash = sha256_hash(&secret);
    sqlx::query("INSERT INTO refresh_tokens (id, secret_hash, user_id, expires_at) VALUES ($1,$2,$3,$4)")
        .bind(token_id).bind(secret_hash).bind(user_id).bind(expiry)
        .execute(&state.db).await?;
    Ok(format!("{}:{}", token_id, secret))
}

pub async fn consume_refresh_token(state: &SharedState, token: &str) -> Option<Uuid> {
    let (id_str, secret) = token.split_once(':')?;
    let token_id = Uuid::parse_str(id_str).ok()?;
    let row = sqlx::query("SELECT secret_hash, user_id FROM refresh_tokens WHERE id = $1 AND expires_at > now()")
        .bind(token_id).fetch_optional(&state.db).await.ok()??;
    let stored_hash: String = row.get("secret_hash");
    let candidate_hash = sha256_hash(secret);
    if constant_time_eq(stored_hash.as_bytes(), candidate_hash.as_bytes()) {
        let user_id = row.get("user_id");
        sqlx::query("DELETE FROM refresh_tokens WHERE id = $1")
            .bind(token_id).execute(&state.db).await.ok()?;
        Some(user_id)
    } else {
        None
    }
}
```

---

### C-02 — Login Timing Oracle: Username Enumeration

**File:** `crates/nullwarden-server/src/handlers/auth.rs:login`  
**Severity:** CRITICAL — Authentication bypass class / Username enumeration  

```rust
pub async fn login(...) -> Result<Json<AuthResponse>, StatusCode> {
    let user = users::find_user(&state, &payload.username)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;  // FAST: returns immediately for unknown username
    let ok = password::verify_password(&user.password_hash, &payload.password)
        .await  // SLOW: 300ms Argon2 for known username
        ...
```

**Impact:** An attacker can enumerate valid usernames by timing responses. Requests for unknown usernames return in ~1ms (DB miss). Requests for known usernames with wrong passwords return in ~300ms (Argon2 verify). At statistical significance, this leaks the full username list.

**Fix:** Always run Argon2 verification, even when the user is not found, using a dummy hash.

```rust
// In handlers/auth.rs
pub async fn login(...) -> Result<Json<AuthResponse>, StatusCode> {
    let user_opt = users::find_user(&state, &payload.username).await;
    
    // Always verify to prevent timing oracle — constant time behavior
    let dummy_hash = state.dummy_hash.clone(); // pre-computed at startup
    let hash = user_opt.as_ref().map(|u| u.password_hash.as_str()).unwrap_or(&dummy_hash);
    let ok = password::verify_password(hash, &payload.password)
        .await
        .unwrap_or(false);
    
    if !ok || user_opt.is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    // ...
}
```

The dummy hash must be computed at server startup (not per-request, to avoid the cost adding latency):

```rust
// AppState::new()
let dummy_hash = password::hash_password_sync("dummy_password_never_used_xyz_!@#").await?;
```

---

### C-03 — Compile Failure: HeaderValue Type Mismatch

**File:** `crates/nullwarden-server/src/handlers/vault.rs:get_vault`  
**Severity:** CRITICAL — Server fails to compile; vault GET endpoint non-functional  

```rust
response_headers.insert("X-Vault-Version", vault.version.into());
//                                          ^^^^^^^^^^^^^^^^^^
// ERROR: u64 does not implement Into<HeaderValue>
// This is a type error that prevents the server from compiling.
```

**Fix:**
```rust
response_headers.insert(
    "X-Vault-Version",
    HeaderValue::from_str(&vault.version.to_string())
        .expect("version is always a valid header value"),
);
```

---

### C-04 — Fuzz Harness Non-Functional: Missing Dependencies

**File:** `crates/nullwarden-fuzz/Cargo.toml`, `fuzz_targets/*.rs`  
**Severity:** CRITICAL — Fuzz testing completely non-operational  

The fuzz targets import `libfuzzer_sys::fuzz_target!` and `rmp_serde`, neither of which is declared in `Cargo.toml`:

```toml
# Current (BROKEN):
[dependencies]
nullwarden-core = { path = "../nullwarden-core" }
# Missing: libfuzzer-sys, rmp-serde, [[bin]] entries with harness=false
```

`cargo build -p nullwarden-fuzz` will fail. The CI `fuzz.yml` will always succeed vacuously because the build would fail but the CI step runs `cargo build` (not `cargo fuzz`), which doesn't actually fuzz anything. The fuzz CI step is a theater of security.

**Fix:**
```toml
[package]
name = "nullwarden-fuzz"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
nullwarden-core = { path = "../nullwarden-core" }
libfuzzer-sys = "0.4"
rmp-serde = "1.1"

[[bin]]
name = "decrypt_input"
path = "fuzz_targets/decrypt_input.rs"
harness = false

[[bin]]
name = "vault_deserialize"
path = "fuzz_targets/vault_deserialize.rs"
harness = false
```

The `fuzz.yml` workflow should also be updated to use `cargo +nightly fuzz run` via `cargo-fuzz`, not `cargo build`.

---

### C-05 — VaultHeader format_version Not Validated

**File:** `crates/nullwarden-core/src/vault/header.rs:decode`  
**Severity:** CRITICAL — Malformed vault accepted; future format confusion  

```rust
pub fn decode(input: &[u8]) -> Option<(Self, usize)> {
    // ...
    let format_version = input[4];  // 0xFF, 0x00, any byte accepted
    // No check: if format_version != Self::FORMAT_VERSION { return None; }
```

A vault file with `format_version = 0x02` (a future format that this version of the code cannot parse correctly) will be silently "decoded" using version-1 parsing logic, producing corrupt KDF parameters. This could cause silent data loss (wrong key derived, decryption fails with a confusing error) or, in a forward-compatibility scenario, misinterpret fields.

**Fix:**
```rust
pub fn decode(input: &[u8]) -> Option<(Self, usize)> {
    let header_len = 4 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN;
    if input.len() < header_len || input[..4] != Self::MAGIC {
        return None;
    }
    let format_version = input[4];
    if format_version != Self::FORMAT_VERSION {
        return None;  // ADD THIS
    }
    // ...
}
```

---

### C-06 — docker-compose Uses `.env.example` as Production Env

**File:** `docker-compose.yml`  
**Severity:** CRITICAL — Production deployment with placeholder credentials  

```yaml
services:
  server:
    env_file:
      - .env.example   # ← SHIPS PLACEHOLDER JWT_SECRET="CHANGE_ME_..."
```

Any deployment that uses `docker-compose up` will run with `JWT_SECRET=CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32`. This means all JWT tokens can be forged by anyone who reads `.env.example` (which is in the public repo).

**Fix:** Use `.env` (which must be gitignored):
```yaml
env_file:
  - .env
```

Add to README: "Copy `.env.example` to `.env` and fill in all required values before running."

---

### C-07 — Migration RLS References `auth.uid()` — Breaks Non-Supabase PostgreSQL

**File:** `crates/nullwarden-server/migrations/20260101000000_create_users.sql` and siblings  
**Severity:** CRITICAL — Server fails to start on vanilla PostgreSQL  

```sql
CREATE POLICY "Users can only see themselves" ON users
    FOR SELECT USING (auth.uid() = id);
-- ERROR: function auth.uid() does not exist
```

`auth.uid()` is a Supabase-specific extension function. It does not exist in standard PostgreSQL. Any deployment against a non-Supabase PostgreSQL instance (including the `docker-compose.yml` which uses `postgres:16`) will fail with `ERROR: schema "auth" does not exist`.

**Fix:** Remove the RLS policies from migrations entirely. The server already enforces access control at the application layer (JWT auth middleware + user_id scoping in every query). Server-side RLS with `auth.uid()` is redundant when the application correctly scopes all queries by authenticated user_id. If Supabase RLS is desired, it should be in a separate `supabase/` directory, not the core migrations.

---

### C-08 — `get.rs` CLI Blocks for 30 Seconds — Process Hangs

**File:** `crates/nullwarden-cli/src/commands/get.rs`  
**Severity:** CRITICAL — CLI unusable for clipboard mode; all resources held for 30s  

```rust
tokio::time::sleep(Duration::from_secs(30)).await;
// This blocks the entire CLI process for 30 seconds
// The user cannot use the terminal during this time
// All file descriptors, memory, and the vault remain open
```

This is not a background task. This is the main `run()` function, which blocks `main()` for 30 seconds. The vault remains partially unlocked in memory (the entry password is still in scope). This defeats the "lock by exit" model: the process holds the copied password in a variable for 30 seconds.

**Fix:** Print a warning and exit immediately. The clipboard clearing is a best-effort operation on most systems. Use a detached subprocess or simply advise the user:

```rust
if !print {
    let mut cb = Clipboard::new().context("failed to access clipboard")?;
    cb.set_text(entry.password.0.clone())
        .context("failed to copy to clipboard")?;
    println!("Password copied to clipboard. Clear it manually after use.");
    // DO NOT sleep 30 seconds — exit immediately
}
```

If clipboard auto-clearing is required, spawn a detached background process (`std::process::Command::new(std::env::current_exe()?)` with a `--clear-clipboard` subcommand) that sleeps 30s and then clears.

---

## 3. HIGH Findings

### H-01 — Refresh Token Migration Missing Expiry and Index

**File:** `crates/nullwarden-server/migrations/20260101000002_create_refresh_tokens.sql`  
**Severity:** HIGH — Token pollution; no expiry; performance  

```sql
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    -- MISSING: expires_at TIMESTAMPTZ NOT NULL
    -- MISSING: INDEX on user_id
    -- MISSING: INDEX on expires_at (for cleanup)
);
```

Tokens never expire at the database level. Even after fix C-01 introduces `id`-based lookup, old tokens accumulate forever. No index on `user_id` means cascade deletes on user are O(n) scans.

**Fix:**
```sql
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_hash TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
```

Add a cleanup job (cron or periodic task in server startup) to delete expired tokens:
```sql
DELETE FROM refresh_tokens WHERE expires_at < now();
```

---

### H-02 — `atomic_write` Does Not Clean Up `.tmp` on Error

**File:** `crates/nullwarden-core/src/vault/store.rs:atomic_write`  
**Severity:** HIGH — Stale `.tmp` files; potential data confusion  

```rust
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    let tmp_path = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
    }
    fs::rename(tmp_path, path)?;
    // If write_all or sync_all fails, tmp_path is left on disk — no cleanup
    Ok(())
}
```

If `write_all` or `sync_all` fails, `vault.nw.tmp` remains on disk. On the next run, `File::create` will truncate and overwrite it, so data loss is unlikely. However, if the path is locked on Windows (antivirus, backup software), the stale `.tmp` file could persist indefinitely and confuse diagnostic tooling.

**Fix:**
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
        let _ = fs::remove_file(&tmp_path); // best-effort cleanup
        return Err(e);
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}
```

---

### H-03 — Rate Limit Configuration Mismatch: Per-Second vs Per-10-Minutes

**File:** `crates/nullwarden-server/src/middleware/rate_limit.rs`  
**File:** `.env.example`  
**Severity:** HIGH — Actual rate limit is 300× more permissive than documented  

```ini
# .env.example says:
RATE_LIMIT_AUTH_REQUESTS=5  # "5 requests per 10 min per IP"
```

```rust
// But rate_limit.rs uses:
GovernorConfigBuilder::default()
    .per_second(requests as u64)  // 5 per SECOND, not per 10 minutes
    .burst_size(requests)
```

5 requests per second = 300 requests per minute = 3,000 requests per 10 minutes. The documented rate limit of "5 per 10 minutes" for auth endpoints would stop brute force. The actual rate limit of "5 per second" allows 3,000 password attempts per 10 minutes, which provides negligible protection.

**Fix:**
```rust
// Use per_millisecond for correct token bucket semantics
// 5 requests per 600 seconds = 1 request per 120 seconds
GovernorConfigBuilder::default()
    .per_millisecond((600_000 / requests as u64).max(1))
    .burst_size(requests)
```

Or add a `rate_limit_auth_window_secs` config field and compute the correct rate.

---

### H-04 — KDF Timing Gate in CI: Unreachable Code

**File:** `crates/nullwarden-core/benches/kdf_bench.rs`  
**File:** `.github/workflows/ci.yml`  
**Severity:** HIGH — NFR-P1 (≥300ms KDF gate) is completely unenforced  

```rust
// kdf_bench.rs panics if < 300ms:
if elapsed < Duration::from_millis(300) {
    panic!("KDF too fast: {:?}.", elapsed);
}
```

```yaml
# ci.yml has no cargo bench step — the gate never runs:
- run: cargo fmt --all -- --check
- run: cargo clippy --workspace --all-targets -- -D warnings
- run: cargo test --workspace
- name: Audit dependencies
  run: cargo audit
```

The `kdf_bench.rs` code is dead from a CI enforcement perspective. A developer can reduce `m_cost` to `1024` and CI will not catch it.

**Fix:** Add a dedicated test that asserts KDF timing in the test suite (not benchmarks):

```rust
// crates/nullwarden-core/tests/kdf_params.rs — add:
#[test]
#[ignore = "timing test — run explicitly with: cargo test -- --ignored"]
fn kdf_meets_minimum_latency() {
    let salt = [9_u8; 32];
    let params = KdfParams::default();
    let start = std::time::Instant::now();
    derive_key(b"testpassword", &salt, params).unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_millis(300),
        "KDF latency {elapsed:?} is below the 300ms minimum — Argon2 params have been weakened"
    );
}
```

Add to CI: `cargo test -- --ignored kdf_meets_minimum_latency`

---

### H-05 — `SecretString` Implements `Serialize`: Accidental Secret Serialization Risk

**File:** `crates/nullwarden-core/src/types.rs`  
**Severity:** HIGH — Vault passwords can be silently included in JSON/log serialization  

```rust
impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)  // Serializes the plaintext value
    }
}
```

This is intentional for vault storage (the encrypted payload uses MessagePack), but it means any code that serializes a struct containing `SecretString` (e.g., `VaultEntry`) into JSON, a log statement with `{:?}` via serde-derived Debug, or accidentally into an HTTP response will leak plaintext passwords. The `Debug` impl correctly says `***REDACTED***`, but `serde::Serialize` uses the raw value.

**Fix:** Keep `Serialize` but add a guard: `Debug` is already correct. The real risk is accidental HTTP serialization. Consider using a newtype wrapper that serializes as `"<redacted>"` by default and only exposes the inner value through an explicit `.expose_secret()` call (similar to `secrecy` crate pattern). Alternatively, do not derive `Serialize` on `VaultEntry` directly for HTTP handler use — only use it for the internal msgpack vault payload path.

At minimum, document clearly with `#[doc = "WARNING: Serializes plaintext. Only for encrypted vault payload."]`.

---

### H-06 — `push.rs` Force Push Sends `expected_version: 0` — Silent Version Reset

**File:** `crates/nullwarden-cli/src/commands/push.rs`  
**Severity:** HIGH — Force push resets server version to 1 unconditionally  

```rust
let new_version = client.push(&config.vault_path, 0, true).await?;
// In SyncClient::push, when force=true, expected_version header is still sent as 0
// In db/vaults.rs, force=true uses UPSERT which resets version to 1 or increments
```

The UPSERT on force push:
```sql
ON CONFLICT (user_id) DO UPDATE SET blob = EXCLUDED.blob, version = vaults.version + 1
```

This correctly increments. But the initial INSERT path sets `version = 1`, which means if a user force-pushes to an existing vault at version 50, the new version is 51 (correct via the ON CONFLICT path). However, if the user is on a fresh account, force push creates a new vault at version 1, which is also correct. The logic is actually fine — but the `expected_version: 0` passed when `force=true` gets sent as the `X-If-Match: 0` header, which is then ignored because `force=true` takes precedence. The 0 is misleading but not incorrect.

The real issue: the `SyncClient::push` still sends `X-If-Match: 0` even when `force=true`:

```rust
if force {
    request = request.header("X-Force", "true");
} else if expected_version > 0 {
    request = request.header("X-If-Match", expected_version.to_string());
}
// But when force=true AND expected_version=0, no If-Match is set — this is correct
```

Actually this is OK. The issue is that `expected_version: 0` is explicitly passed to `push()` as a signal for "no version", which the function correctly handles via the `else if expected_version > 0` branch. Low risk, but API is confusing. Rename the parameter to make intent clear.

Actually, the higher severity issue in force-push is: there's no confirmation that a force-push is destructive. A user selecting "keep local" in conflict resolution triggers a force push that silently overwrites the remote vault. If the remote was the newer/correct version, this causes permanent data loss. **Require a second confirmation prompt for force pushes.**

---

### H-07 — Refresh Token Not Scoped to One Device / Session

**File:** `crates/nullwarden-server/src/auth/token.rs`  
**Severity:** HIGH — Refresh token theft allows persistent access with no revocation signal  

There is no device identifier, session ID, or user-agent binding on refresh tokens. A stolen refresh token can be used from any IP/device indefinitely until expiry. The `consume_refresh_token` function also has no expiry check:

```rust
// No expiry column in the table (see H-01), no expiry check in consume logic
let rows = sqlx::query("SELECT token_hash, user_id FROM refresh_tokens").fetch_all(...)
```

Even after fixing C-01 and H-01, tokens must be:
1. Scoped with an `expires_at` (7 days per `.env.example`)
2. Checked against `expires_at > now()` on every use
3. Optionally bound to a user-agent or device fingerprint

---

### H-08 — `VaultEncryptionKey` Stack Allocation: Zeroize May Be Optimized Away

**File:** `crates/nullwarden-core/src/types.rs`  
**Severity:** HIGH — Compiler may elide zeroize on stack frames  

```rust
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultEncryptionKey(pub [u8; 32]);
```

The `zeroize` crate uses `volatile_set_memory` / compiler fence to prevent optimizations on `drop`. However, when `VaultEncryptionKey` is stored on the stack and passed by value (not heap), LLVM may still optimize away the write if it can prove no subsequent read occurs — especially in `--release` builds with LTO enabled. The `Zeroize` crate mitigates this with `compiler_fence(SeqCst)` but does not guarantee it across all platforms and LLVM versions.

**Mitigation (not a complete fix, but hardening):** Pin key material on the heap using `Box<[u8; 32]>` with `mlock()` where available. Consider the `secmem-proc` or `memsec` crate. At minimum, add `#[inline(never)]` to functions that hold key material to reduce LLVM's optimization view.

---

### H-09 — Missing CORS / Origin Validation on Server

**File:** `crates/nullwarden-server/src/app.rs`  
**Severity:** HIGH — CORS not configured; browser-based attackers can make authenticated requests  

There is no CORS middleware in the Axum router. If the server is accessed from a browser (e.g., a future web UI), any malicious website can make authenticated requests using the user's session cookies (if cookies were used) or trigger preflight-less requests. While the current auth mechanism uses `Authorization: Bearer` headers (which require CORS preflight), the absence of explicit CORS configuration is a security gap that should be closed proactively.

**Fix:** Add explicit CORS middleware with `tower_http::cors::CorsLayer` configured to allow only the application's own origin:

```rust
use tower_http::cors::{CorsLayer, AllowOrigin};

let cors = CorsLayer::new()
    .allow_origin(AllowOrigin::exact("https://app.nullwarden.io".parse()?))
    .allow_methods([Method::GET, Method::PUT, Method::POST])
    .allow_headers([AUTHORIZATION, CONTENT_TYPE]);
```

---

### H-10 — CLI `session.rs` Has No Fallback for Missing Keyring

**File:** `crates/nullwarden-cli/src/session.rs`  
**Severity:** HIGH — CLI completely unusable on headless servers or CI environments  

```rust
pub fn load_access_token() -> anyhow::Result<String> {
    let entry = Entry::new("nullwarden", "access_token")?;
    entry.get_password().context("no active session. please login or register.")
}
```

On headless Linux systems without a D-Bus session (e.g., Docker containers, CI, SSH sessions), the `keyring` crate will fail to initialize with an error like `No such interface 'org.freedesktop.Secret.Service'`. This makes push/pull completely non-functional on common deployment environments.

**Fix:** Implement a fallback file-based token store (e.g., `~/.config/nullwarden/session.json`) with `0600` permissions when the keyring is unavailable:

```rust
pub fn load_access_token() -> anyhow::Result<String> {
    load_from_keyring("access_token")
        .or_else(|_| load_from_file("access_token"))
        .context("no active session. please login or register.")
}
```

---

### H-11 — `db/vaults.rs:put_vault` First-Push Doesn't Handle Concurrent Insert Race

**File:** `crates/nullwarden-server/src/db/vaults.rs`  
**Severity:** HIGH — TOCTOU race on first vault push  

```rust
// First push path:
sqlx::query("INSERT INTO vaults (user_id, blob, version) VALUES ($1, $2, 1) RETURNING ...")
```

If two devices simultaneously push their first vault (e.g., user registers on two devices and both try to push before either pulls), one INSERT succeeds and the other fails with a unique constraint violation, which is mapped to `RowNotFound` and returned as HTTP 409. The second device gets a 409 but has no `current_version` in the response body to understand what happened. The conflict resolution path in the CLI only handles version-mismatch 409s, not first-push 409s.

**Fix:** Use `INSERT ... ON CONFLICT DO NOTHING RETURNING ...` for the first push and detect the no-rows case explicitly:

```sql
INSERT INTO vaults (user_id, blob, version) VALUES ($1, $2, 1)
ON CONFLICT (user_id) DO NOTHING
RETURNING user_id, version, blob
```

If no rows returned → conflict, return 409 with the current server version so the client can resolve properly.

---

## 4. MEDIUM Findings

### M-01 — `token_blocklist` Has No Expiry Cleanup Job

**File:** `crates/nullwarden-server/migrations/20260101000003_create_token_blocklist.sql`  
**Severity:** MEDIUM  

The `token_blocklist` table grows indefinitely. Expired tokens (past `expires_at`) should be purged. The table will accumulate millions of entries over time.

**Fix:** Add a periodic cleanup query executed on server startup and/or via a cron job:
```sql
DELETE FROM token_blocklist WHERE expires_at < now();
```

---

### M-02 — `consume_refresh_token` Silently Ignores DB Errors

**File:** `crates/nullwarden-server/src/auth/token.rs`  
**Severity:** MEDIUM — DB errors return None instead of an error  

```rust
Err(e) => {
    error!("DB consume_refresh_token failed: {}", e);
    None  // Returns "invalid token" on DB failure
}
```

A database connection failure is indistinguishable from an invalid token. This causes a transient DB failure during refresh to log out the user silently. The server returns 401, and the user must log in again.

**Fix:** Return `Option<Result<Uuid, _>>` or propagate the error explicitly so the handler can return 503 Service Unavailable on DB failure rather than 401.

---

### M-03 — `VaultData` Derives `Zeroize` but `version: u64` Is Zeroized

**File:** `crates/nullwarden-core/src/vault/data.rs`  
**Severity:** MEDIUM — Correctness issue; not a security failure  

```rust
#[derive(Debug, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultData {
    #[zeroize(skip)]
    pub version: u64,   // correctly skipped
    pub entries: Vec<VaultEntry>,
}
```

`version` is correctly `#[zeroize(skip)]`. However, `Vec<VaultEntry>` will be zeroized (the vec's backing allocation is zeroed), but only after the entries themselves are dropped. If `VaultEntry` is cloned elsewhere (e.g., passed to a display function), the clone is not zeroized. The `Zeroize` on `VaultData` only zeroizes the local instance.

This is documented behavior of the `zeroize` crate but is a common pitfall. Review all call sites that might clone `VaultEntry` objects to ensure they don't outlive the original.

---

### M-04 — `VaultEntry.id` Is a UUID v4: Good, but Not Documented as Opaque

**File:** `crates/nullwarden-core/src/vault/data.rs`  
**Severity:** MEDIUM — Information disclosure risk  

UUID v4 is random and non-sequential, which is correct. However, `VaultEntry.id` is serialized into the vault payload. If two devices independently add entries, the IDs are different. The sync protocol (push/pull) treats the entire vault as an opaque blob and last-write-wins. This means entries added on one device can be silently lost when the other device pushes.

This is documented as a known limitation ("last-write-wins") but is not surfaced to the user at conflict resolution time. The conflict prompt should tell the user how many entries differ between versions.

---

### M-05 — `update.rs` Notes Cannot Be Cleared

**File:** `crates/nullwarden-cli/src/commands/update.rs`  
**Severity:** MEDIUM — Feature gap; user cannot remove notes from an entry  

```rust
vault.update_entry(&title, username, password, notes.map(Some))?;
```

If `notes` is `None` (user didn't pass `--notes`), `update_entry` receives `None` which means "no change." There is no way to set notes to empty. The `update_entry` signature uses `Option<Option<String>>` for notes but the CLI never passes `Some(None)`.

**Fix:** Add a `--clear-notes` flag:
```rust
#[arg(long)]
clear_notes: bool,
// ...
let notes_update = if clear_notes {
    Some(None)  // explicitly clear
} else {
    notes.map(Some)  // update or no-change
};
```

---

### M-06 — `register.rs` Does Not Validate Auth Password Strength

**File:** `crates/nullwarden-cli/src/commands/register.rs`  
**Severity:** MEDIUM — Auth password may be weak; allows dictionary attacks on server auth  

```rust
pub async fn run(username: String, password: Option<String>) -> anyhow::Result<()> {
    // No validate_password_strength() call
    AuthClient::new(config.server_url).register(username, password).await?;
}
```

`init.rs` calls `validate_password_strength` for the master password. `register.rs` does not validate the auth password. While the auth password is independent of the vault key, a weak auth password enables server-side account takeover (even though this doesn't break zero-knowledge for the vault contents, it breaks account integrity and allows vault deletion/replacement).

**Fix:** Add `validate_password_strength(&password)?;` before the network call in `register.rs`.

---

### M-07 — No Request Body Size Limit on Vault Upload

**File:** `crates/nullwarden-server/src/handlers/vault.rs`  
**Severity:** MEDIUM — DoS via large vault upload  

```rust
pub async fn put_vault(
    ...
    body: Bytes,  // No size limit
) -> Result<impl IntoResponse, StatusCode>
```

Axum's default body size limit is 2MB. For a password vault this is generous, but it should be explicitly configured to prevent OOM attacks via very large uploads. A malicious authenticated user could send gigabyte payloads.

**Fix:** Add explicit body size limit layer:
```rust
// In app.rs
use axum::extract::DefaultBodyLimit;
Router::new()
    .layer(DefaultBodyLimit::max(10 * 1024 * 1024)) // 10MB vault max
```

---

### M-08 — `Dockerfile` Runs as Root

**File:** `Dockerfile`  
**Severity:** MEDIUM — Container privilege escalation risk  

```dockerfile
FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder ...
EXPOSE 8080
CMD ["nullwarden-server"]
# No USER directive — runs as root inside container
```

If the server is compromised, the attacker has root inside the container. With certain Docker configurations (no user namespace remapping), this can escalate to host root.

**Fix:**
```dockerfile
RUN groupadd -r nullwarden && useradd -r -g nullwarden nullwarden
USER nullwarden
CMD ["nullwarden-server"]
```

---

### M-09 — `deny.toml` `multiple-versions = "warn"` Should Be `"deny"` for Security Crates

**File:** `deny.toml`  
**Severity:** MEDIUM — Multiple versions of security-critical crates can cause subtle bugs  

```toml
[bans]
multiple-versions = "warn"
```

Having two versions of `argon2`, `chacha20poly1305`, or `zeroize` in the dependency tree can cause type incompatibilities where the wrong version's types are used silently. This is especially dangerous for cryptographic types.

**Fix:**
```toml
[bans]
multiple-versions = "deny"
skip = [
    # Document any known acceptable duplicates here with reason
]
```

---

## 5. LOW Findings

### L-01 — `zeroize.rs` Test Uses Undefined Behavior

**File:** `crates/nullwarden-core/tests/zeroize.rs`  
**Severity:** LOW — Documented UB; test may produce false passes in release mode  

Reading memory after it has been freed (dropped) is undefined behavior in Rust. The test is documented as intentional UB for testing purposes, but LLVM may reorder or eliminate the write-after-drop in release mode, making the test pass vacuously (the memory was never actually zeroed — LLVM just never wrote non-zero bytes to that location in the first place).

**Fix:** Use `cargo-valgrind` or `miri` for proper memory zeroing verification in CI instead of this UB test. Remove the UB test and replace with:
```
cargo miri test vault_key_zeroizes_on_drop
```

---

### L-02 — `VaultStore.params` Is Always `KdfParams::default()`: No Custom Params

**File:** `crates/nullwarden-core/src/vault/store.rs`  
**Severity:** LOW — Future flexibility blocked  

```rust
pub fn new(path: impl Into<PathBuf>) -> Self {
    Self {
        path: path.into(),
        params: KdfParams::default(),  // hardcoded, no constructor with custom params
    }
}
```

If a user needs to increase KDF parameters (NFR migration path, per ADR-002's recommendation), there is no `VaultStore::with_params(path, params)` constructor. All callers get the default parameters.

**Fix:** Add `pub fn with_params(path, params) -> Self`.

---

### L-03 — `lock.rs` Is Misleading — Does Nothing

**File:** `crates/nullwarden-cli/src/commands/lock.rs`  
**Severity:** LOW — UX confusion  

```rust
pub async fn run() -> anyhow::Result<()> {
    println!("NullWarden CLI uses a 'lock by exit' model.");
    println!("Since the CLI process terminates after each command, no key material persists in memory.");
    println!("The vault is implicitly locked upon command completion.");
    Ok(())
}
```

The `lock` command is documented in the README and AGENTS.md as a real operation that "zeroizes the in-memory derived key." The implementation is a no-op that prints a message. Users expecting `lock` to revoke session tokens or clear the keyring will be surprised.

**Fix:** Make `lock` actively clear session tokens from the keyring (same as `logout` but without the server call). This is meaningful: it prevents token reuse without revoking server-side.

---

### L-04 — Health Endpoint Leaks Server Info Without Auth

**File:** `crates/nullwarden-server/src/app.rs`  
**Severity:** LOW — Information disclosure  

```rust
.route("/health", get(|| async { "ok" }))
```

A plain "ok" response is fine. But if the server version, build timestamp, or component info is ever added (common in health check expansions), it becomes an unauthenticated information leak. The endpoint is accessible without authentication and is visible to external scanners.

**Fix:** Keep the response minimal (`"ok"`). Never add version/build info to this endpoint. Document this in the health check design.

---

### L-05 — `docker-compose.yml` `postgres` Service Has No Health Check

**File:** `docker-compose.yml`  
**Severity:** LOW — Server starts before database is ready  

```yaml
services:
  server:
    depends_on:
      - postgres  # Only waits for container start, not for postgres to be ready
```

`depends_on` without `condition: service_healthy` only waits for the PostgreSQL container to start, not for PostgreSQL to accept connections. The server will crash on startup with a connection refused error if the database hasn't finished initializing.

**Fix:**
```yaml
services:
  postgres:
    image: postgres:16
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U nullwarden -d nullwarden"]
      interval: 5s
      timeout: 5s
      retries: 5
  server:
    depends_on:
      postgres:
        condition: service_healthy
```

---

### L-06 — `audit` Workflow Uses `cargo install` on Every Run — Slow CI

**File:** `.github/workflows/ci.yml`  
**Severity:** LOW — CI performance  

```yaml
- name: Install cargo-audit
  run: cargo install cargo-audit --locked
- name: Install cargo-deny
  run: cargo install cargo-deny --locked
- name: Install cargo-tarpaulin
  run: cargo install cargo-tarpaulin --locked
```

Installing three large Rust tools from source on every CI run adds 5-10 minutes to each build. Use a pre-built binary action or GitHub Actions cache:

```yaml
- uses: taiki-e/install-action@cargo-audit
- uses: taiki-e/install-action@cargo-deny
- uses: taiki-e/install-action@cargo-tarpaulin
```

---

## 6. Code Quality & Architecture

### 6.1 Integration Tests Are Stubs

```rust
// crates/nullwarden-server/tests/auth_integration.rs
#[test]
fn placeholder() {
    assert!(true);
}
```

All four server integration test files (`auth_integration.rs`, `conflict_test.rs`, `rate_limit_test.rs`, `vault_integration.rs`) are placeholder stubs. The test suite passes 100% but covers 0% of the server's behavior. The CI coverage gate runs `cargo tarpaulin -p nullwarden-core` only — the server has zero test coverage enforcement.

**Fix:** Implement integration tests using `axum::serve` with in-memory SQLite for the database (add `sqlx` feature `sqlite` to dev-dependencies), or use `testcontainers` for PostgreSQL. At minimum: register, login, push, pull, conflict, logout flows.

### 6.2 `auth/token.rs` Comment Reveals Design Indecision

```rust
// This is tricky with Argon2 because we can't lookup by hash directly if salt is random
// But for tokens, we can use a static salt or just iterate and verify (slow)
// Actually, Argon2id is requested.
// ...
// Let's stick to what's easiest: fetch ALL and verify.
```

This comment should not exist in production code. It documents that the developer knew the design was wrong and chose the expedient path anyway. Address via C-01 fix.

### 6.3 `push.rs` Conflict Resolution: No Merge Path

When a sync conflict occurs, the user can only choose "keep local" or "keep remote." There is no entry-level merge. This is documented as a v0.1 limitation but means any concurrent edits on two devices result in data loss for one device. Consider documenting this prominently in the CLI conflict prompt.

### 6.4 `input.rs:validate_password_strength` Silently Ignores zxcvbn Errors

```rust
let estimate = zxcvbn(password, &[]);
if (estimate.score() as u8) < 3 {
```

`zxcvbn()` is infallible in this API version. Fine as-is, but the score cast `as u8` from the `Score` enum is non-idiomatic. Use the typed comparison:
```rust
use zxcvbn::Score;
if estimate.score() < Score::Three {
```

---

## 7. CI/CD & Supply Chain

### 7.1 `fuzz.yml` Runs Only `cargo build`, Not Actual Fuzzing

```yaml
- run: cargo build -p nullwarden-fuzz
```

This CI step only verifies compilation. It does not run the fuzz harness. Actual fuzzing requires `cargo +nightly fuzz run <target>`. The weekly scheduled job provides zero fuzzing value.

### 7.2 Release Workflow Signs Only `x86_64-unknown-linux-musl` and `x86_64-pc-windows-gnu`

No macOS (`aarch64-apple-darwin`) or ARM Linux (`aarch64-unknown-linux-musl`) builds. These are the most common developer platforms. Add them to the release matrix.

### 7.3 Dockerfile Uses `debian:bookworm-slim` — Pin to Digest

```dockerfile
FROM debian:bookworm-slim
```

Not pinned to a digest. `bookworm-slim` can change under CI, breaking reproducible builds. Pin to digest:
```dockerfile
FROM debian:bookworm-slim@sha256:<current_digest>
```

### 7.4 SBOM Generation Not Implemented

The README and deliverables list D13 (SBOM per release) as a requirement. Neither the CI nor the release workflow generates an SBOM. Add `cargo cyclonedx` or `syft` to the release workflow.

---

## 8. Remediation Summary

| ID | Severity | Issue | File | Fix Status |
|----|----------|-------|------|-----------|
| C-01 | CRITICAL | O(n) Argon2 token scan — DoS | `auth/token.rs` | Fixed in PR |
| C-02 | CRITICAL | Login timing oracle — username enum | `handlers/auth.rs` | Fixed in PR |
| C-03 | CRITICAL | `HeaderValue` type error — compile fail | `handlers/vault.rs` | Fixed in PR |
| C-04 | CRITICAL | Fuzz harness non-functional | `nullwarden-fuzz/Cargo.toml` | Fixed in PR |
| C-05 | CRITICAL | VaultHeader version not validated | `vault/header.rs` | Fixed in PR |
| C-06 | CRITICAL | docker-compose uses `.env.example` | `docker-compose.yml` | Fixed in PR |
| C-07 | CRITICAL | RLS uses `auth.uid()` — breaks vanilla PG | `migrations/*.sql` | Fixed in PR |
| C-08 | CRITICAL | CLI blocks 30s for clipboard clear | `commands/get.rs` | Fixed in PR |
| H-01 | HIGH | Refresh token missing expiry + index | `migrations/` | Fixed in PR |
| H-02 | HIGH | `atomic_write` no temp cleanup | `vault/store.rs` | Fixed in PR |
| H-03 | HIGH | Rate limit 300× too permissive | `middleware/rate_limit.rs` | Fixed in PR |
| H-04 | HIGH | KDF timing gate unenforced in CI | `ci.yml` + `kdf_params.rs` | Fixed in PR |
| H-05 | HIGH | `SecretString::Serialize` leaks risk | `types.rs` | Documented in PR |
| H-06 | HIGH | Force push no confirmation | `commands/push.rs` | Fixed in PR |
| H-07 | HIGH | Refresh tokens no expiry check | `auth/token.rs` | Fixed in PR |
| H-08 | HIGH | Key zeroize optimizer risk | `types.rs` | Documented in PR |
| H-09 | HIGH | No CORS configuration | `app.rs` | Fixed in PR |
| H-10 | HIGH | No keyring fallback | `session.rs` | Fixed in PR |
| H-11 | HIGH | First-push concurrent insert race | `db/vaults.rs` | Fixed in PR |
| M-01 | MEDIUM | `token_blocklist` no cleanup | `migrations/` | Fixed in PR |
| M-02 | MEDIUM | Token refresh swallows DB errors | `auth/token.rs` | Fixed in PR |
| M-03 | MEDIUM | `VaultData` zeroize clone risk | `vault/data.rs` | Documented |
| M-04 | MEDIUM | Entry merge info gap | `commands/push.rs` | Documented |
| M-05 | MEDIUM | Cannot clear notes | `commands/update.rs` | Fixed in PR |
| M-06 | MEDIUM | Auth password not strength-checked | `commands/register.rs` | Fixed in PR |
| M-07 | MEDIUM | No vault upload size limit | `handlers/vault.rs` + `app.rs` | Fixed in PR |
| M-08 | MEDIUM | Dockerfile runs as root | `Dockerfile` | Fixed in PR |
| M-09 | MEDIUM | `deny.toml` allows duplicate crates | `deny.toml` | Fixed in PR |
| L-01 | LOW | Zeroize test uses UB | `tests/zeroize.rs` | Documented |
| L-02 | LOW | No `VaultStore::with_params()` | `vault/store.rs` | Fixed in PR |
| L-03 | LOW | `lock` command is a no-op | `commands/lock.rs` | Fixed in PR |
| L-04 | LOW | Health endpoint info disclosure risk | `app.rs` | Documented |
| L-05 | LOW | Postgres no health check in compose | `docker-compose.yml` | Fixed in PR |
| L-06 | LOW | CI installs tools from source | `ci.yml` | Fixed in PR |

---

*End of Audit Report — NullWarden v0.1.0*  
*All CRITICAL and HIGH findings have been addressed in the accompanying PR.*
