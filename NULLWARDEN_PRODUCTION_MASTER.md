# NullWarden — Production Master Reference

**Date:** 2026-04-22  
**Scope:** Go-Live Analysis + Supabase Architecture Migration  
**Codebase:** HEAD (post-audit-remediation)  
**Classification:** Internal Engineering  

---

## Executive Summary

NullWarden's cryptographic core is architecturally sound. The zero-knowledge contract holds: the server stores opaque ciphertext, keys never leave the client, and the AEAD primitive is correctly chosen.

**Overall Verdict: NOT READY FOR PRODUCTION**

The system is suitable for internal prototype use with no real user data. Before any external deployment:

- Server integration tests must be replaced with real tests (the current stubs pass vacuously)
- Rate limiting must be validated end-to-end
- The `rls_transaction` SQL injection pattern must be removed
- No SBOM, no reproducible builds, no macOS build target
- No incident response runbook exists
- Supabase migration requires RLS policy rewrite — current `USING (true)` policies are dead code on vanilla Postgres and subtly wrong on Supabase

---

## Table of Contents

1. [Supabase Architecture](#1-supabase-architecture)
2. [Security](#2-security)
3. [Cryptography Correctness](#3-cryptography-correctness)
4. [Functional Correctness](#4-functional-correctness)
5. [User Experience and CLI](#5-user-experience-and-cli)
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

## 1. Supabase Architecture

### 1.1 What the Server Does and Must Not Do

**DOES:**
- Authenticate users (identity only, via Supabase Auth)
- Store encrypted vault blobs (opaque bytes)
- Return encrypted blobs to the authenticated owner
- Track versions and timestamps
- Enforce access control (user A cannot access user B's data)

**MUST NOT:**
- Decrypt vaults
- Derive encryption keys
- See plaintext secrets
- Log vault contents
- Modify vault structure

If any of the above are violated → the zero-knowledge contract is broken.

### 1.2 Supabase Component Mapping

| Supabase Service | NullWarden Use |
|---|---|
| `auth.users` | User identity; do not control directly |
| Supabase Auth (JWT) | Session tokens; replaces custom `jsonwebtoken` server code |
| PostgreSQL | Storage for encrypted blobs, refresh tokens, blocklist |
| Row-Level Security (RLS) | Access control; **must use `auth.uid()`**, not `USING (true)` |
| REST API | Vault blob GET/PUT; replaces Axum handlers (optional) |
| Realtime (optional) | Not needed for v0.1 |

The current Axum server can remain for custom auth flows (refresh token rotation, blocklist) but the DB must be Supabase-hosted Postgres with real RLS.

### 1.3 Data Flow

```
Client (CLI)
   │
   ├─► Supabase Auth → signInWithPassword → JWT issued
   │
   ├─► Client derives vault key (Argon2id, local only)
   │
   ├─► Client encrypts vault (XChaCha20-Poly1305, local only)
   │
   └─► PUT /vault → Supabase DB stores opaque BYTEA
                    Server never sees plaintext
```

### 1.4 Schema (Supabase-Correct)

**Replace the current vanilla-Postgres schema with the following.**

#### `vaults` table

```sql
-- Drop old permissive policy before recreating
ALTER TABLE vaults ENABLE ROW LEVEL SECURITY;

-- THIS IS WRONG (current code):
-- CREATE POLICY "Internal access" ON vaults FOR ALL USING (true);

-- THIS IS CORRECT for Supabase:
CREATE POLICY "Users can access own vault"
  ON vaults
  FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);
```

The critical fix: `auth.uid()` is a Supabase function that reads the JWT sub claim. This is what actually enforces the access boundary. `USING (true)` is a no-op that allows all rows to all users.

#### `vault_history` table

```sql
CREATE POLICY "Users can access own history"
  ON vault_history
  FOR ALL
  USING (auth.uid() = user_id);
```

#### `refresh_tokens` table

```sql
CREATE POLICY "Users can access own tokens"
  ON refresh_tokens
  FOR ALL
  USING (auth.uid() = user_id);
```

#### `token_blocklist` table

```sql
-- Blocklist needs service-role access only, not user-level RLS
-- Use service_role key server-side for all blocklist operations
-- Do NOT expose blocklist to client JWT
ALTER TABLE token_blocklist ENABLE ROW LEVEL SECURITY;
CREATE POLICY "No direct user access"
  ON token_blocklist
  FOR ALL
  USING (false); -- Only accessible via service_role bypass
```

### 1.5 Removing `rls_transaction` (BLOCKER)

The current `db/vaults.rs` uses:

```rust
sqlx::query(&format!("SET LOCAL auth.uid = '{}'", user_id))
```

On vanilla Postgres this is dead code (RLS policies are `USING (true)`). On Supabase this is **wrong** — Supabase's `auth.uid()` reads from the JWT context set by PostgREST, not from `SET LOCAL`. Your Axum server connecting with the service role bypasses RLS entirely. You have two correct approaches:

**Option A — Use service_role key + enforce access in WHERE clauses (current approach, keep it)**

```rust
// All queries already scope by user_id in WHERE — this is correct.
// Remove rls_transaction entirely.
// Service role bypasses RLS, which is fine because Axum already validates JWT
// and extracts user_id from it before any DB call.
sqlx::query("SELECT version, blob FROM vaults WHERE user_id = $1")
    .bind(user_id)
    .fetch_optional(&self.pool)
    .await?
```

**Option B — Use anon key + real RLS (requires passing JWT to Postgres session)**

This requires `set_config('request.jwt.claims', ...)` per-request. More complex. Not recommended for the Axum-server architecture.

**Decision: Use Option A. Remove `rls_transaction`. Keep all `WHERE user_id = $1` clauses.**

### 1.6 Auth Integration with Supabase

The current system has a full custom auth stack (Argon2id hash, JWT signing, refresh token rotation). On Supabase you have two options:

**Option A — Keep custom Axum auth (current approach)**

- Use Supabase only for storage (Postgres)
- Keep the Axum server for all auth
- Connect to Supabase Postgres with `DATABASE_URL` (service role connection string)
- **No changes to auth code needed**
- RLS is bypassed (service role) — access control enforced by Axum + WHERE clauses

**Option B — Use Supabase Auth**

- Drop the Axum auth stack entirely
- Use `supabase.auth.signInWithPassword()` from a thin client
- Supabase issues JWTs natively
- Auth password still independent of vault key (Supabase Auth is identity only)
- CLI must call Supabase Auth REST endpoints directly
- Simpler long-term but significant refactor

**Recommendation for v0.1: Option A.** The auth code works, tests pass, the refactor risk is not worth it. Point `DATABASE_URL` at the Supabase Postgres connection string and deploy.

### 1.7 Supabase-Specific Security Concerns

**Service role key must never reach the CLI.** The Axum server holds `DATABASE_URL` (service role). The CLI only holds the JWT. This is already correctly implemented.

**Supabase Dashboard access.** Anyone with Supabase project access can read all rows via the Dashboard, bypassing RLS (Dashboard uses service role). This is an operational security concern: restrict who has Supabase project access.

**Connection pooling.** Supabase provides PgBouncer. Set `db_max_connections` to match your Supabase plan's connection limit (Free: 60, Pro: 200). The current default of 10 is fine for prototype.

**Direct Postgres URL vs REST API.** The Axum server uses direct Postgres (SQLx). This is correct and more efficient than the Supabase REST API for server-side usage.

### 1.8 Failure Modes on Supabase

| Failure | Behavior | Recovery |
|---|---|---|
| Supabase down | CLI local vault still works; push/pull fails | Retry with exponential backoff (already implemented) |
| DB corruption | Server returns error; local vault preserved | Restore from `vault_history` or last local `.nw` file |
| Auth service down | JWT validation fails for new sessions; existing JWTs still valid until expiry | Wait for service recovery |
| RLS misconfiguration | Cross-user data access possible | Fix policies immediately; rotate all user sessions |

---

## 2. Security

**Verdict: CONDITIONAL — Core model sound; surrounding infrastructure has active blockers**

### 2.1 Threat Model Coverage

| Attacker | Coverage | Gap |
|---|---|---|
| Passive network observer | ✅ TLS 1.3 enforced | ❌ HTTP fallback in `main.rs` runs with only a warning |
| Compromised DB/server | ✅ Only ciphertext stored | None |
| Stolen device (locked) | ✅ Vault is ciphertext | None |
| Stolen device (unlocked) | ⚠️ Zeroize mitigates; LLVM elision risk | Residual H-08 |
| Active MITM | ✅ HSTS set | ❌ No cert pinning |
| Brute-force login | ⚠️ Rate limit configured but integration test now passes | Verify in staging |
| Username enumeration | ✅ Dummy hash mitigates timing oracle | Requires timing validation |
| Rollback/replay | ⚠️ Version counter exists | No cryptographic freshness proof |
| Supply chain | ✅ `cargo audit` + `cargo deny` in CI | ❌ No SBOM generated |

### 2.2 Authentication Analysis

**Access token (JWT):**
- HS256 with server-side `JWT_SECRET` loaded via `envy`. Correct pattern.
- `iss` and `aud` claims now validated in `jwt.rs`. Correct.
- 15-minute expiry. Correct.
- `claims.exp as usize` cast silently truncates on 32-bit targets — not a current target but worth noting.

**Refresh token:**
- Split-token design (`id:secret`) correctly implemented.
- `secret_hash` now uses SHA-256 + `constant_time_eq` (not Argon2id). **This is correct.** The critical fix from the original audit is in place: `token.rs` uses `sha256_hex` + `constant_time_eq` for the secret comparison.
- UUID v4 for secret component (~122 bits entropy). Adequate.

**Rate limiting:**
- `tower_governor` is wired in `app.rs` via `GovernorLayer` applied to auth routes. **Confirmed present.** The integration test `rate_limit_test.rs` verifies it fires at the configured burst size.

### 2.3 Session Management

- Token blocklist: SHA-256 hash in `token_blocklist` table. Correct.
- Cleanup job: `cleanup_blocked_tokens` is wired in `main.rs` as a background Tokio task on `cleanup_interval_secs`. Correct.
- Index on `token_blocklist(expires_at)` added in migration `20260101000003`. Correct.
- No session binding to device fingerprint or IP. Documented residual risk for v0.1.

### 2.4 Secret Handling — Server Side

- `Config.jwt_secret` typed as `SecretString` (Zeroize). Correct.
- `AppState::new()` deprecated method removed. Correct.
- `rls_transaction` still present. **Remove per §1.5.**

### 2.5 Secret Handling — Client Side

- `VaultEncryptionKey`, `SecretString`, `SecretBytes` all implement `Zeroize + ZeroizeOnDrop`. Correct.
- `SecretString::serialize` emits plaintext (required for MessagePack). Needs a `#[doc(hidden)]` warning that this type must never be JSON-serialized in an HTTP handler.
- `entry.password.0.clone()` for clipboard: the clone is not under Zeroize control after passing to `arboard`. Clipboard manager risk documented in CLI manual. Correct posture.
- `AuthRequest { password }` serialized as JSON for HTTP auth. Protected by TLS. Correct and unavoidable.

### 2.6 Input Validation

- Username length validation added in `handlers/auth.rs` (`validate_username`: 3–64 chars). Correct.
- Body limit `DefaultBodyLimit::max(10 * 1024 * 1024)` in place. Correct.
- `VaultHeader::decode()` enforces magic bytes and format version. Correct.
- **BLOCKER: `rls_transaction` string interpolation** — see §1.5. Remove it.

### 2.7 Dependency Risk

- `cargo deny check` with `multiple-versions = "deny"` in CI. Correct.
- `cargo audit` in CI. Correct.
- `Cargo.lock` committed. Correct.
- Two versions of `rustls` (0.21 and 0.23) in the tree — verify `skip` entries in `deny.toml` are intentional.
- `atty 0.2.14` unsoundness on Windows is dev-only (`criterion`). Acceptable.

---

## 3. Cryptography Correctness

**Verdict: PASS with noted residuals**

### 3.1 KDF

- Argon2id, Version V0x13, `m=65536, t=3, p=4`, 32-byte salt, 32-byte key. Correct.
- `kdf_meets_minimum_latency` test marked `#[ignore]`, run explicitly in CI. Correct.
- **Residual:** KDF params stored in vault header enable offline parameter downgrade. Without a signed header, a tampered vault with weaker params produces a different key → AEAD fails → error. Fail-closed. Acceptable for v0.1.

### 3.2 AEAD

- XChaCha20-Poly1305 with 192-bit CSPRNG nonce per operation. Correct.
- AEAD tag verified atomically before returning plaintext. Correct.
- Nonce reuse risk: zero (fresh nonce per encrypt, no state machine).

### 3.3 Key Separation

- Vault encryption key: Argon2id client-side from master password.
- Server auth password: Argon2id server-side from auth password.
- No code path connects them. Correct.

### 3.4 Constant-Time Comparisons

- Auth password verification: `Argon2::default().verify_password()` uses `subtle::ConstantTimeEq` internally. Correct.
- Refresh token secret comparison: `constant_time_eq` crate, SHA-256 hashes. **Correct — this is fixed.**
- Token blocklist lookup: SHA-256 hash as DB lookup key. Not constant-time, but hash is not secret. Acceptable.

### 3.5 Zeroize

- `VaultEncryptionKey([u8; 32])` with `#[derive(Zeroize, ZeroizeOnDrop)]`. LLVM elision risk in release+LTO. Documented residual.
- `tests/zeroize.rs` uses unsafe UB. Replace with `cargo miri test` in CI.
- `clear_notes.rs` test verifies `Some(None)` path persists through save/load cycle. Correct.

---

## 4. Functional Correctness

**Verdict: SUBSTANTIALLY IMPROVED — Core tests real; server tests now real**

### 4.1 Local Vault Operations

All local operations tested via real tests. `e2e_add_get.rs`, `vault_lifecycle.rs`, `integrity.rs`, `duplicate_entry.rs`, `clear_notes.rs` all exercise real code paths. No stubs.

### 4.2 Server Integration Tests

The server tests in `auth_integration.rs`, `vault_integration.rs`, and `rate_limit_test.rs` now use a real in-memory repository via `support.rs`. They are no longer stubs. Tests cover:

- Full register → login → refresh → logout flow
- Access token blocked after logout
- Refresh token rejected after logout
- Refresh tokens stored as SHA-256 (not Argon2)
- Authenticated DELETE account
- Push → pull → conflict flow
- Rate limit enforcement

**Remaining gap:** No test for pull rollback detection (`version < current_version`). The client code has this check but no test exercises it.

### 4.3 Sync Operations

`e2e_sync.rs` exercises real push/pull with a mock Axum server. Covers: create, add entry, push, pull, verify on "second device". 

**Gap:** No conflict test in `e2e_sync.rs`. The conflict path is tested in `vault_integration.rs` at the HTTP handler level but not end-to-end through the CLI sync client.

### 4.4 Password Strength

`validate_password_strength` called in `init.rs`, `register.rs`, `add.rs`, `update.rs`. All call sites covered.

---

## 5. User Experience and CLI

**Verdict: ACCEPTABLE for CLI prototype; blocking UX issues for general use**

### 5.1 Onboarding Flow

- `warn_if_default_server_url` prints a warning when `server_url` is still `http://127.0.0.1:8080` and user runs `push`, `pull`, `register`, `logout`. Correct.
- `cli-manual.md` now documents the new device restore procedure. Correct.
- **Gap:** No interactive setup flow. A user who runs `init` then immediately `push` gets a connection refused with a warning, not guidance.

### 5.2 Password Entry UX

- Password-as-CLI-arg warning now printed in `add.rs` and `register.rs`. Correct.
- `rpassword::read_password()` used everywhere. No echo. Correct.

### 5.3 Error Messages

- `ServerUnavailable` error variant in `CliError` produces human-readable message. Correct.
- Raw reqwest errors are wrapped via `map_network_error`. Correct.

### 5.4 Conflict Resolution UX

Conflict context (local entry count, remote entry count, delta, remote version) is now shown before the resolution prompt. Correct.

### 5.5 Lock vs Logout

- `lock` clears local tokens only. Does NOT call `POST /auth/logout`.
- `logout` calls server logout AND clears local tokens.
- CLI manual documents this distinction. Correct.
- **Gap:** `lock` message still says "Session tokens have been cleared from the keyring" but doesn't explain that the access token may still be valid on the server until expiry.

### 5.6 Clipboard

- Clipboard manager warning now printed on `get`. Correct.
- On Linux without clipboard manager: clipboard owned by X11 selection, cleared on process exit. Correct behavior.

### 5.7 Export

- `export` command implemented. Decrypts with master password, re-encrypts with backup password using a separate `VaultStore`. Correct.
- `export_command.rs` test verifies backup cannot be opened with original password. Correct.

---

## 6. Performance

**Verdict: ACCEPTABLE with known KDF cost; large vault impact untested**

### 6.1 KDF Latency

- Argon2id ≥ 300ms per unlock. Intentional. Must be documented in CLI manual ("vault unlock intentionally takes 300ms minimum for security").

### 6.2 Server Performance

- SQLx PgPool configured via `db_max_connections` env var with default of 10. Adequate for prototype.
- For Supabase Free tier: max 60 connections. Set `DB_MAX_CONNECTIONS=50` to leave headroom for Dashboard and migrations.
- `vault_history` inserts on every push add DB write overhead. Acceptable.

### 6.3 Large Vault

No benchmarks for large vault sizes. O(n) serialization and O(n) encryption in vault size. No upper bound on entry count. Acceptable for prototype.

---

## 7. Reliability and Crash Safety

**Verdict: PASS for local operations; sync path has unverified edge cases**

### 7.1 Atomic Write

`atomic_write`: write to `.tmp`, `sync_all`, rename. On Unix, parent directory is `fsync`'d after rename (added). Correct.

**Windows gap:** `fs::rename` can fail if destination file is open. Not addressed. Low priority for v0.1 given Linux-primary deployment.

### 7.2 Partial Sync Recovery

- Push fail mid-upload: server transaction rolled back, local unchanged. Correct.
- Pull fail before writing: local unchanged. Correct.
- Pull success but `SyncState` save fails: next push will send old version → conflict. Recoverable but creates friction.

### 7.3 Vault History

`vault_history` table stores the previous blob before each overwrite. This provides a 1-level backup backstop on the server. Correct — addresses the "no version history" gap.

---

## 8. Data Recovery and Backup

**Verdict: SUBSTANTIALLY IMPROVED**

### 8.1 Export Command

`nullwarden export [--output path]` implemented. Decrypts vault with master password, re-encrypts with a separate backup password, writes to a `.nwbackup` file. Correct zero-knowledge design (backup file is also opaque ciphertext).

### 8.2 New Device Restore

Documented in `cli-manual.md`. Procedure: configure server URL → `nullwarden pull` → enter master password for integrity verification. Correct.

### 8.3 Vault History (Server)

`vault_history` table retains the previous blob before each `PUT /vault`. Provides one-level recovery backstop. Not exposed via API — recovery requires manual DB access or operator tooling. Acceptable for v0.1.

### 8.4 Migrate Command

`nullwarden migrate [--m-cost] [--t-cost] [--p-cost]` implemented. Unlocks vault with current params, saves with new params. Correct.

---

## 9. Backend and API Behavior

**Verdict: CONDITIONAL — Dead code and RLS pattern must be removed**

### 9.1 Authorization Boundary

Every vault handler extracts `user.id` from validated JWT via `CurrentUser` extractor. All DB queries scope by `user_id = $1`. Correct.

**`rls_transaction` is dead code** — the `SET LOCAL auth.uid = '{}'` has no effect with either `USING (true)` policies on vanilla Postgres or when using service_role on Supabase. **Remove it.** See §1.5.

### 9.2 API Idempotency

- `PUT /vault` with `X-If-Match`: not idempotent by design (version increments). Correct.
- `POST /auth/logout`: not fully idempotent (token already blocked on second call). Acceptable.

### 9.3 Rate Limiting

`GovernorLayer` applied to auth routes in `app.rs`. `rate_limit_test.rs` verifies it fires. Confirmed present and working.

### 9.4 CORS

`AllowOrigin::any()` — placeholder. Acceptable for CLI-only v0.1 (CLI tools don't enforce CORS). Must be restricted before any browser client ships.

### 9.5 User Deletion

`DELETE /auth/user` endpoint implemented in `handlers/auth.rs`. Revokes all refresh tokens then deletes user row (cascades to vault and tokens). Correct.

---

## 10. Database Design

**Verdict: PASS with Supabase RLS correction required**

### 10.1 Schema

All tables present: `users`, `vaults`, `refresh_tokens`, `token_blocklist`, `vault_history`. Indexes present. Cascade deletes correct.

### 10.2 RLS Policies — CRITICAL CORRECTION FOR SUPABASE

**Current state (WRONG for Supabase):**
```sql
CREATE POLICY "Internal access" ON vaults FOR ALL USING (true);
```

**Required state for Supabase:**
```sql
-- Server connects with service_role → RLS bypassed → WHERE clauses enforce access
-- OR
-- Server passes user JWT → auth.uid() works → real RLS enforced
```

Since the Axum server connects with a service role key (which bypasses RLS on Supabase), the `USING (true)` policies are harmless but misleading. **Two actions required:**

1. Remove `rls_transaction` wrapper from `db/vaults.rs`
2. Update policies to match actual access model (either `USING (auth.uid() = user_id)` for anon access, or document that service role is used with no RLS enforcement)

### 10.3 Token Blocklist Cleanup

Index on `token_blocklist(expires_at)` added in migration. Cleanup wired as background Tokio task in `main.rs`. Correct.

### 10.4 Vault History Size

`vault_history` grows unboundedly. No retention policy. Add a migration to cap history at 3 versions per user:

```sql
-- Add after INSERT into vault_history:
DELETE FROM vault_history
WHERE id NOT IN (
  SELECT id FROM vault_history
  WHERE user_id = $1
  ORDER BY created_at DESC
  LIMIT 3
);
```

Or implement this in `db/vaults.rs` as a cleanup step after each backup insert.

---

## 11. Logging, Telemetry, and Observability

**Verdict: PASS**

- `tracing_subscriber::fmt().json().init()` in `main.rs`. Structured JSON logs. Correct.
- No secrets in log call sites. Correct.
- No telemetry or analytics. Correct per privacy posture.
- Log level configurable via `RUST_LOG` environment variable (standard `tracing-subscriber` behavior).

---

## 12. Compatibility and Portability

**Verdict: PARTIAL — Linux and Windows covered; macOS not in build matrix**

### 12.1 Build Targets

Current release matrix: `x86_64-unknown-linux-musl`, `x86_64-pc-windows-gnu`.

**Missing:** `aarch64-apple-darwin`, `x86_64-apple-darwin`, `aarch64-unknown-linux-musl`.

### 12.2 Windows Session File Permissions

`session.rs` now calls `tighten_windows_acl` via `icacls` on Windows. Correct. Note: `icacls` must be available in PATH (standard on all Windows versions).

### 12.3 Keyring

- Linux: `secret-service` (D-Bus) → file fallback. Correct.
- macOS: Keychain. Correct.
- Windows: Credential Manager → `icacls`-hardened file fallback. Correct.

---

## 13. Code Quality and Maintainability

**Verdict: GOOD**

### 13.1 Dead Code

- `AppState::new()` — remove.
- `rls_transaction` in `db/vaults.rs` — remove.
- `revoke_all_user_tokens` — now called in `delete_user` handler. No longer dead.
- `cleanup_expired_tokens` — wired in `main.rs` background task. No longer dead.
- `is_valid_vault_structure` in `nullwarden-fuzz/src/lib.rs` — still unused. Remove or use in fuzz targets.

### 13.2 Vault Format Spec Correction

`docs/vault-format-spec.md` previously documented a non-existent `payload_len` field. **This has been corrected.** The spec now accurately describes: magic(4) + version(1) + m_cost(4) + t_cost(4) + p_cost(4) + salt(32) + nonce(24) = 73-byte header, followed immediately by ciphertext. Correct.

### 13.3 Documentation

`incident-response.md`, `privacy-policy.md`, `deployment-guide.md` all added. ADRs complete. CLI manual updated with restore procedure and clipboard warning. Correct.

---

## 14. Build and Release Pipeline

**Verdict: PARTIAL — Core pipeline functional; SBOM and macOS missing**

### 14.1 CI Pipeline

```yaml
# Confirmed present and correct:
- cargo fmt --all -- --check
- cargo clippy --workspace --all-targets -- -D warnings
- cargo build --workspace
- cargo test --workspace
- cargo test -p nullwarden-core -- --ignored kdf_meets_minimum_latency
- cargo audit
- cargo deny check
- cargo tarpaulin -p nullwarden-core --fail-under 80
```

**Gap:** Coverage gate only on `nullwarden-core`. Server coverage not enforced.

**Gap:** Clippy step covers `--all-targets` but fuzz crate warnings may not be caught (check `deny.toml` for fuzz exclusion).

### 14.2 Fuzz CI

`fuzz.yml` still only builds (`cargo build -p nullwarden-fuzz`). Does not run fuzzing. Replace with:

```yaml
- run: cargo +nightly fuzz run decrypt_input -- -max_total_time=300
- run: cargo +nightly fuzz run vault_deserialize -- -max_total_time=300
```

### 14.3 Release Pipeline

- Signing via `minisign` with `MINISIGN_SECRET_KEY` from GitHub Secrets. Correct.
- Docker image not published in release workflow. Gap.
- No SBOM generation. Gap. Add `cargo cyclonedx` step.
- `FROM debian:bookworm-slim` not digest-pinned in `Dockerfile`. Gap.

---

## 15. Privacy and Compliance

**Verdict: IMPROVED — User deletion implemented; retention gaps remain**

### 15.1 Data Inventory

| Data | Location | Encrypted? | Notes |
|---|---|---|---|
| Username | `users.username` | No | PII identifier |
| Auth password | `users.password_hash` | Argon2id hash | Never plaintext |
| Vault blob | `vaults.blob` | Yes (XChaCha20) | Opaque to server |
| Vault history | `vault_history.blob` | Yes (XChaCha20) | Same opacity |
| Refresh token | `refresh_tokens.secret_hash` | SHA-256 | One-time use |
| Access token | `token_blocklist.token_hash` | SHA-256 | Short-lived |
| Session files | `~/.config/nullwarden/*.session` | No | 0600 Unix, `icacls` Windows |

### 15.2 User Deletion

`DELETE /auth/user` implemented. Cascades to vault, vault_history, refresh_tokens. Blocklist entries expire naturally. Correct for GDPR Article 17.

### 15.3 Retention

- Refresh tokens: 7-day expiry enforced. Cleanup task running.
- Blocklist: expires_at enforced. Cleanup task running.
- Vault history: no size/time limit. Add retention cap (see §10.4).
- User accounts: deletable via API. Correct.

### 15.4 Privacy Policy

`docs/privacy-policy.md` added. Minimal but accurate. Correct for self-hosted deployment context.

---

## 16. Incident Response and Failure Handling

**Verdict: SUBSTANTIALLY IMPROVED — Runbooks added; communication gap remains**

### 16.1 Incident Response

`docs/incident-response.md` added with procedures for:

- JWT secret compromise → generate new secret, deploy, refresh tokens remain valid
- Database breach → revoke all refresh tokens, notify users, advise credential rotation
- Corrupted vault blob → restore from `vault_history` or backup
- Bad deployment → stop, redeploy previous binary, verify health

**Gap:** No automated user notification mechanism. Manual communication required for all scenarios.

### 16.2 JWT Secret Rotation

`docs/deployment-guide.md` documents the zero-downtime JWT secret rotation procedure. Correct.

### 16.3 Severity Levels

Defined in `incident-response.md`: P0 (active compromise), P1 (data corruption/significant defect), P2 (localized/recoverable). Correct.

---

## 17. Go-Live Checklist

### CRITICAL (Deploy Blockers)

- [ ] **Remove `rls_transaction`** from `db/vaults.rs` and all call sites. Replace with direct pool queries. The `SET LOCAL auth.uid` is dead code on both vanilla Postgres and Supabase service-role connections.
- [ ] **Fix RLS policies for Supabase**: Update all `USING (true)` policies. If using service role (recommended), document that RLS is bypassed and access control is enforced by Axum + WHERE clauses. If using anon key, rewrite policies to use `auth.uid()`.
- [ ] **Verify staging deployment end-to-end**: Register → login → push → pull → conflict → logout flow against real Supabase Postgres. Integration tests use in-memory repos; they don't catch Supabase-specific issues.
- [ ] **Validate rate limiting in staging**: Send 6 rapid login requests from the same IP. Verify 429 on the 6th.
- [ ] **Pin Supabase connection string**: Set `DATABASE_URL` to the Supabase direct connection string (not the pooler URL) for SQLx compatibility. Pooler URLs require `pgbouncer=true` parameter.

### HIGH (Before External Users)

- [ ] **Add macOS build target** (`aarch64-apple-darwin`) to release matrix.
- [ ] **Generate SBOM**: Add `cargo cyclonedx` to release workflow. Publish `bom.xml` alongside artifacts.
- [ ] **Cap `vault_history` retention**: Add SQL to trim history to 3 most recent versions per user on each insert.
- [ ] **Pin Dockerfile digest**: Replace `FROM debian:bookworm-slim` with a SHA-pinned version.
- [ ] **Replace fuzz CI theater**: Replace `cargo build -p nullwarden-fuzz` with actual `cargo +nightly fuzz run` calls with a time limit.
- [ ] **Remove dead code**: `AppState::new()`, `is_valid_vault_structure` in fuzz lib, `rls_transaction`.
- [ ] **Replace `cargo miri test`**: Replace the unsafe UB zeroize test with `cargo +nightly miri test -p nullwarden-core` in CI.

### MEDIUM (Before v0.2)

- [ ] **Enforce server coverage**: Add `cargo tarpaulin -p nullwarden-server --fail-under 60` to CI.
- [ ] **Add pull rollback test**: Test that CLI bails when server version < local version.
- [ ] **Add conflict test in `e2e_sync.rs`**: Exercise the 409 conflict path through the CLI sync client, not just the HTTP handler.
- [ ] **Add `lock` clarification**: Update `lock` command output to note that access tokens remain valid on the server until expiry.
- [ ] **Vault history API**: Add a server endpoint or operator script to list/restore from `vault_history` for a given user.
- [ ] **JWT size audit**: Log JWT length during integration tests. If > 1KB due to claims, trim claims.
- [ ] **`SecretString` doc warning**: Add `#[doc]` on `SecretString::serialize` warning that this type must never be used as a field in a JSON-serialized HTTP response struct.

### LOW (Quality of Life)

- [ ] **ARM Linux build**: Add `aarch64-unknown-linux-musl` to release matrix.
- [ ] **SHA-256 checksums**: Publish `SHA256SUMS` file alongside minisign signatures.
- [ ] **Exponential backoff docs**: Document the 3-attempt retry with 250ms/500ms/1000ms backoff that `sync.rs` already implements.
- [ ] **JWT issuer/audience per-environment**: Document that staging and prod should use different `JWT_ISSUER` / `JWT_AUDIENCE` values to prevent token cross-environment reuse.
- [ ] **Pool size documentation**: Add `DB_MAX_CONNECTIONS` guidance per Supabase plan tier to deployment guide.
- [ ] **TOTP/WebAuthn**: Planned v0.2 per ADR. Track as a roadmap item, not a blocker.

---

## Summary Table

| Dimension | Status | Blockers |
|---|---|---|
| Supabase Architecture | ⚠️ Conditional | `rls_transaction` removal, RLS policy correction, staging validation |
| Security | ⚠️ Conditional | Remove `rls_transaction`, staging rate limit verify |
| Cryptography | ✅ Pass | None |
| Functional Correctness | ✅ Pass | Minor: pull rollback test, conflict e2e test |
| UX / CLI | ⚠️ Partial | No interactive onboarding, lock clarification |
| Accessibility | ✅ Acceptable | None for CLI scope |
| Performance | ✅ Acceptable | No large vault benchmarks |
| Reliability | ✅ Pass | Minor Windows rename gap |
| Data Recovery | ✅ Pass | vault_history retention cap needed |
| Backend / API | ⚠️ Conditional | Dead `rls_transaction`, RLS correction |
| Database Design | ⚠️ Conditional | RLS correction for Supabase, history retention |
| Logging | ✅ Pass | None |
| Compatibility | ⚠️ Partial | No macOS build |
| Code Quality | ✅ Good | Dead code cleanup |
| Build / Release | ⚠️ Partial | No SBOM, fuzz CI still theater |
| Privacy | ✅ Pass | History retention |
| Incident Response | ✅ Pass | No automated user notification |

**Legend:** ✅ = Go | ⚠️ = Conditional | ❌ = No-Go

---

*NullWarden Production Master Reference v1.1*  
*Generated: 2026-04-22*  
*Next review: After critical and high checklist items are resolved*
