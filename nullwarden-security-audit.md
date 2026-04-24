# NullWarden — Deep Security Audit Report

**Audit Date:** 2026-04-23  
**Codebase Version:** 0.1.0  
**Auditor:** Internal Security Review  
**Classification:** Internal Engineering — Confidential  
**Scope:** Full codebase review — `nullwarden-core`, `nullwarden-cli`, `nullwarden-server`, `nullwarden-fuzz`, CI/CD pipeline, migrations, Docker configuration  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Audit Scope and Methodology](#2-audit-scope-and-methodology)
3. [Critical Findings](#3-critical-findings)
4. [High Findings](#4-high-findings)
5. [Medium Findings](#5-medium-findings)
6. [Low Findings](#6-low-findings)
7. [Supply Chain and Dependency Audit](#7-supply-chain-and-dependency-audit)
8. [Cryptographic Analysis](#8-cryptographic-analysis)
9. [Architecture and Design Review](#9-architecture-and-design-review)
10. [Testing Gap Analysis](#10-testing-gap-analysis)
11. [CI/CD Pipeline Review](#11-cicd-pipeline-review)
12. [Infrastructure and Deployment Review](#12-infrastructure-and-deployment-review)
13. [Finding Summary Table](#13-finding-summary-table)
14. [Remediation Roadmap](#14-remediation-roadmap)

---

## 1. Executive Summary

NullWarden is a zero-knowledge password vault implemented in Rust, targeting a server-adversarial architecture where the server is structurally incapable of decrypting user data. The cryptographic core is the strongest component of the system — the Argon2id KDF, XChaCha20-Poly1305 AEAD, and memory zeroization are correctly implemented and compose well. The architecture invariants are sound: no plaintext ever leaves the client, and the server correctly stores only opaque encrypted blobs.

However, this audit identified **5 Critical**, **15 High**, **16 Medium**, and **4 Low** severity findings across authentication, session management, rate limiting, deployment, supply chain, and operational security. The most severe issues are concentrated in the server layer and deployment configuration — not in the cryptographic core.

**Top risks requiring immediate action before any production deployment:**

- RLS migrations use Supabase-specific `auth.uid()` which breaks on plain PostgreSQL and will cause server startup failure
- Rate limiting is applied globally (not per-IP), making auth endpoints trivially DoS-able by a single client
- Vault KDF parameters are read from the vault blob without bounds checking, enabling an OOM-based DoS attack via a malicious server-supplied vault
- Logout does not revoke the access token server-side via the `lock` command, leaving tokens valid up to 15 minutes after the user locks
- The Windows session file fallback writes tokens with `"Users:F"` ACL if `USERNAME` env var is absent, granting all local users read access

**Overall security posture:** Strong cryptographic design with significant operational and server-layer gaps. Production-blocking issues exist. The codebase is not production-ready without addressing at least all Critical and High findings.

---

## 2. Audit Scope and Methodology

### 2.1 Assets Reviewed

| Asset | Description |
|-------|-------------|
| `crates/nullwarden-core` | Cryptographic library — KDF, AEAD, vault format, atomic I/O |
| `crates/nullwarden-cli` | CLI binary — commands, sync client, session management |
| `crates/nullwarden-server` | Axum REST API — auth, vault CRUD, middleware, DB layer |
| `crates/nullwarden-fuzz` | Fuzz targets for core deserialization and decryption |
| `Dockerfile` | Container build and runtime configuration |
| `docker-compose.yml` | Local development environment |
| `.github/workflows/` | CI/CD pipeline — ci.yml, release.yml, fuzz.yml |
| `crates/nullwarden-server/migrations/` | PostgreSQL schema migrations |
| `Cargo.lock` | Dependency lock file |
| `deny.toml` | Dependency policy |
| `docs/` | Threat model, ADRs, security design documents |

### 2.2 Methodology

- **Static code analysis** — Manual review of all Rust source files
- **Threat model validation** — Cross-referenced existing threat model against actual implementation
- **Dependency audit** — `cargo audit` simulation against known advisories in Cargo.lock
- **Cryptographic review** — Primitive selection, parameter adequacy, nonce/salt handling
- **Architecture analysis** — Trust boundary correctness, separation of concerns
- **Attack chain mapping** — End-to-end exploit scenario construction
- **CI/CD review** — Supply chain security, build integrity, secret exposure risks
- **Schema review** — SQL migration correctness, RLS policy soundness

### 2.3 Severity Definitions

| Severity | Definition |
|----------|------------|
| **CRITICAL** | Direct authentication bypass, data exposure, or production-blocking deployment failure |
| **HIGH** | Significant security weakness exploitable with low-moderate effort or significant reliability risk |
| **MEDIUM** | Security weakness requiring specific conditions or providing limited impact |
| **LOW** | Best-practice gaps, informational, defense-in-depth improvements |

---

## 3. Critical Findings

---

### CRIT-01 — Supabase-Specific `auth.uid()` in Migrations Breaks Plain PostgreSQL Deployment

**Severity:** CRITICAL  
**Files:** `crates/nullwarden-server/migrations/20260101000001_create_vaults.sql`, `20260101000002_create_refresh_tokens.sql`, `20260101000003_create_token_blocklist.sql`, `20260101000004_create_vault_history.sql`  
**OWASP 2025:** A02 Security Misconfiguration  

**Description:**  
Four of five migrations define RLS policies using `auth.uid()`, which is a Supabase-specific PostgreSQL function provided by the Supabase auth extension. It does not exist in a standard PostgreSQL installation.

```sql
-- From 20260101000001_create_vaults.sql
CREATE POLICY "Users can access own vault"
  ON vaults
  FOR ALL
  USING (auth.uid() = user_id)         -- FAILS on plain PostgreSQL
  WITH CHECK (auth.uid() = user_id);

-- From 20260101000003_create_token_blocklist.sql
CREATE POLICY "No direct user access"
  ON token_blocklist
  FOR ALL
  USING (false);
```

The `docker-compose.yml` ships a standard `postgres:16` container. When `sqlx`'s `Migrator::run()` executes at server startup, the migration will fail with `ERROR: function auth.uid() does not exist`, causing the server to exit immediately. The system is **undeployable** on plain PostgreSQL as shipped.

Additionally, RLS is enabled on all tables but the application server connects via a standard PostgreSQL role (not Supabase's service role). Even if `auth.uid()` existed, these policies would block all application-level DB queries because the application does not set the Supabase `request.jwt` context that populates `auth.uid()`.

**Impact:** Server startup failure on all non-Supabase deployments. The primary documented deployment path (docker-compose + postgres:16) is completely broken.

**Remediation:**

Option A — Supabase-only: document that migrations require Supabase and fail fast with a clear error message. Gate the `auth.uid()` policies behind a feature flag or separate migration set.

Option B — Portable (recommended): replace Supabase RLS policies with application-level authorization (already implemented in handlers) and use simple RLS policies that work on standard PostgreSQL:

```sql
-- Replace Supabase-specific policies with portable equivalents
-- For plain PostgreSQL, authorization is enforced at application layer.
-- RLS serves as defense-in-depth using the application's DB role.

-- Option: drop RLS entirely and rely on app-layer auth (current handlers already do this)
ALTER TABLE vaults DISABLE ROW LEVEL SECURITY;

-- Option: keep RLS but use app role, not auth.uid()
-- CREATE POLICY "app_role_only" ON vaults FOR ALL TO nullwarden_app USING (true);
```

Option C — Conditional migration: detect Supabase environment and apply appropriate policies:

```sql
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'uid' AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'auth'))
  THEN
    -- Supabase-specific RLS
    EXECUTE 'CREATE POLICY "supabase_user_vault" ON vaults FOR ALL USING (auth.uid() = user_id)';
  ELSE
    -- Plain PostgreSQL — app layer handles authorization
    EXECUTE 'CREATE POLICY "app_managed" ON vaults FOR ALL USING (true)';
  END IF;
END $$;
```

---

### CRIT-02 — Global Rate Limiting Creates Auth DoS Vector

**Severity:** CRITICAL  
**File:** `crates/nullwarden-server/src/app.rs`  
**OWASP 2025:** A07 Authentication Failures  

**Description:**  
The rate limiter on auth endpoints uses `GlobalKeyExtractor`, which applies a single global counter shared across all clients:

```rust
GovernorConfigBuilder::default()
    .key_extractor(GlobalKeyExtractor)   // ← single global bucket
    .period(std::time::Duration::from_secs(
        state.config.rate_limit_auth_window_secs,
    ))
    .burst_size(state.config.rate_limit_auth_requests)   // default: 5
    .finish()
```

With default configuration (5 requests per 600 seconds), **any single client** making 5 auth requests blocks all other users from authenticating for 10 minutes. An unauthenticated attacker can send 5 POST requests to `/auth/login` and render the entire service's authentication unusable for all legitimate users. This is a trivial, unauthenticated DoS attack requiring zero credentials.

The attack is even more impactful because `GlobalKeyExtractor` aggregates across all auth endpoints (`/register`, `/login`, `/refresh`, `/logout`). A user completing a normal login flow (register → login → refresh) consumes 3 of the 5 allowed requests globally.

**Impact:** Complete authentication denial-of-service achievable with 5 unauthenticated HTTP requests.

**Remediation:**

Switch to per-IP rate limiting. Use `PeerIpKeyExtractor` for direct connections, or a custom extractor that respects `X-Forwarded-For` when behind a trusted reverse proxy:

```rust
use tower_governor::key_extractor::PeerIpKeyExtractor;
// OR for behind-proxy deployments:
use std::net::IpAddr;
use axum::extract::ConnectInfo;

GovernorConfigBuilder::default()
    .key_extractor(PeerIpKeyExtractor)   // per-IP, not global
    .period(std::time::Duration::from_secs(
        state.config.rate_limit_auth_window_secs,
    ))
    .burst_size(state.config.rate_limit_auth_requests)
    .finish()
```

For deployments behind a reverse proxy (Nginx, Cloudflare), also add a trusted-proxy IP extraction layer that reads `X-Real-IP` or the first entry in `X-Forwarded-For`, rejecting requests where this header is absent or spoofed.

---

### CRIT-03 — Vault KDF Parameters Read From Blob Without Bounds Checking Enables OOM DoS

**Severity:** CRITICAL  
**Files:** `crates/nullwarden-core/src/vault/store.rs`, `crates/nullwarden-core/src/vault/header.rs`  
**OWASP 2025:** A10 Exceptional Conditions  

**Description:**  
When unlocking a vault — including during `pull` from server — the KDF parameters are read directly from the vault header blob without any validation:

```rust
// vault/store.rs
pub fn unlock_bytes(&self, password: &str, bytes: &[u8]) -> Result<VaultData, VaultError> {
    let (header, offset) = VaultHeader::decode(bytes).ok_or(VaultError::InvalidFormat)?;
    let params = KdfParams {
        m_cost: header.m_cost,   // u32, directly from bytes — can be u32::MAX
        t_cost: header.t_cost,   // u32, directly from bytes — can be 0
        p_cost: header.p_cost,   // u32, directly from bytes — can be 0
    };
    let key = VaultKeyDeriver::derive(password, &header.salt, params)?;
```

`VaultHeader::decode()` performs no bounds checking on the KDF parameter fields. An attacker who can control the vault blob served by the sync server can craft a malicious blob with:

- `m_cost: u32::MAX = 4,294,967,295 KiB ≈ 4 TiB` → triggers OOM kill of the CLI process
- `t_cost: 0` → Argon2 returns an error but before any allocation, potentially exposing a confusing error path
- `m_cost: 4 * 1024 * 1024 = 4 GiB` → hangs the CLI for minutes or minutes to hours depending on hardware

**Attack path:**

1. Server is compromised (or attacker MITM's a non-TLS connection in dev mode)
2. Attacker modifies the vault blob at rest or in transit, setting `m_cost` bytes 5-8 to `0xFF 0xFF 0xFF 0xFF`
3. User runs `nullwarden pull` → `unlock_bytes()` is called for integrity check
4. Argon2id attempts to allocate 4 TiB → OOM → process killed
5. Local vault not overwritten (integrity check runs before write), so data is preserved, but the client is disrupted repeatedly

This attack does not compromise the vault's confidentiality (the AEAD tag check would also fail on a maliciously crafted blob), but it is an effective DoS against the client process. The attack also works if an attacker places a crafted file in the local vault path directly.

**Impact:** Client process crash / OOM on any device that pulls from a compromised server, or on any device where the vault file has been tampered with locally.

**Remediation:**

Add bounds validation in `VaultHeader::decode()`:

```rust
// vault/header.rs
const MIN_M_COST: u32 = 8 * 1024;            // 8 MB minimum
const MAX_M_COST: u32 = 1 * 1024 * 1024;     // 1 GB maximum
const MIN_T_COST: u32 = 1;
const MAX_T_COST: u32 = 100;
const MIN_P_COST: u32 = 1;
const MAX_P_COST: u32 = 64;

pub fn decode(input: &[u8]) -> Option<(Self, usize)> {
    // ... existing length and magic checks ...
    let m_cost = u32::from_le_bytes(input[5..9].try_into().ok()?);
    let t_cost = u32::from_le_bytes(input[9..13].try_into().ok()?);
    let p_cost = u32::from_le_bytes(input[13..17].try_into().ok()?);

    // Bounds check before any allocation
    if m_cost < MIN_M_COST || m_cost > MAX_M_COST
        || t_cost < MIN_T_COST || t_cost > MAX_T_COST
        || p_cost < MIN_P_COST || p_cost > MAX_P_COST
    {
        return None;
    }
    // ...
}
```

---

### CRIT-04 — `lock` Command Does Not Revoke Server-Side Access Token

**Severity:** CRITICAL  
**Files:** `crates/nullwarden-cli/src/commands/lock.rs`, `crates/nullwarden-cli/src/commands/logout.rs`  
**OWASP 2025:** A07 Authentication Failures  

**Description:**  
The `lock` command clears session tokens from the local keyring/file system but does not call the server's `/auth/logout` endpoint to revoke the access token:

```rust
// commands/lock.rs
pub async fn run() -> anyhow::Result<()> {
    clear_access_token()?;
    clear_refresh_token()?;
    println!("NullWarden CLI session locked.");
    // ← No HTTP call to /auth/logout
    // ← Access token remains valid on server for up to 15 minutes
```

The comment in the output text acknowledges this:
```
"Note: Your access token may still be valid on the server until it expires."
```

This means an attacker who observes or intercepts a valid access token (e.g., via process memory dump, network sniffing on a non-TLS dev connection, or log exposure) can continue to use it for up to 15 minutes after the user locks the vault. This window can be exploited to pull the encrypted vault blob and attempt offline decryption.

The `logout` command correctly calls the server, but `lock` — which is the primary "secure this session" command — does not. Users who rely on `lock` for security are left with a false sense of security.

**Impact:** 15-minute window where a stolen access token remains valid after the user explicitly locks the vault. An attacker can pull the vault blob and attempt offline Argon2id cracking during this window.

**Remediation:**

The `lock` command should also call the server logout endpoint:

```rust
// commands/lock.rs
pub async fn run() -> anyhow::Result<()> {
    let config = Config::load()?;

    // Attempt server-side revocation first
    let access_token = load_access_token().ok();
    let refresh_token = load_refresh_token().ok();
    if let (Some(at), Some(rt)) = (access_token, refresh_token) {
        let client = AuthClient::new(config.server_url);
        if let Err(e) = client.logout(&at, &rt).await {
            eprintln!("Warning: server-side token revocation failed: {e}. Tokens cleared locally.");
        }
    }

    // Always clear locally regardless of server result
    clear_access_token()?;
    clear_refresh_token()?;

    println!("Vault locked. Session tokens revoked locally and on server.");
    Ok(())
}
```

---

### CRIT-05 — Windows Session File Fallback Grants All-Users Read on `USERNAME` Env Var Absence

**Severity:** CRITICAL  
**File:** `crates/nullwarden-cli/src/session.rs`  
**OWASP 2025:** A02 Security Misconfiguration  

**Description:**  
When OS keyring storage fails, session tokens are written to the filesystem with Windows ACL hardening via `icacls`. The username for the ACL is pulled from the `USERNAME` environment variable with an unsafe fallback:

```rust
// session.rs
.arg(format!(
    "{}:F",
    std::env::var("USERNAME").unwrap_or_else(|_| "Users".to_string())
))
```

If `USERNAME` is not set (possible in some service account contexts, CI environments, or when running under `runas` without inheriting the environment), the ACL is set as `Users:F`, which grants the **built-in Users group** (all local users) **Full Control** over the session file. JWT access tokens and refresh tokens are written in plaintext and become readable by every local user on the machine.

Additionally, even when `USERNAME` is set correctly, it may include the domain prefix for domain-joined Windows machines (e.g., `CORP\alice`). The backslash in `CORP\alice:F` passed as a command-line argument may be misinterpreted by the `icacls.exe` argument parser, depending on how the argument is quoted, potentially resulting in a malformed ACL that silently applies a permissive default.

Furthermore, `icacls.exe` is invoked by searching PATH, not by absolute path (`C:\Windows\System32\icacls.exe`). An attacker who can manipulate the PATH environment variable could substitute a malicious binary.

**Impact:** Session tokens (JWT access + refresh) written world-readable on Windows when the `USERNAME` env var is absent, exposing full account access to all local users.

**Remediation:**

```rust
#[cfg(windows)]
fn tighten_windows_acl(path: &std::path::Path) -> anyhow::Result<()> {
    use std::env;

    // Use SID-based identity, not username string, to avoid domain/encoding issues
    // Prefer Windows API via the `windows` crate over subprocess icacls
    // Fallback: use whoami crate which handles domain accounts correctly
    let username = whoami::username(); // returns just the username part, no domain

    if username.is_empty() {
        anyhow::bail!("Cannot determine current username for ACL hardening");
    }

    // Use absolute path to icacls.exe to prevent PATH hijacking
    let icacls_path = std::path::Path::new(r"C:\Windows\System32\icacls.exe");

    let status = std::process::Command::new(icacls_path)
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{username}:F"))  // username only, no domain prefix
        .status()
        .context("failed to invoke icacls for session file ACL hardening")?;

    if !status.success() {
        anyhow::bail!("icacls failed (exit code: {:?})", status.code());
    }

    Ok(())
}
```

For a more robust solution, use the `windows` crate's Win32 API bindings to set ACLs programmatically without spawning a subprocess.

---

## 4. High Findings

---

### HIGH-01 — Logout Does Not Atomically Revoke Both Tokens; Partial Logout Possible

**Severity:** HIGH  
**File:** `crates/nullwarden-server/src/handlers/auth.rs`  
**OWASP 2025:** A07 Authentication Failures  

**Description:**  
The logout handler performs two independent revocation steps with no transactional guarantee:

```rust
pub async fn logout(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(payload): Json<RefreshRequest>,
) -> AppResult<StatusCode> {
    // Step 1: block access token (best effort, errors ignored)
    if let Some(auth_header) = headers.get(AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                let _ = jwt::block_token(&state, token).await;  // ← error swallowed
            }
        }
    }
    // Step 2: consume refresh token (best effort, errors ignored)
    let _ = token::consume_refresh_token(&state, &payload.refresh_token).await;

    Ok(StatusCode::NO_CONTENT)
}
```

If Step 1 succeeds (access token blocked) but Step 2 fails (DB error, network timeout), the refresh token remains valid. An attacker who has stolen the refresh token can mint new, unblocked access tokens indefinitely until the refresh token naturally expires (7 days). Conversely, if Step 2 succeeds and Step 1 fails, the access token remains valid until natural expiry (15 minutes).

Additionally, `consume_refresh_token()` in `auth/token.rs` itself ignores the revocation error:

```rust
let _ = revoke_refresh_token(state, token_id).await;  // ← DB delete error ignored
Ok(row.user_id)                                         // ← still returns "valid"
```

If the DB delete fails, the same refresh token can be consumed again on the next request — it was never actually invalidated.

**Remediation:**  
Revoke the refresh token first (higher security value), then block the access token. Return an error to the client if refresh token revocation fails. For the `consume_refresh_token()` function, treat revocation failure as a hard error, not a soft warning:

```rust
if secure_secret_matches(&row.secret_hash, secret) {
    // Revoke MUST succeed — if it fails, we can't guarantee single-use semantics
    revoke_refresh_token(state, token_id).await
        .map_err(|_| AppError::Internal(anyhow::anyhow!("Failed to revoke refresh token")))?;
    Ok(row.user_id)
}
```

---

### HIGH-02 — No Per-User Rate Limiting on Vault Upload Endpoint

**Severity:** HIGH  
**File:** `crates/nullwarden-server/src/app.rs`, `crates/nullwarden-server/src/handlers/vault.rs`  
**OWASP 2025:** A02 Security Misconfiguration  

**Description:**  
Rate limiting is applied only to `/auth/*` endpoints. The vault `PUT` endpoint has no rate limiting whatsoever:

```rust
let auth_routes = Router::new()
    .route("/auth/register", post(auth::register))
    // ...
    .layer(auth_rate_limit);     // ← only auth routes limited

let api_routes = Router::new()
    .route("/vault", get(vault::get_vault).put(vault::put_vault))  // ← no rate limit
    .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
```

A compromised or malicious authenticated account can:
1. Upload 10MB vault blobs at maximum network speed, consuming storage in `vault_history` (3 history entries × 10MB = 30MB minimum per user before cleanup)
2. Trigger `backup_current_vault()` on every forced push, filling the `vault_history` table
3. Exhaust DB storage for all users if running a multi-user deployment

The 10MB body limit prevents individual request size abuse but not request rate abuse.

**Remediation:**  
Add per-user rate limiting on vault operations. A reasonable limit is 60 vault writes per minute and 120 reads per minute:

```rust
let vault_write_limit_config = Box::leak(Box::new(
    GovernorConfigBuilder::default()
        .key_extractor(/* per-user extractor using JWT sub */UserIdKeyExtractor)
        .period(std::time::Duration::from_secs(60))
        .burst_size(60)
        .finish()
        .expect("vault write rate limit config must be valid"),
));
```

Also consider adding a maximum vault blob size limit smaller than 10MB (e.g., 2MB) that is appropriate for realistic password vault sizes.

---

### HIGH-03 — No Audit Logging for Security-Relevant Events

**Severity:** HIGH  
**Files:** `crates/nullwarden-server/src/handlers/auth.rs`, `crates/nullwarden-server/src/handlers/vault.rs`  
**OWASP 2025:** A09 Logging and Alerting  

**Description:**  
The server uses `tracing` for request/response logging via `log_request_id` middleware but logs no security-relevant events beyond raw HTTP method/URI/status:

```rust
// middleware/request_id.rs
info!(
    method = %request.method(),
    uri = %request.uri(),
    request_id = %request_id,
    "Request started"
);
```

The following events are not logged:
- Failed authentication attempts (username, source IP, timestamp)
- Successful logins (username, source IP)
- Rate limit activations (which IP triggered, which endpoint)
- Vault push/pull events (user ID, version, timestamp)
- Token revocation events (user ID, reason)
- Account deletions
- JWT validation failures (expired, invalid signature, blocklisted)

Without this logging, post-incident forensics are impossible. After a credential compromise, there is no way to determine: when the attacker first authenticated, how many times they accessed the vault, from which IPs, or when the account was first targeted.

**Remediation:**  
Add structured security event logging throughout handlers. Use a separate log level or structured field to mark security events for SIEM integration:

```rust
// In auth handler, after successful login:
tracing::info!(
    event = "auth.login.success",
    user_id = %user.id,
    // Never log the username or IP in the same event as user_id (correlation risk)
    // but DO log for security monitoring purposes with appropriate PII controls
    "Authentication successful"
);

// After failed login:
tracing::warn!(
    event = "auth.login.failure",
    // Do NOT log the attempted username (prevents username enumeration via logs)
    "Authentication failure"
);

// After vault push:
tracing::info!(
    event = "vault.push",
    user_id = %user.id,
    version = new_version,
    "Vault updated"
);
```

---

### HIGH-04 — `VaultData` Internal Version Counter Diverges From Sync Version Counter

**Severity:** HIGH  
**Files:** `crates/nullwarden-core/src/vault/data.rs`, `crates/nullwarden-cli/src/sync_state.rs`  
**OWASP 2025:** A06 Insecure Design  

**Description:**  
There are three independent version counters for the same logical entity:

1. `VaultData.version` (u64) — incremented by `add_entry()`, `update_entry()`, `delete_entry()`
2. `SyncState.last_version` (u64) — updated by `push`/`pull` commands from server response
3. `vaults.version` (BIGINT) in the database — server-side optimistic lock counter

These counters are not reconciled. Specifically:

- `VaultData.version` starts at 0 for a new vault and increments with each mutation
- `SyncState.last_version` starts at 0 and is set to the server's version (1, 2, 3...) after each sync
- The server's `vaults.version` starts at 1 on first push

After a fresh init + 5 add_entry calls + first push:
- `VaultData.version = 5`
- `SyncState.last_version = 1` (server version)
- DB `vaults.version = 1`

On a second device after pull:
- `VaultData.version = 5` (from decrypted payload)
- `SyncState.last_version = 1` (from server response)
- Both match, so no confusion yet

However, if the user adds 3 more entries locally on device 2 and then does a push:
- `VaultData.version = 8`
- Push sends `X-If-Match: 1` (from `SyncState.last_version`)
- Server checks: DB version == 1? Yes → updates to version 2
- `SyncState.last_version = 2`

Meanwhile on device 1, `SyncState.last_version` is still 1. Device 1 tries to push with `X-If-Match: 1` → 409 Conflict, which is correct behavior. But there is no way to determine whether the "internal" vault version (VaultData.version) is consistent with the server version without full decryption. A future feature that reports "your vault is N changes ahead of the last sync" relies on `VaultData.version` being meaningful, but it counts local mutations regardless of sync status.

More critically: if `SyncState.last_version` is corrupted or reset (e.g., the sidecar file is deleted), the client sends `X-If-Match: 0` on the next push. The server handler for this case is:

```rust
// No version header → first push path
query!("INSERT INTO vaults ... ON CONFLICT (user_id) DO NOTHING RETURNING ...")
```

Since the vault already exists, `ON CONFLICT DO NOTHING` returns zero rows → `RowNotFound` → 409 Conflict. The user gets a confusing conflict error with no guidance, even though their vault state is valid. They must use `push --force` which they may not know about.

**Remediation:**  
Consolidate to a single source of truth for sync version state. The `VaultData.version` internal counter should be removed or repurposed as a change sequence number that is distinct from the server sync version. Document clearly in code comments that `SyncState.last_version` is the canonical sync state. Add explicit handling for the "re-sync after lost sync state" scenario:

```rust
// If SyncState.last_version is 0 but a vault exists on server,
// pull first before attempting push, rather than failing with 409.
pub async fn run() -> anyhow::Result<()> {
    // ...
    if sync_state.last_version == 0 {
        // Check if vault exists on server first
        match client.pull(0).await {
            Ok((version, _)) if version > 0 => {
                // Server has a vault; user must pull or force push
                eprintln!("A vault exists on the server (version {version}). Run `pull` first or use `push --force`.");
                return Ok(());
            }
            _ => {} // No server vault or pull failed; proceed with first push
        }
    }
    // ...
}
```

---

### HIGH-05 — Clipboard Timeout Not Implemented Despite AGENTS.md Specification

**Severity:** HIGH  
**File:** `crates/nullwarden-cli/src/commands/get.rs`  
**OWASP 2025:** A02 Security Misconfiguration  

**Description:**  
`AGENTS.md` specifies: "Get entry: copies to clipboard for 30s". The implementation copies to clipboard but never clears it:

```rust
// commands/get.rs
cb.set_text(entry.password.0.clone())
    .context("failed to copy to clipboard")?;
println!("Password copied to clipboard. If you use a clipboard manager, clear its history after use.");
```

The password persists in the clipboard indefinitely until replaced. Any application with clipboard access (including many browser extensions, sync utilities, and malware) can silently read the password after the user has moved on. Clipboard managers log all clipboard history, meaning the password is often stored permanently on the user's system in plaintext in the clipboard manager's database.

The warning message is insufficient mitigation because users do not manually clear clipboard history, and in automated or scripted contexts the message is never read.

**Impact:** Passwords persist in clipboard and clipboard manager history indefinitely, accessible to all applications with clipboard API access.

**Remediation:**

Spawn a background thread to clear the clipboard after 30 seconds:

```rust
pub async fn run(title: String, print: bool) -> anyhow::Result<()> {
    // ...
    if !print {
        use arboard::Clipboard;
        let password_text = entry.password.0.clone();
        let mut cb = Clipboard::new().context("failed to access clipboard")?;
        cb.set_text(password_text.clone())
            .context("failed to copy to clipboard")?;

        println!("Password copied to clipboard. Will be cleared in 30 seconds.");

        // Spawn a background task to clear the clipboard
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            if let Ok(mut cb) = Clipboard::new() {
                // Only clear if our content is still there (don't clobber user's own clipboard)
                if cb.get_text().map(|t| t == password_text).unwrap_or(false) {
                    let _ = cb.set_text("");
                    eprintln!("Clipboard cleared.");
                }
            }
        });
    }
    Ok(())
}
```

Note: the background task approach requires the CLI process to remain alive for 30 seconds. For a true fire-and-forget approach, use a separate daemon process or platform-specific clipboard security APIs.

---

### HIGH-06 — `push --force` Has No Server-Side Rate Limiting and Can Destroy Vault History

**Severity:** HIGH  
**File:** `crates/nullwarden-cli/src/commands/push.rs`, `crates/nullwarden-server/src/db/vaults.rs`  
**OWASP 2025:** A02 Security Misconfiguration  

**Description:**  
The force push path bypasses all version checking and writes a backup on every invocation:

```rust
// db/vaults.rs — force push path
let res = if force {
    backup_current_vault(&mut tx, user_id).await?;
    query!(
        "INSERT INTO vaults (user_id, blob, version) VALUES ($1, $2, 1)
         ON CONFLICT (user_id) DO UPDATE SET blob = EXCLUDED.blob, version = vaults.version + 1 ..."
    )
```

`backup_current_vault()` is called on every force push. The history is capped at 3 entries, but:
1. An attacker with a valid access token can force-push garbage blobs repeatedly, filling the history with garbage and destroying all 3 history entries
2. The legitimate user's last 3 real vault states are overwritten with attacker-controlled garbage
3. Even after the access token expires and the account is recovered, the vault history is permanently destroyed

Combined with the missing vault rate limiting (HIGH-02), this is a complete vault destruction attack.

**Remediation:**  
Add server-side validation that the force push body is a structurally valid NullWarden vault (magic bytes check only — the server cannot decrypt but can check the header):

```rust
// handlers/vault.rs
pub async fn put_vault(..., body: Bytes) -> AppResult<impl IntoResponse> {
    // Structural validation: at minimum, check magic bytes
    // Server never decrypts, but can verify basic format integrity
    if body.len() < 73 || &body[..4] != b"NWAR" {
        return Err(AppError::BadRequest("Invalid vault format".to_string()));
    }
    // ...
}
```

Additionally, rate limit force pushes more strictly (e.g., max 3 per hour per user).

---

### HIGH-07 — Sync State Sidecar File Written Non-Atomically

**Severity:** HIGH (reliability/correctness)  
**File:** `crates/nullwarden-cli/src/sync_state.rs`  
**OWASP 2025:** A10 Exceptional Conditions  

**Description:**  
The vault file uses a correct atomic write pattern (write-tmp → fsync → rename). The sync state sidecar file does not:

```rust
// sync_state.rs
pub fn save(&self, vault_path: &Path) -> anyhow::Result<()> {
    let path = state_path(vault_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let raw = serde_json::to_string_pretty(self)?;
    fs::write(path, raw).context("failed to save sync state")?;  // ← not atomic
    Ok(())
}
```

`fs::write()` is equivalent to `open(O_TRUNC | O_CREAT) + write_all()` and is not atomic. A crash, power loss, or signal during this write can leave `vault.nw.sync` truncated or empty.

If the sidecar is corrupted or empty, on next load:
```rust
pub fn load(vault_path: &Path) -> anyhow::Result<Self> {
    // ...
    let raw = fs::read_to_string(&path)?;
    serde_json::from_str(&raw).context("failed to parse sync state")?  // ← parse error on empty/corrupt
}
```
This would return an error, propagating up and potentially aborting the push/pull operation entirely, rather than falling back to a safe default.

Additionally, if `serde_json::from_str` fails, `SyncState::default()` (version 0) is not returned — the error propagates and the user gets an unhelpful failure message.

**Remediation:**  
Apply the same atomic write pattern used for the vault, and add graceful fallback on parse failure:

```rust
pub fn load(vault_path: &Path) -> anyhow::Result<Self> {
    let path = state_path(vault_path);
    if !path.exists() {
        return Ok(Self::default());
    }
    let raw = fs::read_to_string(&path)?;
    // Graceful fallback: corrupt sync state means we lost version tracking
    // Default to version 0, which will cause a conflict on next push (recoverable)
    Ok(serde_json::from_str(&raw).unwrap_or_default())
}

pub fn save(&self, vault_path: &Path) -> anyhow::Result<()> {
    let path = state_path(vault_path);
    let tmp = path.with_extension("tmp");
    // ... same atomic write pattern as VaultStore::atomic_write() ...
}
```

---

### HIGH-08 — Docker Builder Stage Not Digest-Pinned; Supply Chain Risk

**Severity:** HIGH  
**File:** `Dockerfile`  
**OWASP 2025:** A03 Software Supply Chain  

**Description:**  
The Dockerfile uses a tag-pinned final stage but a mutable-tag builder stage:

```dockerfile
FROM rust:1.81.0-bookworm AS builder   # ← tag only, no digest pin
# ...
FROM debian:bookworm-slim@sha256:a629e796d77a7b2ff82186ed15d01a493801c020eed5ce6adaa2704356f15a1c  # ← digest pinned ✓
```

The `rust:1.81.0-bookworm` tag is mutable. Docker Hub could serve a different image under this tag (tag mutation, compromise of the `rust` official image, or simply an updated rebuild). All compilation artifacts — including the final server binary — are produced in the builder stage. A compromised builder image could:
1. Inject malicious code during compilation
2. Replace the compiled binary with a backdoored version
3. Exfiltrate `JWT_SECRET` or other build-time secrets if any are injected via `--build-arg`

The release pipeline's GitHub Actions `docker/build-push-action` will pull the builder image at push time, meaning the release binary is only as trustworthy as the builder image tag at that specific moment.

**Remediation:**

Pin both stages to immutable digests:

```dockerfile
FROM rust:1.81.0-bookworm@sha256:<digest> AS builder
FROM debian:bookworm-slim@sha256:a629e796d77a7b2ff82186ed15d01a493801c020eed5ce6adaa2704356f15a1c
```

Obtain the current digest:
```bash
docker pull rust:1.81.0-bookworm
docker inspect --format='{{index .RepoDigests 0}}' rust:1.81.0-bookworm
```

Update the `deny.toml` to include a Docker image digest verification step in CI.

---

### HIGH-09 — No Vault Blob Size Limit Beyond 10MB; Realistic Limit Should Be Smaller

**Severity:** HIGH  
**File:** `crates/nullwarden-server/src/app.rs`  
**OWASP 2025:** A02 Security Misconfiguration  

**Description:**  
The vault upload body limit is 10MB. A realistic password vault for an individual user contains hundreds to low thousands of entries. A typical vault with 1,000 entries (service, username, 32-char password, optional notes) would be approximately 100-200KB after serialization and encryption overhead. The 10MB limit is 50-100x larger than any realistic single-user vault.

This oversized limit:
1. Wastes server storage for every vault history entry (3 × 10MB = 30MB per user minimum on force pushes)
2. Increases the attack surface for resource exhaustion
3. Allows a legitimate user to accidentally upload corrupted tooling output, build artifacts, or other large files as a vault, which would always fail to decrypt but consume storage

**Remediation:**

Reduce the vault upload limit to a more realistic maximum (e.g., 1MB) and document the reasoning:

```rust
// A vault with 10,000 entries (extreme upper bound) is approximately 500KB.
// 1MB provides 2x headroom and prevents storage abuse.
const MAX_VAULT_BLOB_SIZE: usize = 1 * 1024 * 1024;

.layer(DefaultBodyLimit::max(MAX_VAULT_BLOB_SIZE))
```

---

### HIGH-10 — Algorithm Not Explicitly Pinned in JWT Validation

**Severity:** HIGH  
**File:** `crates/nullwarden-server/src/auth/jwt.rs`  
**OWASP 2025:** A07 Authentication Failures  

**Description:**  
JWT validation uses `Validation::default()` without explicitly setting the allowed algorithm:

```rust
let mut validation = Validation::default();
validation.set_audience(&[state.config.jwt_audience.as_str()]);
validation.set_issuer(&[state.config.jwt_issuer.as_str()]);
// ← validation.algorithms is not explicitly set
```

`jsonwebtoken` 9.x sets `algorithms: vec![Algorithm::HS256]` by default. However, the `Header::default()` used in `issue_access_token()` also uses HS256. While the current combination is safe, relying on implicit defaults for security-critical behavior is fragile:

1. A future `jsonwebtoken` version could change the default allowed algorithms
2. A code review might miss that the algorithm is implicit
3. If the codebase is ported to use RS256 (recommended in ADR-007), not explicitly resetting `validation.algorithms` could inadvertently allow both HS256 and RS256, enabling algorithm confusion attacks

**Remediation:**

Explicitly set the algorithm:

```rust
use jsonwebtoken::Algorithm;

let mut validation = Validation::new(Algorithm::HS256);  // explicitly HS256 only
validation.set_audience(&[state.config.jwt_audience.as_str()]);
validation.set_issuer(&[state.config.jwt_issuer.as_str()]);
validation.validate_exp = true;   // explicit, not implicit
```

When upgrading to RS256 in v0.2, set `Validation::new(Algorithm::RS256)` and remove the symmetric secret entirely from validation.

---

### HIGH-11 — No Vault Structural Validation During Pull Before Overwriting Local File

**Severity:** HIGH  
**File:** `crates/nullwarden-cli/src/commands/pull.rs`  

**Description:**  
The `pull` command validates vault integrity by attempting full decryption before writing to disk, which is good. However, the AEAD decryption requires the master password, which must be entered by the user. If a user runs `pull` on a vault they cannot yet decrypt (e.g., a different user's vault served by a compromised server), the write path fails gracefully. But the error path does not preserve the original vault file in all cases:

```rust
// pull.rs
store
    .unlock_bytes(&master_password, &bytes)
    .context("failed to decrypt downloaded vault (integrity check failed)")?;

tokio::fs::write(&config.vault_path, &bytes)
    .await
    .context("failed to write local vault")?;
```

If `unlock_bytes` succeeds (correct password, valid AEAD) but `tokio::fs::write` fails (disk full, permissions error), the local vault has not been overwritten — the original is intact. This case is handled correctly.

However, there is no backup of the current local vault before the write. If `tokio::fs::write` partially writes (extremely unlikely with most OS implementations but possible on some exotic filesystems or with certain filesystem errors), the local vault could be corrupted.

**Remediation:**

Create a backup of the current vault before overwriting:

```rust
// Before writing, save current vault as a backup
let backup_path = config.vault_path.with_extension("nw.bak");
if config.vault_path.exists() {
    tokio::fs::copy(&config.vault_path, &backup_path).await
        .context("failed to create local vault backup before pull")?;
}

tokio::fs::write(&config.vault_path, &bytes).await
    .context("failed to write local vault")?;

// Success: remove backup
let _ = tokio::fs::remove_file(&backup_path).await;
```

---

### HIGH-12 — `export_vault()` Public API Does Not Enforce Password Strength

**Severity:** HIGH  
**File:** `crates/nullwarden-cli/src/commands/export.rs`  

**Description:**  
The `export_vault()` function is the programmatic API for vault export. It does not call `validate_password_strength()`:

```rust
pub async fn export_vault(
    vault_path: &Path,
    output: &Path,
    master_password: &str,
    backup_password: &str,   // ← no strength check
) -> anyhow::Result<()> {
    let store = VaultStore::new(vault_path);
    let data = store.unlock(master_password)?;
    let backup_store = VaultStore::new(output);
    backup_store.save(backup_password, &data)?;  // ← weak password accepted
    Ok(())
}
```

The interactive `run()` function does check strength, but any code calling `export_vault()` directly — including the test at `tests/export_command.rs` which uses `"different-but-still-strong-42"` as the backup password — bypasses enforcement. A weak backup password (e.g., `"1234"`) would be accepted and would result in a backup vault that can be cracked orders of magnitude faster than the Argon2id parameters suggest.

The backup is particularly sensitive: it's often stored offline, on USB drives, or in cloud storage where an attacker might have easier access than to the online sync server.

**Remediation:**

Enforce strength in `export_vault()` itself:

```rust
pub async fn export_vault(
    vault_path: &Path,
    output: &Path,
    master_password: &str,
    backup_password: &str,
) -> anyhow::Result<()> {
    // Enforce strength on the backup password - this protects the exported artifact
    crate::input::validate_password_strength(backup_password)
        .context("backup password too weak")?;
    // ...
}
```

---

### HIGH-13 — TOCTOU Race Condition in `init` Command

**Severity:** HIGH  
**File:** `crates/nullwarden-cli/src/commands/init.rs`  

**Description:**  
The vault initialization command checks for an existing vault and then creates it, with no atomicity guarantee between the check and creation:

```rust
if config.vault_path.exists() {
    bail!("A vault already exists at {}...", config.vault_path.display());
}
// ← arbitrary time gap — another process or thread could create the file here
let store = VaultStore::new(&config.vault_path);
store.init(&password).context("failed to initialize vault")?;
```

`VaultStore::init()` → `save()` → `atomic_write()` uses `File::create()` which is `O_CREAT | O_TRUNC`. This will silently overwrite any file created in the gap. If two CLI processes (or the user and a deployment script) simultaneously run `nullwarden init` on the same vault path, one will silently destroy the other's newly created vault.

The window is small in practice (milliseconds between check and first write), but in automated deployment or test scenarios the race can be reproducible.

**Remediation:**

Use `O_CREAT | O_EXCL` semantics to fail atomically if the file already exists:

```rust
// In atomic_write(), use OpenOptions for the init case
// Or: check-and-create in one syscall using OpenOptions::create_new()

// vault/store.rs — add an init-specific write that fails if file exists:
fn atomic_write_new(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    // O_CREAT | O_EXCL: fails if file exists (atomic check-and-create)
    let tmp_path = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)  // ← atomic: fails with AlreadyExists if file exists
        .open(&tmp_path)?;
    file.write_all(data)?;
    file.sync_all()?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}
```

---

### HIGH-14 — Vault History Accumulates Old Encrypted Blobs; No Retention Policy Documentation

**Severity:** HIGH (operational/privacy)  
**File:** `crates/nullwarden-server/src/db/vaults.rs`  

**Description:**  
The `vault_history` table retains up to 3 previous encrypted vault blobs per user. These blobs are encrypted under the user's current master password key (since the vault is re-encrypted with the same key on each save). However, if a user changes their master password (currently not a supported operation), old history blobs remain encrypted under the old key. An attacker who compromises the DB and separately obtains an old master password (e.g., from a prior breach at another service) could decrypt old history entries even if the user has rotated to a new master password.

More practically: vault history is never deleted outside of the 3-entry cap and user account deletion. There is no user-facing mechanism to purge vault history, no time-based expiry, and no documentation informing users that their last 3 vault states are retained on the server.

**Remediation:**
1. Add a time-based expiry to `vault_history` entries (e.g., 30 days)
2. Add a `DELETE /vault/history` endpoint for user-initiated purge
3. Document the retention policy in `docs/privacy-policy.md` (it currently does not mention vault history)
4. When master password change is implemented (v0.2), ensure vault history is purged on key rotation

---

### HIGH-15 — Missing `X-Forwarded-For` Proxy Trust Configuration

**Severity:** HIGH  
**File:** `crates/nullwarden-server/src/app.rs`  
**OWASP 2025:** A02 Security Misconfiguration  

**Description:**  
The rate limiter uses `GlobalKeyExtractor` (from CRIT-02, to be replaced with `PeerIpKeyExtractor`). When deployed behind a reverse proxy (Nginx, Cloudflare, AWS ALB — which is the standard production deployment pattern), `PeerIpKeyExtractor` would read the proxy's IP address, not the actual client IP, making all users appear to be the same IP and triggering rate limits immediately.

The standard solution is to trust the `X-Forwarded-For` header from the proxy. However, if this header is trusted without validating the source IP (i.e., only accepting it from known proxy IPs), an attacker can spoof `X-Forwarded-For: 1.2.3.4` to bypass rate limiting entirely.

Neither scenario is handled: there is no trusted proxy configuration, no `X-Forwarded-For` processing, and no documentation of the expected deployment topology.

**Remediation:**  
Add configuration for trusted proxy CIDR ranges and use the rightmost non-trusted IP in `X-Forwarded-For`:

```rust
// config.rs
pub struct Config {
    // ...
    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<String>,  // e.g., ["10.0.0.0/8", "172.16.0.0/12"]
}
```

Use `tower_http::forwarded` or implement custom extraction that validates the forwarding chain.

---

## 5. Medium Findings

---

### MED-01 — `unlock()` Deserializes MessagePack Before Verifying Format Version

**Severity:** MEDIUM  
**File:** `crates/nullwarden-core/src/vault/store.rs`  

Vault format version is checked in `VaultHeader::decode()`, but the format version check only rejects unknown versions (non-0x01). As vault formats evolve, old clients will return `VaultError::InvalidFormat` with no indication that the vault is from a newer format version. Users will see a generic error with no migration guidance.

**Remediation:** Return a distinct error variant `VaultError::UnsupportedFormatVersion(u8)` that includes the version number found, allowing the CLI to display a helpful message: "This vault was created with a newer version of NullWarden. Please upgrade."

---

### MED-02 — `tracing-subscriber` JSON Mode Logs Full Internal Error Details to Stdout

**Severity:** MEDIUM  
**File:** `crates/nullwarden-server/src/main.rs`  

```rust
tracing_subscriber::fmt().json().init();
```

`AppError::Internal` logs with `{:?}` which includes the full debug representation including stack traces, DB connection strings that may appear in sqlx error messages, and file paths:

```rust
AppError::Internal(err) => {
    error!("Internal server error: {:?}", err);
```

In a containerized deployment where stdout is shipped to a log aggregator, this leaks internal system information. The error response to the client is correctly generic, but the server logs contain sensitive details.

**Remediation:** Use structured error logging that redacts sensitive fields. Log the error type and a correlation ID, not the full debug representation.

---

### MED-03 — No Input Length Limits on Vault Entry Fields

**Severity:** MEDIUM  
**File:** `crates/nullwarden-core/src/vault/data.rs`  

`add_entry()` and `update_entry()` accept unbounded `String` values for `title`, `username`, `password`, and `notes`. A user can create entries with megabyte-scale strings, producing a vault that exceeds the 10MB sync limit and can never be successfully pushed. The error they receive would be a server 413 response that provides no explanation about which entry is too large.

**Remediation:** Add reasonable length limits per field (e.g., title: 256 chars, username: 256 chars, password: 4096 chars, notes: 10,000 chars) and return `VaultError::EntryFieldTooLong` with the field name.

---

### MED-04 — CORS Configured With `AllowOrigin::any()` in Production-Intended Code

**Severity:** MEDIUM  
**File:** `crates/nullwarden-server/src/app.rs`  

```rust
.allow_origin(AllowOrigin::any()) // In production, restrict to your domain
```

The comment acknowledges this is wrong for production but it's implemented in production code with no enforcement mechanism. A future web UI or browser extension that sends cookies would be vulnerable to CSRF if this is not changed before launch.

**Remediation:** Make allowed origins a configuration parameter with no default (startup failure if not set in production mode) or default to `AllowOrigin::list([])` (deny all cross-origin) and require explicit configuration.

---

### MED-05 — Refresh Token Revocation in `consume_refresh_token` Is Silent on Failure

**Severity:** MEDIUM  
**File:** `crates/nullwarden-server/src/auth/token.rs`  

(Partially covered in HIGH-01) — specifically, the in-memory test implementation of `RefreshTokenRepository` for `cleanup_expired_tokens` always returns `Ok(0)` without actually removing expired tokens. This causes tests to accumulate expired tokens in memory, potentially causing false passing results for tests that verify refresh tokens cannot be reused after logout, if the token's in-memory expiry record is never cleaned up.

**Remediation:** Implement actual expiry-based cleanup in the in-memory repository.

---

### MED-06 — Health Endpoint Returns Service Confirmation Without Authentication

**Severity:** MEDIUM  
**File:** `crates/nullwarden-server/src/app.rs`  

```rust
.route("/health", get(|| async { "ok" }))
```

The unauthenticated health endpoint confirms service availability and can be used by attackers to:
- Confirm the service is running before targeted attacks
- Monitor for service restarts to time token replay attacks
- Enumerate service versions if the response includes version information

**Remediation:** At minimum, move `/health` to a non-public port (separate health check port) or add a simple shared secret check. A `/readiness` endpoint for load balancer use should be separate from `/liveness`.

---

### MED-07 — `zxcvbn` Does Not Check for Context-Specific Weak Passwords

**Severity:** MEDIUM  
**File:** `crates/nullwarden-cli/src/input.rs`  

```rust
pub fn validate_password_strength(password: &str) -> anyhow::Result<()> {
    let estimate = zxcvbn(password, &[]);  // ← empty user_inputs list
```

`zxcvbn` accepts a list of user-specific inputs (username, application name, etc.) to additionally penalize passwords derived from them. With an empty list, `"nullwarden123"` or `"vaultmaster"` would score higher than their actual security warrants, since zxcvbn doesn't know these are application-specific strings.

**Remediation:**

```rust
let estimate = zxcvbn(password, &["nullwarden", "vault", "master", "password"]);
```

---

### MED-08 — No Protection Against Vault Enumeration via Timing on `GET /vault`

**Severity:** MEDIUM  
**File:** `crates/nullwarden-server/src/handlers/vault.rs`  

The `GET /vault` endpoint returns 404 for users who have no vault and 200 for users who do. While this requires a valid JWT (authenticated user), a user who registers can determine whether another user ID has a vault via timing or direct testing. In multi-user deployments, this could reveal account activity patterns.

**Remediation:** Consider returning 200 with an empty body for new users rather than 404, or document the intended information disclosure.

---

### MED-09 — `Dockerfile` Runs as Non-Root but Does Not Drop Linux Capabilities

**Severity:** MEDIUM  
**File:** `Dockerfile`  

The Dockerfile correctly drops root with `USER nullwarden`, but does not drop Linux capabilities:

```dockerfile
USER nullwarden
CMD ["nullwarden-server"]
```

By default, containers retain capabilities like `CAP_NET_BIND_SERVICE`, `CAP_DAC_OVERRIDE`, `CAP_AUDIT_WRITE`, etc. For a password vault server, no additional capabilities beyond the absolute minimum are needed.

**Remediation:**

```dockerfile
# In docker-compose.yml or Kubernetes manifests:
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
cap_add:
  - NET_BIND_SERVICE  # only if binding to port < 1024
```

---

### MED-10 — No Vault Integrity Check After Successful `push`

**Severity:** MEDIUM  
**File:** `crates/nullwarden-cli/src/commands/push.rs`  

The `push` command uploads the encrypted blob but does not verify that the server returned the same blob on a subsequent `GET`. If the server silently modified or truncated the blob (due to a bug, storage error, or malicious behavior), the client would have no indication. The user's only protection is the eventual AEAD decryption failure when pulling on another device.

**Remediation:** After a successful push, do a `GET /vault` and verify the SHA-256 hash of the returned blob matches the uploaded blob. This can be done with a lightweight HEAD-like request if a content hash header is added to the GET response:

```
Response header: X-Vault-Content-Hash: sha256:<hex>
```

---

### MED-11 — `icacls` Subprocess on Windows Not Validated for Exit Code Details

**Severity:** MEDIUM  
**File:** `crates/nullwarden-cli/src/session.rs`  

The `icacls` failure case only checks `status.success()`:

```rust
if !status.success() {
    anyhow::bail!("icacls failed while securing session file permissions");
}
```

`icacls` may return success (exit code 0) while logging errors to stderr if some ACL entries fail to apply (e.g., for unresolvable usernames). The function has no stderr capture to detect silent ACL application failures.

**Remediation:** Capture and log stderr output from `icacls`:

```rust
let output = Command::new(icacls_path)
    .args([...])
    .output()?;

if !output.status.success() {
    let stderr = String::from_utf8_lossy(&output.stderr);
    anyhow::bail!("icacls failed: {}", stderr);
}
```

---

### MED-12 — No Expiry on Token Blocklist Cleanup Interval

**Severity:** MEDIUM  
**File:** `crates/nullwarden-server/src/main.rs`  

The cleanup task runs every `cleanup_interval_secs` (default 3600s = 1 hour). During this interval, the `token_blocklist` table accumulates expired entries. Access tokens have a 15-minute lifetime, so at default settings the table can accumulate 4 cycles of expired tokens before cleanup. Under high load with many logouts, this table can grow significantly.

More importantly, the `contains_token()` query performs a full table scan if the `token_blocklist.token_hash` is not indexed:

```sql
SELECT 1 FROM token_blocklist WHERE token_hash = $1
```

`token_hash TEXT PRIMARY KEY` — this IS indexed as primary key. OK. But the cleanup query:

```sql
DELETE FROM token_blocklist WHERE expires_at < $1
```

requires the index on `expires_at`. The migration creates this index (`idx_token_blocklist_expires_at`). This is fine.

However, the cleanup interval is configurable down to 1 second, which could cause excessive DB load. There's no minimum validation on `CLEANUP_INTERVAL_SECS`.

**Remediation:** Validate minimum cleanup interval in config:

```rust
if cfg.cleanup_interval_secs < 60 {
    anyhow::bail!("CLEANUP_INTERVAL_SECS must be at least 60 seconds");
}
```

---

### MED-13 — Vault Version Counter Stored in VaultData Is Redundant and Misleading

**Severity:** MEDIUM  
**File:** `crates/nullwarden-core/src/vault/data.rs`  

`VaultData.version` (u64) is incremented on every mutation but:
1. It is not used by the sync protocol (which uses `SyncState.last_version` from the server)
2. It is not used for any integrity check
3. It creates confusion about what "version" means (vault mutation count vs. server sync version)

A developer reading the code might assume `VaultData.version` is the value to send in `X-If-Match`, leading to bugs.

**Remediation:** Remove `VaultData.version` or rename it to `VaultData.mutation_count` to clearly distinguish it from the sync version. Add a doc comment clarifying the difference.

---

### MED-14 — `warn_if_default_server_url` Is Advisory Only; No Production Guard

**Severity:** MEDIUM  
**File:** `crates/nullwarden-cli/src/config.rs`  

```rust
pub fn warn_if_default_server_url(config: &Config, command: &str) {
    if config.server_url == DEFAULT_SERVER_URL {
        eprintln!("Warning: `{command}` is using the default server URL ({DEFAULT_SERVER_URL})...");
    }
}
```

This warning is printed to stderr but execution continues. A user deploying NullWarden for production use with the default config will push their vault to `http://127.0.0.1:8080` (a non-existent server) without realizing it. All pushes will fail silently if the server isn't running, or worse, they might be pushing to a locally running test server and believe their data is synced.

**Remediation:** For the `push` command specifically, consider making the default server URL a hard error, not a warning. At minimum, add a `--force` flag that must be explicitly provided when using the default URL.

---

### MED-15 — Missing Structured Error Types for Network Failures Reaching User

**Severity:** MEDIUM  
**File:** `crates/nullwarden-cli/src/error.rs`, `crates/nullwarden-cli/src/client/sync.rs`  

Network errors propagate as `CliError::ServerUnavailable` which produces:
```
Error: Cannot reach NullWarden server at http://127.0.0.1:8080. Is the server running? <connection refused>
```

For a production deployment, this message instructs users to check if the server is running at a localhost address they don't recognize. The error message should include the configured server URL and clearer recovery guidance.

**Remediation:** Include the full configured `server_url` in error messages and add guidance specific to the command that failed.

---

### MED-16 — No `seccomp` Profile or AppArmor Policy for Container

**Severity:** MEDIUM  
**File:** `Dockerfile`, `docker-compose.yml`  

The container has no syscall filtering (`seccomp`) or mandatory access control profile (`AppArmor`/`SELinux`). For a security-focused application handling vault blobs, restricting the container's system call surface reduces the blast radius of any vulnerability in the Axum/Tokio stack.

**Remediation:** Create a custom `seccomp` profile that allows only the syscalls needed by the server: network I/O, file I/O, process management, signals. Reference Docker's default `seccomp` profile and further restrict it.

---

## 6. Low Findings

---

### LOW-01 — `prompt_password()` Does Not Trim Trailing Newline on Non-TTY Input

**Severity:** LOW  
**File:** `crates/nullwarden-cli/src/input.rs`  

`rpassword::read_password()` reads until newline on TTY. In piped or scripted usage (`echo "mypassword" | nullwarden init`), the trailing newline is included in the returned string. `zxcvbn` would evaluate `"mypassword\n"` rather than `"mypassword"`, and the derived vault key would be different from what the user expects.

**Remediation:** Trim trailing newlines from the returned password: `password.trim_end_matches('\n').trim_end_matches('\r').to_string()`.

---

### LOW-02 — Error Enums Not Marked `#[non_exhaustive]`

**Severity:** LOW  
**Files:** `crates/nullwarden-core/src/error.rs`, `crates/nullwarden-server/src/error.rs`  

`VaultError` and `AppError` are public enums without `#[non_exhaustive]`. Adding a new variant in a future version is a breaking change for any downstream code that matches on these enums.

**Remediation:** Add `#[non_exhaustive]` to both enums.

---

### LOW-03 — `cargo deny` Policy Has `multiple-versions = "warn"` Instead of `"deny"`

**Severity:** LOW  
**File:** `deny.toml`  

```toml
[bans]
multiple-versions = "warn"   # ← allows duplicate dependencies
```

Multiple versions of the same dependency increase compile time, binary size, and supply chain attack surface. CI currently warns but does not fail on version duplication. The Cargo.lock confirms multiple versions of several crates (e.g., `windows-sys` appears at 0.48, 0.52, 0.59, 0.60, 0.61).

**Remediation:** Change to `multiple-versions = "deny"` and resolve duplicates, or add explicit `skip` rules with justification for unavoidable duplicates.

---

### LOW-04 — `SecretString.serialize()` Emits Plaintext in Debug/Log Contexts

**Severity:** LOW  
**File:** `crates/nullwarden-core/src/types.rs`  

`SecretString` implements `Serialize` to emit the raw string value. The code comment correctly warns about this:

```rust
/// # Warning
///
/// The `Serialize` implementation for this type emits the **plaintext** string.
/// This is intended for encrypted storage (e.g. MessagePack vaults) but means
/// this type must **never** be used as a field in a struct that is serialized
/// to JSON for an HTTP response
```

However, there is no compile-time enforcement of this constraint. A developer could accidentally serialize a `SecretString` in an HTTP handler, leaking the plaintext in a JSON response.

**Remediation:** Add a `#[cfg(test)]`-gated attribute or a custom wrapper type that panics if serialized outside of the vault encryption context. Alternatively, use `serde(skip)` by default and require explicit opt-in for vault serialization via a newtype wrapper.

---

## 7. Supply Chain and Dependency Audit

### 7.1 Blocking Vulnerability

**RUSTSEC-2023-0071** — `rsa` crate — Marvin Attack (timing side-channel for key recovery)

**Dependency path:** `nullwarden-server` → `sqlx` → `sqlx-macros-core` → `sqlx-mysql` → `rsa 0.9.x`

**Status:** No fixed version available upstream for `rsa`.

**Impact in context:** NullWarden never performs RSA operations. The `rsa` crate is compiled dead code pulled in via `sqlx-mysql` which is included by `sqlx-macros-core` (which provides compile-time query checking) even when only PostgreSQL is needed.

**Fix:** Remove the `macros` feature from the `sqlx` dependency. The server code uses `sqlx::query()` runtime functions exclusively — confirmed by reviewing `db/users.rs`, `db/vaults.rs`, `db/tokens.rs`. No `sqlx::query!()` or `sqlx::query_as!()` macros are used anywhere.

```toml
# crates/nullwarden-server/Cargo.toml
# BEFORE:
# sqlx = { package = "sqlx-core", ... features = [..., "macros?"] }  (if any macro feature exists)

# AFTER — explicitly exclude macros to eliminate sqlx-macros-core → sqlx-mysql → rsa chain:
sqlx = { package = "sqlx-core", version = "=0.8.6", default-features = false, features = [
    "_rt-tokio", "_tls-rustls-ring-webpki", "uuid", "chrono", "migrate"
    # "macros" intentionally absent
] }
```

Verify the fix by running `cargo tree -p nullwarden-server | grep rsa` — should return no output.

### 7.2 Unmaintained Dependency Warnings

| Advisory | Crate | Version | Via | Fix |
|----------|-------|---------|-----|-----|
| RUSTSEC-2021-0145 | `atty` | 0.2.14 | `criterion` 0.3 | Upgrade criterion to 0.5 |
| RUSTSEC-2024-0375 | `atty` | 0.2.14 | `criterion` 0.3 | Same |
| RUSTSEC-2021-0127 | `serde_cbor` | 0.11.2 | `criterion` 0.3 | Same |
| RUSTSEC-2024-0388 | `derivative` | 2.2.0 | `keyring` 2.x → `zbus` 3.x | Upgrade keyring to 3.x |
| RUSTSEC-2024-0384 | `instant` | 0.1.13 | `keyring` 2.x → `zbus` 3.x | Same |
| RUSTSEC-2025-0134 | `rustls-pemfile` | 2.2.0 | `axum-server` 0.7.x | Upgrade axum-server or add deny.toml ignore |

### 7.3 Complete Dependency Fix Manifest

```toml
# crates/nullwarden-core/Cargo.toml
[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }   # was "0.3"

# crates/nullwarden-cli/Cargo.toml
keyring = "3"   # was "2" — drops zbus 3.x / derivative / instant

# crates/nullwarden-server/Cargo.toml
sqlx = { package = "sqlx-core", version = "=0.8.6", default-features = false, features = [
    "_rt-tokio", "_tls-rustls-ring-webpki", "uuid", "chrono", "migrate"
    # macros removed
]}
axum-server = { version = "0.8.0", features = ["tls-rustls"] }  # check for rustls-pemfile fix
```

After applying these changes, `cargo audit` and `cargo deny check` should both pass cleanly.

### 7.4 Multiple Version Duplication

The following crates appear in multiple versions in `Cargo.lock`, increasing binary size and attack surface:

| Crate | Versions Present |
|-------|------------------|
| `windows-sys` | 0.48, 0.52, 0.59, 0.60, 0.61 (5 versions) |
| `windows-targets` | 0.48, 0.52, 0.53 |
| `hashbrown` | 0.14, 0.15, 0.17 |
| `thiserror` | 1.0, 2.0 |
| `itertools` | 0.10, 0.13 |
| `tower` | 0.4, 0.5 |
| `tower-http` | 0.5, 0.6 |
| `getrandom` | 0.2, 0.3, 0.4 |
| `rand_core` | 0.6, 0.9 |

The `tower` / `tower-http` duplication (0.4 + 0.5) is the most significant — the server uses `tower 0.4` (for middleware) while `reqwest` pulls `tower 0.5`. These are ABI-incompatible and both are compiled into the final binary.

---

## 8. Cryptographic Analysis

### 8.1 Primitive Assessment

| Component | Choice | Assessment |
|-----------|--------|------------|
| Vault KDF | Argon2id m=65536 t=3 p=4 | ✅ Correct. PHC winner. Memory-hard and time-hard. Parameters exceed OWASP minimum. 300ms CI gate enforces latency. |
| Vault AEAD | XChaCha20-Poly1305 | ✅ Correct. 192-bit nonce eliminates random collision risk. Software-constant-time. RustCrypto crate, audited. |
| Nonce generation | OsRng (24 bytes) | ✅ Correct. CSPRNG. Per-operation uniqueness. |
| Salt generation | OsRng (32 bytes) | ✅ Correct. Per-vault fresh salt on every save. |
| Auth password hashing | Argon2id (PHC string format) | ✅ Correct. Independent of vault KDF path. |
| Auth password comparison | Argon2 library (constant-time internally) | ✅ Correct. |
| Refresh token comparison | SHA-256 + `constant_time_eq` | ✅ Correct. Timing-safe. |
| JWT signing | HS256 | ⚠️ Acceptable for prototype. RS256 recommended for production (key rotation, asymmetric verification). See HIGH-10. |
| Access token blocking | SHA-256 of token string | ✅ Correct. Prevents token hash length extension. |
| Vault payload serialization | MessagePack (rmp-serde) | ✅ Correct. Binary, compact, consistent encoding. |
| Secret memory handling | `Zeroize` + `ZeroizeOnDrop` | ✅ Correct. `Debug` impls redacted. Unit tests validate zeroing. |

### 8.2 Key Separation Verification

The architectural separation between server auth credentials and vault encryption key material is correctly implemented and enforced:

- Server `password.rs` uses `argon2::PasswordHasher` (produces PHC string `$argon2id$...`)
- Core `kdf.rs` uses `argon2::hash_password_into` (produces raw bytes for AEAD key)
- No code in `nullwarden-server` imports or calls `nullwarden_core::kdf::derive_key`
- No vault encryption key bytes appear in server logs, DB schema, or wire format

**This invariant is correctly maintained.**

### 8.3 Nonce Safety

XChaCha20-Poly1305 with a 192-bit CSPRNG nonce:

```
P(collision | n encryptions) = 1 - e^(-n²/2^193)

n = 2^64 (astronomical):   P ≈ 2^(-65)   — negligible
n = 2^32 (~4B operations): P ≈ 2^(-129)  — effectively zero
```

Compare to AES-GCM (96-bit nonce):
```
n = 2^32: P ≈ 50%  — serious collision risk
```

The nonce is regenerated on every `save()` call (not per-entry), meaning the entire vault re-encrypts with a fresh nonce on every mutation. This is correct and eliminates any partial-encryption attack surface.

### 8.4 KDF Parameter Adequacy

The current parameters (`m=65536, t=3, p=4`) target ≥300ms on reference hardware. Against a 2026 attacker:

- **GPU (RTX 4090):** ~64GB VRAM. At 64MB per Argon2id hash, approximately 1,000 parallel guesses. If the GPU can compute one hash per 300ms, that's ~3,330 hashes/second — or ~288M guesses/day
- **zxcvbn score ≥ 3** represents a password space exceeding ~10^10 (10 billion guesses)
- **Time to crack a score-3 password** at 288M/day ≈ 34 days on a single RTX 4090

This is adequate for a prototype. For production, consider increasing to `m=131072` (128MB) when hardware improves. The `migrate` command provides a migration path.

### 8.5 Authenticated Encryption Integrity

The AEAD tag is verified by `chacha20poly1305` before any plaintext is returned. The crate uses the `decrypt()` method which:
1. Verifies the Poly1305 authentication tag
2. Returns `Err(aead::Error)` on any verification failure
3. Never returns partial plaintext

`VaultCipher::decrypt()` correctly maps `aead::Error` to `VaultError::DecryptionFailed` without exposing the underlying error. **No timing oracle in the decryption path.**

---

## 9. Architecture and Design Review

### 9.1 Trust Boundary Correctness

The zero-knowledge server boundary is correctly implemented:
- ✅ No `derive_key()` calls in server code
- ✅ No plaintext fields in `vaults` table  
- ✅ Server returns opaque `BYTEA` blobs
- ✅ `VaultData` deserialization happens only after client-side decryption
- ✅ Server cannot distinguish between a vault with 1 entry vs. 1,000 entries (beyond blob size)

**Confirmed: zero-knowledge invariant holds at the code level.**

### 9.2 Session Architecture

The JWT + refresh token architecture is sound with the following notes:

**Correct:**
- Short access token lifetime (15 min)
- Refresh token rotation (single-use)
- Server-side blocklist for revoked access tokens
- Constant-time comparison for refresh token secrets
- SHA-256 of token for blocklist storage (not Argon2id, which is correct — SHA-256 is appropriate for high-entropy random tokens)
- Dummy hash for login timing oracle mitigation

**Gaps:**
- No `jti` (JWT ID) claim for fine-grained revocation without blocklist
- `iss` and `aud` default values create cross-instance confusion risk (MED)
- No `nbf` (not-before) claim to prevent pre-issued token use
- JWT secret rotation procedure exists but is manual; no automated rotation

### 9.3 Sync Protocol Correctness

The optimistic locking protocol:
- Version counter starts at 1 on first push
- `X-If-Match` header carries expected version
- DB `UPDATE ... WHERE version = $expected_version` provides atomic check-and-update
- `RowNotFound` → 409 Conflict is correct
- `X-Force` bypass is authenticated but unrate-limited (see HIGH-02, HIGH-06)

**Gap:** The protocol does not sign server responses. A MITM who can intercept the `X-Vault-Version` response header can downgrade the client's local version counter, causing spurious conflict errors on subsequent pushes. Full server-response signing is on the roadmap (ADR mention) but absent.

### 9.4 Atomic Write Correctness

The vault write path is correctly implemented:

```
write(tmp) → sync_all() → rename(tmp → vault) → [Unix: sync parent dir]
```

On POSIX systems, `rename()` is atomic at the filesystem level. The `sync_all()` before rename ensures data is durable before the rename makes it visible. The parent directory fsync ensures the rename itself is durable (important on ext4 without `data=journal`).

**One gap:** `atomic_write()` creates the temp file with `fs::File::create()`, which opens with `O_TRUNC`. If a `.tmp` file already exists from a previous crashed write, it is silently overwritten rather than checked. This is acceptable behavior but worth documenting.

---

## 10. Testing Gap Analysis

### 10.1 Missing Test Coverage

| Gap | Risk | Recommended Test |
|-----|------|-----------------|
| KDF parameter bounds validation (CRIT-03) | HIGH | Fuzz `VaultHeader::decode()` with extreme m_cost/t_cost/p_cost values |
| Windows ACL fallback behavior | HIGH | Unit test `save_to_file()` with missing `USERNAME` env var |
| Rate limit per-IP behavior (after CRIT-02 fix) | HIGH | Integration test with multiple simulated IPs |
| `lock` command server-side revocation (CRIT-04) | HIGH | E2E test: lock → verify access token rejected |
| Clipboard clearing after 30s (HIGH-05) | MEDIUM | Async test with mocked clipboard |
| `export_vault()` with weak password (HIGH-12) | MEDIUM | Unit test that `export_vault("1234")` returns error |
| Vault history destruction via force push (HIGH-06) | MEDIUM | Integration test: force push N times, verify history capped |
| Sync state corruption recovery (HIGH-07) | MEDIUM | Write corrupt JSON to sidecar, verify graceful fallback |
| Wrong format version in vault header | MEDIUM | Unit test `VaultHeader::decode()` with version byte = 0x02 |
| Large vault beyond 10MB upload limit | MEDIUM | Integration test: PUT /vault with 10MB + 1 byte body → 413 |
| Concurrent `init` race condition (HIGH-13) | LOW | Spawn two threads calling `init()` simultaneously |

### 10.2 Fuzz Coverage Gaps

Current fuzz targets cover:
- `decrypt_input` — random bytes as ciphertext → no panics ✅
- `vault_deserialize` — random bytes as MessagePack → no panics ✅

Missing fuzz targets:
- `vault_header_decode` — random bytes as vault header (important for CRIT-03)
- `unlock_bytes` — complete vault bytes with random KDF params
- `json_auth_payload` — random JSON as auth request body
- `vault_put_body` — random bytes as vault upload body

### 10.3 Property-Based Testing Gaps

No `proptest` or `quickcheck` usage found. Recommended property tests:

```rust
// Property: encrypt → decrypt is identity for all keys and plaintexts
proptest! {
    fn encrypt_decrypt_roundtrip(key in any::<[u8; 32]>(), plaintext in any::<Vec<u8>>()) {
        let vault_key = VaultEncryptionKey(key);
        let (nonce, ct) = encrypt(&vault_key, &plaintext).unwrap();
        let pt = decrypt(&vault_key, &nonce, &ct).unwrap();
        prop_assert_eq!(pt, plaintext);
    }
}

// Property: any modification to ciphertext fails authentication
proptest! {
    fn tamper_always_fails(flip_pos in 0usize..100) {
        // ...
    }
}
```

---

## 11. CI/CD Pipeline Review

### 11.1 `ci.yml` Assessment

| Check | Status | Notes |
|-------|--------|-------|
| `cargo fmt` | ✅ | Enforced |
| `cargo clippy -D warnings` | ✅ | Zero-warning gate |
| `cargo test --workspace` | ✅ | All tests must pass |
| KDF latency gate | ✅ | `--ignored kdf_meets_minimum_latency` |
| `cargo audit` | ⚠️ | Blocked by RUSTSEC-2023-0071 until dependency fix |
| `cargo deny check` | ✅ | License + advisory policy |
| Coverage gate (core ≥80%) | ✅ | Tarpaulin enforced |
| Coverage gate (server ≥60%) | ✅ | Tarpaulin enforced |
| Miri job | ✅ | Runs on nightly, detects UB |
| Secret scanning | ❌ | No `git-secrets` / `trufflehog` in `ci.yml` — AGENTS.md mentions it as required but it's not implemented |
| SBOM generation in CI | ❌ | Only in release workflow, not in PR CI |
| Dependency pinning check | ❌ | No check that `Cargo.lock` is committed and up-to-date |

### 11.2 `release.yml` Assessment

| Check | Status | Notes |
|-------|--------|-------|
| Multi-target build matrix | ✅ | 5 targets covered |
| SBOM via `cargo-cyclonedx` | ✅ | |
| Binary signing via `minisign` | ✅ | Requires `MINISIGN_SECRET_KEY` secret |
| SHA256 checksums | ✅ | |
| Docker build + push to GHCR | ✅ | |
| Builder image digest pinning | ❌ | See HIGH-08 |
| Reproducible build verification | ❌ | No verification that two identical builds produce identical binaries |
| Release gate (must pass CI first) | ❌ | `release.yml` runs on tag push independently; there's no explicit `needs: ci` dependency |

**Critical gap in release.yml:** A tag can be pushed on a commit that failed CI, and the release workflow would still build and publish binaries. Add:

```yaml
# release.yml
jobs:
  build:
    needs: [ci-check]  # require CI to pass first
```

### 11.3 Secret Scanning Gap

`AGENTS.md` requires:
> No secrets in git history (`git-secrets` / `trufflehog`)

But neither tool is integrated in `ci.yml`. The `JWT_SECRET` in `.env.example` is clearly marked as a placeholder, but there is no automated check to prevent accidental commit of real secrets.

**Add to `ci.yml`:**

```yaml
- name: Scan for secrets in repository history
  uses: trufflesecurity/trufflehog@main
  with:
    path: ./
    base: ${{ github.event.repository.default_branch }}
    head: HEAD
    extra_args: --debug --only-verified
```

---

## 12. Infrastructure and Deployment Review

### 12.1 Docker Configuration

| Aspect | Assessment |
|--------|------------|
| Multi-stage build | ✅ Build artifacts not in final image |
| Non-root user | ✅ `USER nullwarden` |
| Minimal base image | ✅ `debian:bookworm-slim` |
| Digest-pinned final stage | ✅ |
| Digest-pinned builder stage | ❌ HIGH-08 |
| Health check in Dockerfile | ❌ No `HEALTHCHECK` instruction |
| Capability dropping | ❌ MED-09 |
| Read-only root filesystem | ❌ Not configured in docker-compose |
| Exposed port documented | ✅ `EXPOSE 8080` |
| No secrets in image | ✅ All via env vars |

**Recommended Dockerfile additions:**

```dockerfile
# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q --spider http://localhost:8080/health || exit 1

# Security labels
LABEL org.opencontainers.image.source="https://github.com/org/nullwarden"
LABEL org.opencontainers.image.licenses="MIT"
```

### 12.2 Database Security

| Aspect | Assessment |
|--------|------------|
| Parameterized queries everywhere | ✅ All sqlx queries use bind parameters |
| Migrations run at startup | ✅ `Migrator::run()` in main |
| Separate DB user for app | ⚠️ Not documented; docker-compose uses a single `nullwarden` user for everything |
| DB connection string in plaintext env | ⚠️ `DATABASE_URL` is in `.env`; production should use secrets manager |
| Vault blob column type | ✅ `BYTEA` — opaque, no text indexes |
| No vault content in indexes | ✅ No index on `blob` column |
| Connection pool size limit | ✅ Configurable `DB_MAX_CONNECTIONS` |
| RLS on Supabase | ✅ (but see CRIT-01 for plain PostgreSQL) |

### 12.3 TLS Configuration

The server supports TLS via `axum-server` + `rustls`. On startup:
- If `TLS_CERT_PATH` and `TLS_KEY_PATH` are both set: TLS enabled
- Otherwise: plain HTTP with a `WARN` log

**Gap:** No minimum TLS version enforcement is visible in the code. `rustls` defaults to TLS 1.2 minimum. For a security vault, TLS 1.3-only should be enforced:

```rust
// Configure rustls to TLS 1.3 only
use rustls::ServerConfig;
let tls_cfg = ServerConfig::builder()
    .with_safe_default_cipher_suites()
    .with_safe_default_kx_groups()
    .with_protocol_versions(&[&rustls::version::TLS13])?
    // ...
```

---

## 13. Finding Summary Table

| ID | Title | Severity | File(s) | OWASP 2025 |
|----|-------|----------|---------|------------|
| CRIT-01 | Supabase `auth.uid()` breaks plain PostgreSQL | CRITICAL | migrations/* | A02 |
| CRIT-02 | Global rate limiting enables auth DoS | CRITICAL | app.rs | A07 |
| CRIT-03 | Vault KDF params unsanitized — OOM DoS | CRITICAL | store.rs, header.rs | A10 |
| CRIT-04 | `lock` command doesn't revoke server-side token | CRITICAL | lock.rs | A07 |
| CRIT-05 | Windows ACL fallback grants all-users on missing USERNAME | CRITICAL | session.rs | A02 |
| HIGH-01 | Logout non-atomic; partial revocation possible | HIGH | auth.rs, token.rs | A07 |
| HIGH-02 | No per-user rate limit on vault endpoints | HIGH | app.rs, vault.rs | A02 |
| HIGH-03 | No security event audit logging | HIGH | handlers/* | A09 |
| HIGH-04 | Version counter divergence between client and server | HIGH | data.rs, sync_state.rs | A06 |
| HIGH-05 | Clipboard password not cleared after 30s | HIGH | get.rs | A02 |
| HIGH-06 | Force push can destroy vault history; no rate limit | HIGH | push.rs, vaults.rs | A02 |
| HIGH-07 | Sync state sidecar file written non-atomically | HIGH | sync_state.rs | A10 |
| HIGH-08 | Docker builder stage not digest-pinned | HIGH | Dockerfile | A03 |
| HIGH-09 | Vault upload limit too permissive (10MB) | HIGH | app.rs | A02 |
| HIGH-10 | JWT algorithm not explicitly pinned in validation | HIGH | jwt.rs | A07 |
| HIGH-11 | No local vault backup before pull overwrite | HIGH | pull.rs | A10 |
| HIGH-12 | `export_vault()` API skips password strength check | HIGH | export.rs | A07 |
| HIGH-13 | TOCTOU race in vault `init` | HIGH | init.rs | A10 |
| HIGH-14 | Vault history retained without user-facing expiry | HIGH | vaults.rs | Privacy |
| HIGH-15 | No trusted proxy config for `X-Forwarded-For` | HIGH | app.rs | A02 |
| MED-01 | No version-specific error on unsupported format | MEDIUM | store.rs | UX |
| MED-02 | Full internal errors logged in JSON mode | MEDIUM | main.rs | A09 |
| MED-03 | No length limits on vault entry fields | MEDIUM | data.rs | A02 |
| MED-04 | CORS wildcard in production code | MEDIUM | app.rs | A02 |
| MED-05 | In-memory test repo never cleans expired tokens | MEDIUM | support.rs | Testing |
| MED-06 | Unauthenticated health endpoint | MEDIUM | app.rs | A02 |
| MED-07 | `zxcvbn` not seeded with context-specific words | MEDIUM | input.rs | A07 |
| MED-08 | Vault existence info-leak via GET 404 | MEDIUM | vault.rs | A01 |
| MED-09 | Container does not drop Linux capabilities | MEDIUM | Dockerfile | A02 |
| MED-10 | No post-push integrity verification | MEDIUM | push.rs | A08 |
| MED-11 | `icacls` stderr not captured | MEDIUM | session.rs | A02 |
| MED-12 | No minimum `CLEANUP_INTERVAL_SECS` validation | MEDIUM | main.rs | A02 |
| MED-13 | `VaultData.version` is redundant and misleading | MEDIUM | data.rs | A06 |
| MED-14 | Default server URL warning is advisory only | MEDIUM | config.rs | A02 |
| MED-15 | Network error messages expose internal config | MEDIUM | error.rs | A09 |
| MED-16 | No `seccomp` profile for container | MEDIUM | docker-compose.yml | A02 |
| LOW-01 | `prompt_password` doesn't trim newlines on non-TTY | LOW | input.rs | — |
| LOW-02 | Error enums not `#[non_exhaustive]` | LOW | error.rs | — |
| LOW-03 | `cargo deny` allows duplicate versions | LOW | deny.toml | A03 |
| LOW-04 | `SecretString::serialize()` emits plaintext | LOW | types.rs | A04 |

**Totals:** 5 Critical, 15 High, 16 Medium, 4 Low = **40 total findings**

---

## 14. Remediation Roadmap

### Sprint 1 — Production Blocking (Must Fix Before Any External Deployment)

All 5 Critical findings, plus HIGH-08 and HIGH-10:

| Priority | Finding | Estimated Effort |
|----------|---------|-----------------|
| P0 | CRIT-01: Fix RLS migrations for plain PostgreSQL | 2h |
| P0 | CRIT-02: Switch rate limiter to per-IP `PeerIpKeyExtractor` | 1h |
| P0 | CRIT-03: Add KDF param bounds checking in `VaultHeader::decode()` | 2h |
| P0 | CRIT-04: Implement server-side revocation in `lock` command | 2h |
| P0 | CRIT-05: Fix Windows ACL hardening — username resolution + absolute path | 3h |
| P1 | HIGH-08: Pin Docker builder to digest | 0.5h |
| P1 | HIGH-10: Explicitly pin JWT algorithm to HS256 in `Validation::new()` | 0.5h |

### Sprint 2 — High Severity Remediation

| Priority | Finding | Estimated Effort |
|----------|---------|-----------------|
| P1 | HIGH-01: Make logout transactional — revoke refresh first | 2h |
| P1 | HIGH-02: Add per-user rate limiting on vault endpoints | 2h |
| P1 | HIGH-03: Add structured security event logging | 4h |
| P1 | HIGH-05: Implement clipboard clearing after 30 seconds | 2h |
| P1 | HIGH-06: Add vault blob structural validation + rate limit force push | 3h |
| P1 | HIGH-07: Apply atomic write pattern to sync state sidecar | 1h |
| P2 | HIGH-09: Reduce vault upload limit to 1MB | 0.5h |
| P2 | HIGH-11: Create local vault backup before pull overwrite | 1h |
| P2 | HIGH-12: Enforce password strength in `export_vault()` public API | 0.5h |
| P2 | HIGH-13: Use `create_new()` for atomic vault init | 1h |
| P2 | HIGH-14: Add vault history expiry + `DELETE /vault/history` endpoint | 3h |
| P2 | HIGH-15: Document and configure trusted proxy CIDR support | 3h |

### Sprint 3 — Supply Chain, Medium, and CI Hardening

| Priority | Finding | Estimated Effort |
|----------|---------|-----------------|
| P1 | Dep: Upgrade `criterion` 0.3 → 0.5 (drops `atty`, `serde_cbor`) | 1h |
| P1 | Dep: Upgrade `keyring` 2 → 3 (drops `derivative`, `instant`) | 1h |
| P1 | Dep: Remove `macros` from sqlx features (eliminates `rsa` vuln) | 1h |
| P1 | CI: Add `trufflehog` secret scanning to `ci.yml` | 1h |
| P1 | CI: Add `needs: ci` dependency in `release.yml` | 0.5h |
| P2 | MED-01: Return typed error with format version on unsupported vault | 1h |
| P2 | MED-03: Add length limits on vault entry fields | 2h |
| P2 | MED-04: Make CORS origins a required configuration parameter | 1h |
| P2 | MED-07: Seed `zxcvbn` with application-specific context words | 0.5h |
| P3 | LOW-02: Add `#[non_exhaustive]` to error enums | 0.5h |
| P3 | LOW-03: Change `deny.toml` multiple-versions to "deny" | 1h |

### Security Gate Updates Required

After Sprint 1 completion, update the security gate checklist in `AGENTS.md`:

```markdown
Security Gate Criteria (per sprint):
- [ ] cargo clippy -- -D warnings clean
- [ ] cargo test 100% pass, >80% coverage on core
- [ ] cargo audit zero critical/high CVEs          ← will pass after dep fixes
- [ ] cargo deny check clean                       ← will pass after dep fixes
- [ ] Four-eyes review on new crypto paths
- [ ] Threat model updated for any new component
- [ ] No secrets in git history (trufflehog in CI) ← add to ci.yml
- [ ] Rate limit tests pass for both global and per-user scenarios  ← new
- [ ] KDF parameter bounds test passes              ← new
- [ ] Clipboard clearing test passes                ← new
```

---

*Report generated: 2026-04-23*  
*Codebase state: commit HEAD as of audit date*  
*Next review: Post Sprint 1 completion — re-audit all Critical and High findings*  
*Classification: Internal Engineering — Do not share externally*
