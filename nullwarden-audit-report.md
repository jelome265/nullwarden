# NullWarden — Full Audit Report
## Security · Bugs · Missed Requirements · C4 Violations

> **Classification:** Internal Engineering — Audit Phase  
> **Auditor:** Senior Security Engineer + Architect  
> **Repo State:** As committed, documents 4–104  
> **DB Clarification:** Target platform is **Supabase** (PostgreSQL-compatible), not raw Postgres  
> **Date:** 2026-04-15  
> **Verdict:** ⛔ DO NOT SHIP — Multiple critical security failures, compilation-breaking bugs, and missing core features.

---

## Audit Methodology

Every source file was read and cross-referenced against:
1. Requirements from the README (FR1–FR14, NFR-S1–S12, NFR-P1–P5, NFR-R1–R4)
2. The security invariants defined in §8.2 of the project doc
3. The threat model defined in §8.3
4. C4 architectural principles (Context → Container → Component → Code separation)
5. The question: **"What happens if someone reverse-engineers this?"**

Findings are ordered: CRITICAL → HIGH → MEDIUM → LOW → MISSED → C4.

---

## CRITICAL — Fix Before Anything Else

### C-01 · COMPILATION FAILURE — Use-After-Move in `auth.rs` (CLI)
**File:** `crates/nullwarden-cli/src/client/auth.rs`  
**Severity:** CRITICAL — code does not compile

```rust
// BROKEN: username and password are String (owned), moved into first AuthRequest
self.http
    .post(".../auth/register")
    .json(&AuthRequest { username, password })  // ← both values MOVED here
    .send()...

// Second use is a compile error — E0382 use of moved value
.json(&AuthRequest { username, password })  // ← COMPILE ERROR
```

**Fix:** Clone before first use, or restructure:
```rust
pub async fn register(&self, username: String, password: String) -> anyhow::Result<()> {
    self.http
        .post(format!("{}/auth/register", self.base_url))
        .json(&AuthRequest { username: username.clone(), password: password.clone() })
        .send()
        .await
        .context("register request failed")?
        .error_for_status()
        .context("register response was not successful")?;
    // now username/password are still owned
    let login = self.http
        .post(format!("{}/auth/login", self.base_url))
        .json(&AuthRequest { username, password })
        ...
}
```

---

### C-02 · JWT REFRESH ISSUES A TOKEN FOR `UUID::NIL` — AUTH BYPASS
**File:** `crates/nullwarden-server/src/handlers/auth.rs`  
**Severity:** CRITICAL — any user can get a token for `00000000-0000-0000-0000-000000000000`

```rust
pub async fn refresh(...) -> Result<Json<AuthResponse>, StatusCode> {
    token::consume_refresh_token(&state, &payload.refresh_token)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    // BUG: issues access token for nil UUID, not the user who owns the refresh token
    let access_token = jwt::issue_access_token(&state, uuid::Uuid::nil())
```

The refresh token store (`HashSet<String>`) has **no mapping from refresh token → user ID**. There is no way to know which user a refresh token belongs to — the implementation is architecturally broken. A reverse engineer who obtains a refresh token from the plaintext session file gets a valid token for nil UUID, potentially matching a real user depending on insertion order.

**Fix:** Store refresh tokens as `HashMap<String, Uuid>` (token → user_id). Hash before storage (Argon2id as documented).

```rust
// db/pool.rs
pub refresh_tokens: RwLock<HashMap<String, Uuid>>,  // token_hash → user_id

// auth/token.rs
pub async fn issue_refresh_token(state: &SharedState, user_id: Uuid) -> String {
    let token = Uuid::new_v4().to_string();
    let hash = argon2_hash(&token);  // hash before storage
    state.refresh_tokens.write().await.insert(hash, user_id);
    token  // return plaintext to client only
}

pub async fn consume_refresh_token(state: &SharedState, token: &str) -> Option<Uuid> {
    // constant-time lookup against stored hashes
}
```

---

### C-03 · CONFLICT DETECTION NOT IMPLEMENTED — DATA LOSS ON SYNC
**Files:** `crates/nullwarden-server/src/handlers/vault.rs`, `crates/nullwarden-server/src/db/vaults.rs`, `crates/nullwarden-cli/src/commands/push.rs`  
**Severity:** CRITICAL — FR12 (MUST) entirely absent; silent data overwrite

The server's `put_vault` function blindly increments the version without checking the client's `expected_version`:

```rust
// vaults.rs — no expected_version parameter, no conflict check
pub async fn put_vault(state: &SharedState, user_id: Uuid, blob: Vec<u8>) -> StoredVault {
    let version = vaults.get(&user_id).map_or(1, |v| v.version + 1);
    // always succeeds — never returns 409
}
```

The client `push.rs` sends no `expected_version` at all:
```rust
// sync.rs — raw bytes only, no version negotiation
let mut request = self.http.put(format!("{}/vault", self.base_url)).body(bytes);
```

A reverse engineer can replay any push request to overwrite vault data with no rejection.

**Fix (server):** Accept `expected_version` in request header or JSON wrapper. Compare with stored version atomically. Return 409 if mismatch.

**Fix (client):** Track last-known server version in a local state file. Include in every push. Handle 409 with the conflict resolution flow (UC-07).

---

### C-04 · IN-MEMORY DATABASE — ALL DATA LOST ON SERVER RESTART
**File:** `crates/nullwarden-server/src/db/pool.rs`  
**Severity:** CRITICAL — no persistence whatsoever; Supabase not integrated

```rust
pub struct AppState {
    pub users: RwLock<HashMap<String, StoredUser>>,    // ← in-memory only
    pub refresh_tokens: RwLock<HashSet<String>>,       // ← in-memory only
    pub vaults: RwLock<HashMap<Uuid, StoredVault>>,    // ← in-memory only
}
```

The SQL migration files exist but are **never executed**. `sqlx` is a dependency but is **never used anywhere in the server code**. There is **zero Supabase integration**. This means:
- Every server restart wipes all user accounts
- Every server restart wipes all vaults
- Supabase RLS policies cannot protect data that never reaches it

A reverse engineer who restarts the process achieves full data erasure.

**Fix:** Replace `AppState` in-memory maps with `sqlx::PgPool` connected to Supabase. Run migrations on startup. All reads/writes go through sqlx queries.

```toml
# Cargo.toml — already present but unused
sqlx = { version = "0.7", features = ["postgres", "runtime-tokio-rustls", "uuid"] }
```

```rust
// db/pool.rs — actual implementation needed
pub struct AppState {
    pub db: sqlx::PgPool,
    pub config: Config,
}
```

---

### C-05 · REFRESH TOKENS STORED AS PLAINTEXT IN MEMORY
**File:** `crates/nullwarden-server/src/auth/token.rs`  
**Severity:** CRITICAL — violates documented security design

The design docs explicitly state: *"Refresh token stored as Argon2id hash in DB."*  
The implementation stores raw plaintext tokens in a `HashSet<String>` in RAM.

A process memory dump exposes all active refresh tokens. A reverse engineer with heap inspection capability can enumerate all valid sessions.

**Fix:** Hash tokens with Argon2id before storage. Use constant-time comparison on retrieval. Store in Supabase with expiry.

---

### C-06 · JWT SECRET EXPOSED — NO TLS — SERVER BINDS PLAIN HTTP
**File:** `crates/nullwarden-server/src/main.rs`  
**Severity:** CRITICAL — NFR-S8 (TLS 1.3 only) not implemented; JWT sent in clear

```rust
let listener = TcpListener::bind(addr).await?;
axum::serve(listener, app).await?;
```

There is no TLS configuration anywhere. All JWTs, vault blobs, and credentials travel in plaintext HTTP. A passive network observer has full access to all traffic. This violates the project's own threat model entry:

> *"Passive network observer | Full traffic capture → TLS 1.3; only ciphertext in transit"*

Additionally, `config.tls_cert_path` and `tls_key_path` are parsed from env but never used.

**Fix (Supabase deployment):** Serve the API behind Supabase's edge or a TLS-terminating proxy (Caddy/nginx/Traefik). At minimum, use `axum-server` with `rustls` for native TLS:

```rust
use axum_server::tls_rustls::RustlsConfig;

let config = RustlsConfig::from_pem_file(cert_path, key_path).await?;
axum_server::bind_rustls(addr, config)
    .serve(app.into_make_service())
    .await?;
```

---

### C-07 · ACCESS TOKENS STORED AS PLAINTEXT FILE — TOKEN THEFT TRIVIAL
**File:** `crates/nullwarden-cli/src/session.rs`  
**Severity:** CRITICAL — NFR-S11 violation; reverse engineering target #1

```rust
pub fn save_access_token(token: &str) -> anyhow::Result<()> {
    fs::write(path, token).context("failed to save access token")
}
// path = ~/.local/share/nullwarden/session.token
```

The JWT access token is written unencrypted to a predictable filesystem path. Any process running as the same user can read it. A reverse engineer targets this file first — it grants immediate authenticated API access without knowing the password.

**Fix (Minimum):** Use the OS keyring (`keyring` crate — wraps Secret Service on Linux, Keychain on macOS, Credential Manager on Windows). No token should ever touch the filesystem as plaintext.

```rust
// session.rs — production implementation
use keyring::Entry;

pub fn save_access_token(token: &str) -> anyhow::Result<()> {
    let entry = Entry::new("nullwarden", "access_token")?;
    entry.set_password(token)?;
    Ok(())
}
```

**Fix (Minimum fallback for headless):** Encrypt the token file with a key derived from a machine-specific secret (e.g., TPM or `/etc/machine-id` + HKDF).

---

### C-08 · VAULT ENTRY PASSWORD FIELD IS PLAIN `String` — NOT ZEROIZED
**File:** `crates/nullwarden-core/src/vault/data.rs`  
**Severity:** CRITICAL — NFR-S5 (Zeroize all sensitive types) violated

```rust
pub struct VaultEntry {
    pub id: Uuid,
    pub title: String,
    pub username: String,
    pub password: String,    // ← plain String, NOT zeroized on drop
    pub notes: Option<String>,
}
```

`VaultData` also derives `Clone`, meaning copies of `VaultEntry` (including plaintext passwords) can be left scattered through the heap without being zeroized.

A memory dump of the process after vault operations will contain plaintext passwords.

**Fix:**
```rust
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::types::SecretString;

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultEntry {
    pub id: Uuid,
    pub title: String,
    pub username: String,
    pub password: SecretString,         // ← wraps String, zeroized on drop
    pub notes: Option<String>,
    pub totp: Option<SecretString>,
}
// Remove Clone from VaultEntry. If cloning is needed, make it explicit and controlled.
```

Note: `SecretString` must not implement `Clone` without explicit intent. The serialization must handle the inner `String` for rmp-serde while zeroizing after use.

---

### C-09 · PASSWORD PRINTED TO STDOUT — NO CLIPBOARD
**File:** `crates/nullwarden-cli/src/commands/get.rs`  
**Severity:** CRITICAL — security design explicitly requires clipboard with 30s clear

```rust
pub async fn run(title: String) -> anyhow::Result<()> {
    ...
    println!("password: {}", entry.password);  // ← printed to terminal, shell history risk
```

Passwords printed to stdout appear in terminal scrollback, may be captured by terminal loggers, and can appear in shell history if piped. UC-04 requires: "Password copied to clipboard (cleared after 30 s) or printed to stdout per `--print` flag."

**Fix:**
```rust
use arboard::Clipboard;  // or 'cli-clipboard' crate

// Default: clipboard
let mut cb = Clipboard::new()?;
cb.set_text(entry.password.0.clone())?;
println!("Password copied to clipboard (clears in 30s)");
tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(30)).await;
    if let Ok(mut cb) = Clipboard::new() {
        let _ = cb.set_text(String::new());
    }
});

// --print flag: explicit user opt-in only
if print_flag {
    println!("password: {}", entry.password.0);
}
```

---

## HIGH — Fix Before Beta

### H-01 · RATE LIMITING IS A PLACEHOLDER — NEVER APPLIED
**File:** `crates/nullwarden-server/src/middleware/rate_limit.rs`  
**Severity:** HIGH — NFR-S10 (rate limiting) violated; brute force fully open

```rust
// rate_limit.rs
pub fn placeholder() {}
```

`tower_governor` is in `Cargo.toml` but never configured or applied to any route. The `/auth/login` endpoint accepts unlimited requests. A reverse engineer with an offline dictionary can enumerate any account without throttling.

**Fix:** Apply `GovernorLayer` to auth routes in `app.rs`:
```rust
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};

let governor_conf = Arc::new(
    GovernorConfigBuilder::default()
        .per_second(state.config.rate_limit_auth_requests as u64)
        .burst_size(state.config.rate_limit_auth_requests)
        .finish()
        .unwrap(),
);

Router::new()
    .route("/auth/login", post(auth::login).layer(GovernorLayer { config: governor_conf }))
    .route("/auth/register", post(auth::register).layer(...))
```

---

### H-02 · NO SECURITY HEADERS ON ANY RESPONSE
**File:** `crates/nullwarden-server/src/app.rs`  
**Severity:** HIGH — all documented response headers absent

The README documents these required headers on all responses:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'none'
```

None are set. Any future web interface is vulnerable to clickjacking, MIME sniffing, and protocol downgrade.

**Fix:** Add `tower-http`'s `SetResponseHeadersLayer` or a custom middleware:
```rust
use tower_http::set_header::SetResponseHeaderLayer;
use axum::http::{header, HeaderValue};

Router::new()
    .layer(SetResponseHeaderLayer::if_not_present(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    ))
    .layer(SetResponseHeaderLayer::if_not_present(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    ))
    // ... etc.
```

---

### H-03 · LOGOUT ACCEPTS REFRESH TOKEN, NOT ACCESS TOKEN
**File:** `crates/nullwarden-server/src/handlers/auth.rs`  
**Severity:** HIGH — access tokens cannot be revoked; no blocklist exists

```rust
// logout handler takes RefreshRequest (refresh_token field)
pub async fn logout(
    State(state): State<SharedState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<StatusCode, StatusCode> {
    token::revoke_refresh_token(&state, &payload.refresh_token).await;
    Ok(StatusCode::NO_CONTENT)
}
```

The documented design says: *"Revoked token added to server-side blocklist. Subsequent requests with revoked token → 401."*

The current implementation:
1. Only revokes the refresh token, not the access token
2. Has no access token blocklist — issued access tokens remain valid until expiry (15 min) after logout
3. The `AUTHORIZATION` header is not even read in the logout handler

A reverse engineer who captures a JWT access token has a guaranteed 15-minute window even after the user logs out.

**Fix:** Read the Bearer token from the Authorization header, add it to a Redis/Supabase-backed blocklist, check blocklist on every authenticated request.

---

### H-04 · `CI.YML` MISSING `CARGO AUDIT` AND `CARGO DENY`
**File:** `.github/workflows/ci.yml`  
**Severity:** HIGH — dependency vulnerabilities will never be caught in CI

```yaml
# Current CI — no audit
jobs:
  rust:
    steps:
      - run: cargo fmt --all -- --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace
      # Missing: cargo audit, cargo deny, coverage gate, benchmark gate
```

**Fix:**
```yaml
      - name: Install cargo-audit
        run: cargo install cargo-audit --locked
      - name: Audit dependencies
        run: cargo audit
      - name: Install cargo-deny
        run: cargo install cargo-deny --locked
      - name: Deny policy check
        run: cargo deny check
      - name: Install cargo-tarpaulin
        run: cargo install cargo-tarpaulin --locked
      - name: Coverage gate
        run: cargo tarpaulin -p nullwarden-core --fail-under 80
```

---

### H-05 · `DENY.TOML` MISSING ADVISORIES AND BANS SECTIONS
**File:** `deny.toml`  
**Severity:** HIGH — `cargo deny` will not check CVEs with current config

```toml
# Current — only license check
[licenses]
allow = ["MIT", "Apache-2.0", "BSD-3-Clause", "Unicode-DFS-2016"]
```

**Fix:**
```toml
[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"
notice = "warn"

[licenses]
allow = ["MIT", "Apache-2.0", "BSD-3-Clause", "Unicode-DFS-2016"]
unlicensed = "deny"
copyleft = "warn"

[bans]
multiple-versions = "warn"
wildcards = "deny"
highlight = "all"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

---

### H-06 · PASSWORD STRENGTH THRESHOLD TOO LOW
**File:** `crates/nullwarden-cli/src/input.rs`  
**Severity:** HIGH — allows weak passwords that are trivially offline-crackable

```rust
if estimate.score() < 2 {  // ← allows score=2 ("Fair")
    bail!("password is too weak");
}
```

The design doc explicitly requires **zxcvbn score ≥ 3**. Score 2 corresponds to "Fair" passwords such as `password1!` which are in most wordlists.

**Fix:**
```rust
if estimate.score() < 3 {
    bail!("password is too weak (score: {}/4). Use a longer, more complex passphrase.", estimate.score());
}
```

---

### H-07 · `CONFIG.RS` JWT SECRET IS PLAIN `String` — NOT ZEROIZED
**File:** `crates/nullwarden-server/src/config.rs`  
**Severity:** HIGH — the signing key exists in memory as plaintext for process lifetime

```rust
pub struct Config {
    pub jwt_secret: String,   // ← never zeroized
    ...
}
```

If the process dumps core or is inspected via `/proc/<pid>/mem`, the JWT signing key is recoverable. Combined with the in-memory token store, this enables complete session forgery.

**Fix:** Wrap in `SecretString` with `ZeroizeOnDrop`. The `jsonwebtoken` crate can accept `&[u8]` so extract the bytes immediately and drop the `String`.

---

### H-08 · CROSS-COMPILATION AND RELEASE SIGNING NOT IMPLEMENTED
**File:** `.github/workflows/release.yml`, `scripts/sign-release.sh`  
**Severity:** HIGH — D10 (signed binaries) is a deliverable; supply chain attack surface

```yaml
# release.yml — only linux default target
- run: cargo build --workspace --release
```

```sh
# sign-release.sh
echo "Signing hook placeholder"
```

The `.cargo/config.toml` only has `target-dir = "target"`. Cross-compilation targets and signing are completely absent. Users downloading unsigned binaries have no way to verify integrity.

**Fix (`.cargo/config.toml`):**
```toml
[build]
target-dir = "target"

[target.x86_64-unknown-linux-musl]
linker = "x86_64-linux-musl-gcc"

[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
```

**Fix (release.yml):**
```yaml
strategy:
  matrix:
    target: [x86_64-unknown-linux-musl, x86_64-pc-windows-gnu]
steps:
  - run: rustup target add ${{ matrix.target }}
  - run: cargo build --release -p nullwarden-cli --target ${{ matrix.target }}
  - name: Sign with minisign
    run: |
      echo "$MINISIGN_SECRET_KEY" | minisign -S -s /dev/stdin \
        -m target/${{ matrix.target }}/release/nullwarden-cli \
        -x target/${{ matrix.target }}/release/nullwarden-cli.minisig
```

---

## MEDIUM — Fix Before Any User Testing

### M-01 · `LOCK.RS` IS A STUB — KEY ZEROIZATION NOT IMPLEMENTED
**File:** `crates/nullwarden-cli/src/commands/lock.rs`  
**Severity:** MEDIUM — FR13 (MUST) missing

```rust
pub async fn run() -> anyhow::Result<()> {
    println!("Vault lock is client-side only in the current prototype; ...");
    Ok(())
}
```

The unlock/lock lifecycle described in the state diagram (UNLOCKED → LOCKED) does not exist. Each CLI command independently unlocks the vault from disk. There is no in-process state. While this means keys don't persist between commands (good), the lock command is semantically meaningless.

**Required:** Either (a) implement a daemon with session state that can be locked, or (b) document explicitly that the CLI model is "lock by exit" and the lock command is informational. Update the state diagram to match reality.

---

### M-02 · FUZZ TARGETS ARE EMPTY STUBS
**Files:** `crates/nullwarden-fuzz/fuzz_targets/decrypt_input.rs`, `vault_deserialize.rs`  
**Severity:** MEDIUM — FZ-01, FZ-02 not implemented; parser bugs will not be found

```rust
fn main() {}
```

No actual fuzzing infrastructure. The scheduled fuzz workflow is also broken as a result.

**Fix:**
```rust
// decrypt_input.rs — using cargo-fuzz (libFuzzer)
#![no_main]
use libfuzzer_sys::fuzz_target;
use nullwarden_core::crypto::decrypt;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 { return; }
    let key: [u8; 32] = data[..32].try_into().unwrap();
    let rest = &data[32..];
    if rest.len() < 24 { return; }
    let nonce: [u8; 24] = rest[..24].try_into().unwrap();
    let ct = &rest[24..];
    // Must never panic — only return Err
    let _ = decrypt(&key, &nonce, ct);
});
```

Add to `Cargo.toml` fuzz crate:
```toml
[[bin]]
name = "decrypt_input"
path = "fuzz_targets/decrypt_input.rs"
test = false
doc = false
```

---

### M-03 · BENCHMARKS ARE EMPTY STUBS — KDF GATE CANNOT FIRE
**Files:** `crates/nullwarden-core/benches/kdf_bench.rs`, `encrypt_bench.rs`  
**Severity:** MEDIUM — NFR-P1 (≥ 300 ms KDF gate) cannot be enforced; params could silently weaken

```rust
fn main() {}
```

**Fix:**
```rust
// kdf_bench.rs — using criterion
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nullwarden_core::kdf::{derive_key, generate_salt, KdfParams};
use std::time::Duration;

fn bench_argon2id(c: &mut Criterion) {
    let salt = generate_salt();
    let params = KdfParams::default();
    c.bench_function("argon2id_derive_key", |b| {
        b.iter(|| {
            derive_key(black_box(b"test_master_password"), &salt, params).unwrap()
        })
    });
}

fn check_minimum_latency() {
    let salt = generate_salt();
    let params = KdfParams::default();
    let start = std::time::Instant::now();
    derive_key(b"password", &salt, params).unwrap();
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_millis(300),
        "KDF too fast: {:?}. Argon2 params must produce >= 300ms latency.", elapsed);
}

criterion_group!(benches, bench_argon2id);
criterion_main!(benches);
```

Add `criterion` to dev-dependencies and add `[[bench]]` entry in `Cargo.toml`.

---

### M-04 · ZEROIZE TEST DOESN'T VERIFY ZEROIZATION
**File:** `crates/nullwarden-core/tests/zeroize.rs`  
**Severity:** MEDIUM — the test named "zeroize" tests nothing about zeroization

```rust
#[test]
fn vault_key_wraps_32_bytes() {
    let key = VaultKey([0_u8; 32]);
    assert_eq!(key.as_ref().len(), 32);  // ← just a length check
}
```

This provides zero assurance that memory is actually zeroed on drop.

**Fix:**
```rust
#[test]
fn vault_key_zeroizes_on_drop() {
    let raw_ptr: *const u8;
    let expected_zero = [0u8; 32];
    {
        let key = VaultKey([0xAB_u8; 32]);
        raw_ptr = key.0.as_ptr();
        // Verify non-zero before drop
        unsafe { assert_ne!(&*std::ptr::slice_from_raw_parts(raw_ptr, 32), &expected_zero); }
    } // key dropped here — Zeroize must run
    unsafe {
        let post_drop = std::slice::from_raw_parts(raw_ptr, 32);
        assert_eq!(post_drop, &expected_zero,
            "VaultKey was NOT zeroized on drop — memory safety failure");
    }
}
```

This test must be `#[cfg(test)]` only and annotated with a comment explaining the unsafe is intentional for verification.

---

### M-05 · REQUEST ID MIDDLEWARE IS A PLACEHOLDER
**File:** `crates/nullwarden-server/src/middleware/request_id.rs`  
**Severity:** MEDIUM — traceability and incident response impossible without request IDs

```rust
pub fn placeholder() {}
```

**Fix:** Use `tower-http`'s built-in `RequestIdLayer`:
```rust
use tower_http::request_id::{MakeRequestUuid, SetRequestIdLayer};
use axum::http::header::HeaderName;

let x_request_id = HeaderName::from_static("x-request-id");
Router::new()
    ...
    .layer(SetRequestIdLayer::new(x_request_id.clone(), MakeRequestUuid))
    .layer(PropagateRequestIdLayer::new(x_request_id))
```

---

### M-06 · ADR DOCS ARE ONE-LINE PLACEHOLDERS
**Files:** `docs/adr/*.md`  
**Severity:** MEDIUM — rationale for crypto choices not documented; future engineers will regress them

```markdown
# ADR-001
XChaCha20-Poly1305 is used for vault encryption.
```

Each ADR needs: Context, Decision, Consequences, Alternatives Considered, Security Implications. The README already has this content — it just needs to be moved into the ADR files.

---

### M-07 · `OPENAPI` SPEC IS MISSING ALL ENDPOINTS
**File:** `docs/api-reference.yaml`  
**Severity:** MEDIUM — D9 (OpenAPI 3.1 spec) is a deliverable; only `/health` exists

```yaml
paths:
  /health:
    get:
      responses:
        "200":
          description: OK
```

The full API (`/auth/register`, `/auth/login`, `/auth/refresh`, `/auth/logout`, `/vault GET`, `/vault PUT`) is absent. Clients cannot generate typed SDKs and API consumers have no contract.

---

## LOW — Polish Before Release

### L-01 · VAULT AUTH CLIENT REGISTERS BUT DOES NOT SAVE REFRESH TOKEN
**File:** `crates/nullwarden-cli/src/client/auth.rs`  
```rust
let _ = login.refresh_token;  // ← silently discarded
```
The refresh token is received and immediately thrown away. Token refresh (FR3) is unimplementable from the CLI.

### L-02 · `VAULT.RS` CLIENT GET EXPOSES `entry.password` WITHOUT `SecretString`
Until C-08 is fixed, `println!("password: {}", entry.password)` means the password field is `Display`-able anywhere. After C-08 is fixed, this becomes a type error, which is the correct outcome.

### L-03 · `config.rs` SERVER — ALL FIELDS ARE MANDATORY WITH NO DEFAULTS
If any env var is missing, `envy::from_env()` returns an error and the server panics at startup with a confusing error message. Add `#[serde(default)]` with sensible defaults and validate on startup with a clear error.

### L-04 · `docker-compose.yml` USES `.env.example` — CREDENTIALS IN VCS
```yaml
env_file:
  - .env.example
```
`.env.example` contains `password=password`. For development this is acceptable but it must be documented that this file should never be used in production and a separate `.env` (gitignored) is required.

### L-05 · MIGRATION FILES IN `src/migrations/` — SHOULD BE AT WORKSPACE ROOT
The SQLx convention for migrations is a `migrations/` directory at the crate root (or configured via `SQLX_OFFLINE`). Placing them under `src/` is non-standard and will break `sqlx migrate run`.

---

## MISSED REQUIREMENTS — FR/NFR NOT IMPLEMENTED

| Requirement | Status | Evidence |
|-------------|--------|----------|
| FR3 Token Refresh | ❌ BROKEN | Refresh issues token for nil UUID (C-02) |
| FR4 Logout | ❌ BROKEN | No access token revocation (H-03) |
| FR10 Push with conflict detection | ❌ MISSING | No expected_version in protocol (C-03) |
| FR12 Conflict detection | ❌ MISSING | Server never returns 409 (C-03) |
| FR13 Vault lock | ❌ STUB | lock.rs is a no-op (M-01) |
| FR14 Secure clipboard output | ❌ MISSING | Passwords printed to stdout (C-09) |
| NFR-S2 Argon2 param gate ≥ 300ms | ❌ NO CI GATE | Bench stubs (M-03) |
| NFR-S4 Nonce uniqueness (fuzz) | ❌ NO FUZZ | Fuzz stubs (M-02) |
| NFR-S5 Zeroize all sensitive types | ❌ PARTIAL | password: String in VaultEntry (C-08) |
| NFR-S6 No plaintext in DB | ❌ NO DB | In-memory only (C-04) |
| NFR-S7 Constant-time comparisons | ❌ NOT VERIFIED | constant_time_eq dep present but login uses normal comparison for username lookup |
| NFR-S8 TLS 1.3 only | ❌ MISSING | Plain HTTP (C-06) |
| NFR-S10 Rate limiting | ❌ MISSING | Tower-governor unused (H-01) |
| NFR-S12 Dependency audit in CI | ❌ MISSING | cargo audit absent from ci.yml (H-04) |
| NFR-P1 KDF latency gate | ❌ NO BENCHMARK | Bench stubs (M-03) |
| NFR-R1 Atomic writes | ✅ IMPLEMENTED | `atomic_write()` in store.rs |
| NFR-R2 Integrity check | ✅ IMPLEMENTED | AEAD tag failure propagates |
| NFR-PO1 Linux musl binary | ❌ MISSING | No cross-compile config (H-08) |
| NFR-PO2 Windows binary | ❌ MISSING | No cross-compile config (H-08) |
| D9 OpenAPI 3.1 spec | ❌ INCOMPLETE | Only /health exists (M-07) |
| D10 Signed binaries | ❌ MISSING | sign-release.sh is a placeholder (H-08) |
| D13 SBOM | ❌ MISSING | No cargo sbom generation |
| Supabase integration | ❌ NOT STARTED | All in-memory (C-04) |

---

## REVERSE ENGINEERING THREAT ANALYSIS

**"What if someone reverse-engineers this?"**

The following attack paths are currently viable with zero effort:

| Attack | Entry Point | Current Exploitability |
|--------|------------|------------------------|
| **Session hijack** | Read `~/.local/share/nullwarden/session.token` — plaintext JWT | Trivial — file readable by same-user processes (C-07) |
| **Token forgery** | Steal `JWT_SECRET` from env dump + in-memory process inspection | Trivial — no protection on secret (H-07) |
| **Account takeover via refresh abuse** | Obtain any valid refresh token → get token for nil UUID | Trivial — nil UUID auth bypass (C-02) |
| **Full DB wipe** | Restart server process | Trivial — in-memory only (C-04) |
| **Vault overwrite (no conflict)** | Send PUT /vault repeatedly | Trivial — no version checking (C-03) |
| **Brute force credentials** | Unlimited login attempts | Trivial — rate limiter never applied (H-01) |
| **Vault format identification** | Look for magic bytes `NWDN` at offset 0 | Trivial — documented and static |
| **Plaintext password recovery** | Memory dump of running `nullwarden-cli` | Medium effort — `password: String` not zeroized (C-08) |
| **Traffic interception** | Passive sniff on network interface | Trivial — plain HTTP (C-06) |
| **Credential extraction from RAM** | Dump process heap after vault unlock | Medium effort — access tokens, refresh tokens in clear RAM |

The vault file itself (`vault.nw`) is the only part of the system that is actually secure as designed: XChaCha20-Poly1305 is correctly implemented in `crypto.rs`, Argon2id KDF is correctly implemented in `kdf.rs`, the header format is correct, and atomic writes work. **The cryptographic core is sound. Everything around it is not.**

---

## C4 ARCHITECTURE VIOLATIONS

The codebase was evaluated against C4 model principles: Context, Container, Component, Code separation. The following structural violations were found.

### C4-V1 · `AppState` VIOLATES SINGLE RESPONSIBILITY — GOD OBJECT
**File:** `crates/nullwarden-server/src/db/pool.rs`

```rust
pub struct AppState {
    pub config: Config,          // ← configuration domain
    pub users: RwLock<...>,      // ← auth domain
    pub refresh_tokens: RwLock<...>, // ← session domain
    pub vaults: RwLock<...>,     // ← vault domain
}
```

All four domains are fused into one shared state object. Every handler receives the entire application state regardless of what it needs. A vault handler should not have access to the user authentication store.

**C4 Fix (Component separation):**
```
Container: nullwarden-server
├── Component: AuthService
│   ├── UserRepository (users table)
│   └── SessionRepository (refresh_tokens table)
├── Component: VaultService
│   └── VaultRepository (vaults table)
└── Component: ConfigService
```

```rust
// Distinct state types per component
pub struct AuthState { pub db: PgPool, pub config: AuthConfig }
pub struct VaultState { pub db: PgPool }

// Handlers receive only what they need
async fn login(State(state): State<Arc<AuthState>>, ...) {}
async fn put_vault(State(state): State<Arc<VaultState>>, ...) {}
```

### C4-V2 · HANDLERS DIRECTLY CALL DB LAYER — NO SERVICE LAYER
**Files:** `handlers/auth.rs`, `handlers/vault.rs`

The handlers directly call `db::users::find_user`, `db::vaults::put_vault`, etc. There is no service/domain layer between HTTP concerns and data access concerns. This means:
- Business logic (auth rules, conflict resolution) is entangled with HTTP parsing
- The db layer is not independently testable without spinning up HTTP
- When switching from in-memory to Supabase, handlers must be rewritten

**C4 Fix (Component boundary):**
```
handlers/ (HTTP adapter — deserialize request, serialize response)
   ↓ calls
services/ (domain logic — auth rules, conflict detection, version management)
   ↓ calls
repositories/ (data access — SQL queries, Supabase client)
```

### C4-V3 · `crypto.rs` AND `kdf.rs` ARE FLAT — NO DOMAIN BOUNDARY
**Files:** `crates/nullwarden-core/src/crypto.rs`, `kdf.rs`

The public API of `nullwarden-core` exposes raw `[u8; 32]` keys directly. There is no type-safe barrier preventing a caller from passing the wrong bytes as a key, or using a KDF output in a different context than intended.

**C4 Fix (Code level — newtype pattern):**
```rust
// types.rs — domain types that cannot be confused
pub struct VaultEncryptionKey(pub(crate) [u8; 32]);  // derived from Argon2id only
pub struct VaultNonce(pub(crate) [u8; 24]);           // CSPRNG only

// crypto.rs — only accepts domain types, not raw bytes
pub fn encrypt(key: &VaultEncryptionKey, plaintext: &[u8]) 
    -> Result<(VaultNonce, Vec<u8>), VaultError> { ... }

// kdf.rs — only produces VaultEncryptionKey, not [u8; 32]
pub fn derive_key(password: &[u8], salt: &[u8; SALT_LEN], params: KdfParams) 
    -> Result<VaultEncryptionKey, VaultError> { ... }
```

This makes misuse a compile error rather than a runtime bug.

### C4-V4 · `VaultStore` HANDLES BOTH FILE I/O AND CRYPTOGRAPHY — MIXED CONCERNS
**File:** `crates/nullwarden-core/src/vault/store.rs`

`VaultStore::save()` calls KDF derivation, calls encryption, serializes data, and performs atomic file writes — all in a 40-line function. These are four distinct responsibilities that cannot be independently tested.

**C4 Fix:**
```
VaultStore (file I/O, atomic write, path management)
VaultSerializer (MessagePack encode/decode)
VaultCipher (encrypt/decrypt using VaultEncryptionKey)
VaultKeyDeriver (Argon2id wrapper)
```

Each should be independently testable and injectable as traits for mocking in tests.

### C4-V5 · CLI COMMANDS ACCESS `VaultStore` DIRECTLY — NO CLI ADAPTER LAYER
The CLI commands import and use `nullwarden_core::vault::VaultStore` directly. There is no application service layer between the CLI argument parser and the core library. This means:
- CLI argument parsing logic is entangled with vault business logic in `add.rs`, `get.rs`, etc.
- Switching from file-based storage to encrypted SQLite would require rewriting all commands
- Integration tests cannot mock the vault store

**C4 Fix:** Introduce a `VaultManager` trait at the application boundary:
```rust
// cli/vault_manager.rs
pub trait VaultManager {
    fn add_entry(&self, master_pwd: &str, entry: NewEntry) -> Result<()>;
    fn get_entry(&self, master_pwd: &str, title: &str) -> Result<VaultEntry>;
    fn list_entries(&self, master_pwd: &str) -> Result<Vec<EntryMetadata>>;
}

// cli/commands/add.rs — depends on trait, not concrete type
pub async fn run(manager: &dyn VaultManager, title: String, ...) -> anyhow::Result<()> {
    let master = prompt_password("Master password")?;
    manager.add_entry(&master, NewEntry { title, ... })?;
}
```

---

## SUPABASE MIGRATION PATH

Since the database is Supabase (not raw Postgres), the following changes are required:

### 1. Replace `sqlx::PgPool` with Supabase PostgREST client or keep `sqlx` pointed at Supabase's connection string

Supabase exposes a standard Postgres wire protocol. `sqlx` works as-is with:
```
DATABASE_URL=postgresql://postgres:[password]@db.[project-ref].supabase.co:5432/postgres
```

### 2. Enable Row Level Security (RLS) on all tables

```sql
-- users table
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- vaults table — users can only see their own vault
CREATE POLICY "Users can only access own vault"
ON vaults FOR ALL
USING (auth.uid() = owner_id);

-- This requires Supabase Auth integration. If using JWT from nullwarden-server,
-- configure Supabase to accept custom JWTs:
-- Settings → API → JWT Secret → set to same JWT_SECRET as server
```

### 3. Migration files must use `sqlx migrate` format

```
crates/nullwarden-server/
└── migrations/           ← move from src/migrations/
    ├── 20260101000000_create_users.sql
    ├── 20260101000001_create_vaults.sql
    └── 20260101000002_create_refresh_tokens.sql
```

### 4. Add migration runner to server startup

```rust
// main.rs
sqlx::migrate!("./migrations")
    .run(&pool)
    .await
    .context("Failed to run database migrations")?;
```

### 5. Add `SUPABASE_URL` and `SUPABASE_ANON_KEY` to `.env.example`

```bash
# .env.example additions
SUPABASE_URL=https://[project-ref].supabase.co
DATABASE_URL=postgresql://postgres:[password]@db.[project-ref].supabase.co:5432/postgres
```

---

## REMEDIATION PRIORITY ORDER

```
IMMEDIATE (blocks everything):
  C-01  Fix compilation error in auth.rs
  C-04  Implement Supabase connection and real persistence

SECURITY CRITICAL (before any network exposure):
  C-02  Fix JWT refresh → user mapping
  C-03  Implement conflict detection (client + server)
  C-05  Hash refresh tokens before storage
  C-06  Enforce TLS (even via reverse proxy)
  C-07  Use OS keyring for token storage
  C-08  Zeroize VaultEntry.password
  C-09  Implement clipboard with 30s clear

HIGH (before any user testing):
  H-01  Apply rate limiting to auth routes
  H-02  Add security response headers
  H-03  Implement proper logout with access token blocklist
  H-04  Add cargo audit + cargo deny to CI
  H-05  Fix deny.toml
  H-06  Raise password strength threshold to score ≥ 3
  H-07  Zeroize JWT secret in Config
  H-08  Implement cross-compilation + release signing

MEDIUM (before any beta release):
  M-01  Document or implement lock command
  M-02  Implement fuzz harnesses
  M-03  Implement criterion benchmarks with KDF gate
  M-04  Fix zeroize test to actually verify memory
  M-05  Implement request ID middleware
  M-06  Expand ADR documentation
  M-07  Complete OpenAPI spec

C4 ARCHITECTURE (before scaling work):
  C4-V1  Split AppState into per-component state
  C4-V2  Add service layer between handlers and repositories
  C4-V3  Use newtypes for cryptographic key material
  C4-V4  Split VaultStore concerns into distinct types
  C4-V5  Add VaultManager trait for CLI decoupling
```

---

## WHAT PASSES

The following is correctly implemented and should not be changed:

| Component | Assessment |
|-----------|-----------|
| `crypto.rs` — XChaCha20-Poly1305 | ✅ Correct AEAD usage, CSPRNG nonce |
| `kdf.rs` — Argon2id | ✅ Correct params, correct output length |
| `vault/header.rs` — binary format | ✅ Magic, version, params, salt, nonce — correct layout |
| `vault/store.rs` — atomic write | ✅ write-tmp → rename pattern correctly implemented |
| `vault/key.rs` — VaultKey | ✅ Zeroize + ZeroizeOnDrop correct |
| `types.rs` — SecretString/SecretBytes | ✅ Zeroize correct |
| `tests/vault_lifecycle.rs` | ✅ Tests the full init/add/unlock/delete cycle |
| `tests/crypto_roundtrip.rs` | ✅ Correct encrypt/decrypt test |
| Workspace structure | ✅ Clean crate separation (core, cli, server, fuzz) |
| `Cargo.lock` committed | ✅ Deterministic builds |
| `rust-toolchain.toml` | ✅ Pinned toolchain |

**Bottom line:** The cryptographic core is correct. The vault file format is correct. Atomic writes work. Everything that interacts with the network, the OS, or the user is either broken, insecure, or missing.

---

*NullWarden Audit Report v1.0*  
*Generated: 2026-04-15*  
*Next action: Address C-01 through C-09 before any further development*
