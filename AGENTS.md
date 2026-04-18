# NullWarden Agent Guidelines

## Workspace Structure
- Rust workspace with 4 crates: `core`, `cli`, `server`, `fuzz`
- Core cryptographic library: `crates/nullwarden-core`
- CLI application: `crates/nullwarden-cli` 
- REST API server: `crates/nullwarden-server`
- Fuzz testing: `crates/nullwarden-fuzz`

## Key Commands
- Build all: `cargo build --workspace`
- Run tests: `cargo test --workspace`
- Run CLI: `cargo run --bin nullwarden-cli -- <command>`
- Run server: `cargo run --bin nullwarden-server`
- Security audit: `cargo audit`
- Code formatting: `cargo fmt --all -- --check`
- Linting: `cargo clippy --workspace --all-targets -- -D warnings`
- Dependency check: `cargo deny check`
- Fuzz build: `cargo build -p nullwarden-fuzz`
- Coverage: `cargo tarpaulin -p nullwarden-core --fail-under 80`

## Development Workflow
1. Security gates must pass before merging to main:
   - `cargo clippy -- -D warnings` clean
   - `cargo test` 100% pass, >80% coverage on core
   - `cargo audit` zero critical/high CVEs
   - `cargo deny check` clean
   - Four-eyes review on new crypto paths
   - No secrets in git history (git-secrets/trufflehog)

2. Branch strategy:
   - `main`: protected, release-tagged
   - `develop`: integration branch
   - `feature/*`: per-story branches
   - `hotfix/*`: critical bug patches
   - `security/*`: security fix branches

## Cryptographic Requirements (CRITICAL)
- KDF: Argon2id with m=65536, t=3, p=4 (≥300ms on reference hardware)
- Encryption: XChaCha20-Poly1305 with unique 192-bit nonce per operation
- Key derivation: Client-only from master password (server never sees keys)
- Memory safety: All sensitive types must implement Zeroize and be zeroized immediately
- Auth separation: Server auth tokens independent of vault encryption keys

## Vault Operations
- Init: `nullwarden-cli init`
- Add entry: `nullwarden-cli add <title> <username> [--password <pw>] [--notes <text>]`
- Update entry: `nullwarden-cli update <title> [--username <user>] [--password <pw>] [--notes <text>]`
- Get entry: `nullwarden-cli get <title> [--print]` (prints password if --print, else copies to clipboard for 30s)
- List entries: `nullwarden-cli list`
- Delete entry: `nullwarden-cli delete <title>`
- Lock vault: `nullwarden-cli lock`
- Push to server: `nullwarden-cli push`
- Pull from server: `nullwarden-cli pull`
- Register user: `nullwarden-cli register <username> [--password]`
- Logout: `nullwarden-cli logout`

## Configuration
- Vault location: XDG standard (`~/.local/share/nullwarden/vault.nw`)
- CLI config: TOML file at XDG config dir
- Environment variables for server:
  - `DATABASE_URL`: PostgreSQL connection string
  - `JWT_SECRET`: 256-bit random key for token signing
  - `SERVER_ADDR`: Bind address (default: 0.0.0.0:8080)

## Testing
- Unit tests: `cargo test`
- Integration tests: Test CLI-server interaction
- Property tests: Nonce uniqueness, KDF consistency
- Fuzz testing: `cargo run --bin nullwarden-fuzz`
- Benchmarks: `cargo bench` (KDF and encryption performance)

## Important Notes
- Server is untrusted encrypted blob store only - zero knowledge by design
- All cryptographic operations happen client-side
- Vault writes use atomic write-temp → fsync → rename pattern
- Password input never echoes, never in shell history (uses rpassword)
- Conflict detection via version counters on push/pull operations
- For detailed documentation, see README.md and docs/ directory
