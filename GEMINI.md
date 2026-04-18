# NullWarden — Project Context

NullWarden is a security-first, Rust-based zero-knowledge password vault. It implements a client-trusted/server-adversarial architecture where the server never sees the master password or the plaintext vault contents.

## Project Overview

- **Purpose:** Secure password management with zero-knowledge synchronization.
- **Main Technologies:**
    - **Rust:** Core implementation language.
    - **XChaCha20-Poly1305:** AEAD for vault encryption.
    - **Argon2id:** KDF for key derivation from master passwords.
    - **Axum:** Web framework for the synchronization server.
    - **SQLx (PostgreSQL/Supabase):** Database interaction for the server.
    - **Clap:** Command-line argument parsing for the CLI.
    - **Zeroize:** Memory safety for sensitive data.

### Architecture (C4 Context)

- **`nullwarden-core`**: A library containing the cryptographic primitives, vault header format, and data structures. It handles encryption/decryption and atomic file writes.
- **`nullwarden-cli`**: The user-facing CLI application. It manages the local vault, interacts with the synchronization server, and uses the OS keyring for session tokens.
- **`nullwarden-server`**: A REST API that stores encrypted vault blobs and handles user authentication (via JWT). It treats all client data as opaque bytes.
- **`nullwarden-fuzz`**: Contains fuzzing targets (using `cargo-fuzz`) to ensure the robustness of the vault parser and decryption logic.

## Building and Running

The project is structured as a Rust workspace.

### Key Commands

- **Build Workspace:**
  ```bash
  cargo build --workspace
  ```
- **Run Tests:**
  ```bash
  cargo test --workspace
  ```
- **Run CLI (Example):**
  ```bash
  cargo run -p nullwarden-cli -- init
  ```
- **Run Server:**
  ```bash
  cargo run -p nullwarden-server
  ```
- **Linting:**
  ```bash
  cargo clippy --workspace -- -D warnings
  ```
- **Formatting:**
  ```bash
  cargo fmt --all
  ```
- **Dependency Audit:**
  ```bash
  cargo audit
  ```
- **Release Build:**
  ```bash
  ./scripts/build-release.sh
  ```

### Configuration

- **Server:** Requires a `.env` file (see `.env.example`). Needs `DATABASE_URL` (Postgres/Supabase) and `JWT_SECRET`.
- **CLI:** Configured via `config.toml` (usually in `~/.config/nullwarden/`).

## Development Conventions

- **Security First:** Never implement code that transmits plaintext secrets to the server.
- **Memory Safety:** Sensitive types (passwords, keys) MUST implement or be wrapped in types that implement `Zeroize` and `ZeroizeOnDrop`.
- **Code Style:** Enforced by `cargo fmt` and `clippy`. CI will fail on any warnings (`-D warnings`).
- **Commits:** Conventional commits are recommended (`feat:`, `fix:`, `sec:`, etc.).
- **Testing:** New features MUST include unit tests. Synchronizations and API changes require integration tests.
- **Migrations:** Database schema changes must be implemented as `sqlx` migrations in `crates/nullwarden-server/migrations/`.
- **Zero-Knowledge:** Any change to the synchronization protocol or vault format requires a security review.
