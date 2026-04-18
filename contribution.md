 gemini --resume 'd6ec720c-a945-4f07-b61a-965952adf857'

NullWarden — Contribution Guide

Purpose

This document explains how to contribute to NullWarden. The project is a security-first, Rust-based zero-knowledge password vault. All contributions must preserve the zero-knowledge guarantees, adhere to the security gates in the README, and follow the repository's CI and code-quality expectations.

Getting started (Development environment)

1. Prerequisites
   - Rust toolchain (stable) via rustup
   - cargo, rustfmt, clippy
   - cargo-audit (`cargo install cargo-audit`)
   - Optional: musl toolchain for cross builds (`rustup target add x86_64-unknown-linux-musl`)

2. Clone
   - Fork the repository (if you don't have push access) and clone your fork.
   - Add upstream remote to keep in sync.

   git clone <your-fork-url>
   git remote add upstream <canonical-repo-url>

3. Build & run tests locally
   - Format:    cargo fmt --all
   - Lint:      cargo clippy -- -D warnings
   - Test:      cargo test --all
   - Audit deps: cargo audit

Branching and workflow

- Branches
  - main ← protected, release-tagged
  - develop ← integration branch
  - feature/* ← per-story branches
  - hotfix/* ← critical bug patches
  - security/* ← security fixes (private until patched)

- Naming: feature/<short-description>, hotfix/<issue-id>

- Workflow
  1. Create a feature branch off develop.
  2. Make incremental commits with clear messages.
  3. Ensure all tests and linters pass locally before opening a PR.
  4. Open a PR against develop (or the branch requested in the issue).
  5. Link the related issue and describe changes, security impact, and tests added.

Pull Request checklist (PRs must satisfy before merge)

- [ ] Target branch: develop (or other requested branch)
- [ ] Title and description follow the repository's guidance and reference issues
- [ ] Unit tests added/updated; all tests pass
- [ ] cargo fmt and cargo clippy -- -D warnings clean
- [ ] cargo audit shows no critical/high CVEs introduced
- [ ] No secrets, keys, or passwords in commits or branch history
- [ ] Security reviewer assigned for any cryptographic or protocols changes
- [ ] Threat model updated when a new component or interface is added
- [ ] CHANGELOG entry added (if applicable)

Code style and commit messages

- Use `cargo fmt` for formatting.
- Fix clippy warnings; the CI enforces `-D warnings`.
- Commit message format (recommended):
  <type>(scope): short description

  Types: feat, fix, docs, style, refactor, perf, test, chore, ci, sec
  Example: feat(core): add XChaCha20-Poly1305 encryptor

Testing and CI expectations

- Unit tests for all new functionality.
- Integration tests for sync and API interactions.
- Crypto code must include deterministic tests and property tests where applicable.
- CI runs the same checks as the PR checklist; ensure local parity before pushing.

Security and Secrets

- This is a zero-knowledge project. Never add code that stores or transmits plaintext secrets to the server.
- Do not commit credentials, private keys, or any secrets. Use environment variables or local vault files for development secrets.
- All crypto-related code changes require a secondary security review (four-eyes).
- Use `git-secrets` or equivalent local scanning before pushing; maintainers will run repository scans in CI.

Release and signing

- Releases are created from main and must be tagged.
- Release artifacts should be signed (cosign / minisign) per README.

Reporting issues and security vulnerabilities

- For regular bugs and feature requests, open an issue with reproduction steps, environment, and impact.
- For security vulnerabilities, follow responsible disclosure: email the maintainers (see repository contact or SECURITY.md if present). Do not post vulnerabilities publicly.

Maintainers and review

- Maintain a respectful, collaborative tone in PRs and issues.
- Security-sensitive PRs may be kept private until a patch is ready.

Additional notes

- The project follows a security-hardened Agile process (2-week sprints) and requires security gates before merging to main — see README for the detailed gate checklist.
- If unsure about the security impact of a change, discuss it in an issue before implementation.

Thank you for contributing to NullWarden!
