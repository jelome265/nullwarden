# NullWarden — Zero-Knowledge Password Vault with Cloud Sync
## Full Project Documentation · Enterprise Prototype

> **Classification:** Internal Engineering — Prototype Phase  
> **Version:** 1.0.0  
> **Stack:** Rust (core + CLI) · REST backend (Rust/Axum) · PostgreSQL  
> **Last Updated:** 2026-04-15

---

## Table of Contents

1. [Problems This Project Addresses](#1-problems-this-project-addresses)
2. [Aims and SMART Objectives](#2-aims-and-smart-objectives)
3. [Scope](#3-scope)
4. [Development Methodology](#4-development-methodology)
5. [Project Plan — WBS and Gantt](#5-project-plan--wbs-and-gantt)
6. [Risks, Mitigations, and Failure Modes](#6-risks-mitigations-and-failure-modes)
7. [Deliverables Summary](#7-deliverables-summary)
8. [Requirements Specification](#8-requirements-specification)
9. [Functional Requirements](#9-functional-requirements)
10. [Non-Functional Requirements](#10-non-functional-requirements)
11. [Requirements Traceability Matrix](#11-requirements-traceability-matrix)
12. [System Modelling — UML](#12-system-modelling--uml)
13. [Use Case Descriptions · System Architecture & Security Design](#13-use-case-descriptions--system-architecture--security-design)
14. [Testing Strategy and Test Cases · Evaluation and Recommendations](#14-testing-strategy-and-test-cases--evaluation-and-recommendations)
15. [Full Project File Structure](#15-full-project-file-structure)

---

## 1. Problems This Project Addresses

### 1.1 Problem Inventory

| # | Problem | Class | Severity |
|---|---------|-------|----------|
| P1 | **Device-bound vault loss** — local-only vaults are destroyed entirely on device failure or replacement. No recovery mechanism exists without a separate backup. | Data durability | HIGH |
| P2 | **Server-side plaintext exposure** — most hosted password managers decrypt server-side or store re-encryptable data. A server breach leaks all credentials. | Trust model | CRITICAL |
| P3 | **Weak cloud storage trust assumptions** — cloud providers (S3, GCS, Dropbox) can access unencrypted blobs. Encryption must not depend on provider goodwill. | Confidentiality | HIGH |
| P4 | **Credential reuse and poor management hygiene** — users keep passwords in plain text files, browser storage, or spreadsheets. No structured vault → massive attack surface. | Hygiene | HIGH |
| P5 | **Improper cryptographic implementations** — DIY or library-misuse: missing KDFs, nonce reuse, unauthenticated encryption, short keys. Renders any vault security theatre. | Cryptographic integrity | CRITICAL |
| P6 | **Absent zero-knowledge guarantees** — systems advertise "encryption" while retaining key material server-side or in escrow. Regulatory and threat model implications are severe. | Architectural | CRITICAL |
| P7 | **No cross-device consistency** — vaults that exist only locally cannot be accessed from a second workstation, a recovery device, or a team member's machine. | Usability/operability | MEDIUM |
| P8 | **Timing-attack vulnerability in auth comparisons** — naive credential comparison leaks timing oracles allowing offline enumeration. | Side-channel | HIGH |

### 1.2 Root Cause Analysis

The common root cause across P2, P5, and P6 is **misplaced trust boundary placement**: decryption authority resides at the server, making the server the highest-value target in the architecture. NullWarden resolves this by treating the server as an **untrusted encrypted blob store** — a dumb, stateless, zero-knowledge backend with no decryption capability by design.

---

## 2. Aims and SMART Objectives

### 2.1 Project Aim

> Design and implement `nullwarden`: a zero-knowledge, cross-device password vault where all cryptographic operations are client-exclusive, the server stores only opaque ciphertext, and no credential recovery is possible without the user's master password.

### 2.2 SMART Objectives

**O1 — Zero-Knowledge Enforcement**
- **S:** The server must store only opaque encrypted blobs. It must never hold, derive, or access plaintext vault entries or encryption keys.
- **M:** Zero plaintext fields in database schema. Verified by schema audit + penetration test showing no decryptable data at rest.
- **A:** Enforced architecturally: decryption code does not exist on the server.
- **R:** Core security guarantee. Differentiates from LastPass-class breach scenarios.
- **T:** Phase 1 (Weeks 1–4).

**O2 — Cryptographically Sound Key Derivation**
- **S:** Implement Argon2id with `m=65536` (64 MB), `t=3`, `p=4` as the KDF baseline. Per-user, per-vault salt (32 bytes, CSPRNG). Derive a 256-bit encryption key, never the master password itself.
- **M:** KDF wall-clock time ≥ 300 ms on reference hardware (i7-equivalent). Measured in CI benchmark.
- **A:** `argon2` crate (Rust) provides a maintained, audited implementation.
- **R:** Defends offline dictionary attacks under full DB compromise.
- **T:** Phase 1 (Week 2).

**O3 — Authenticated Encryption**
- **S:** Use `XChaCha20-Poly1305` for all vault payload encryption. Each encryption operation must generate a unique 192-bit random nonce.
- **M:** 0 nonce reuse events. Verified by unit tests with deterministic nonce injection mocking + fuzz harness.
- **A:** `chacha20poly1305` crate (RustCrypto), widely audited.
- **R:** AEAD provides both confidentiality and integrity — no separate MAC required.
- **T:** Phase 1 (Week 2).

**O4 — Secure Sync Across Devices**
- **S:** Upload/download encrypted vault blobs to the server. Implement version-counter-based conflict detection. Client validates blob integrity before writing to disk.
- **M:** Sync round-trip < 500 ms on 10 Mbps link. Conflict detection catches all concurrent write scenarios (verified by integration test suite).
- **A:** REST API with versioned vault endpoint. PostgreSQL optimistic locking via `version` integer column.
- **R:** Enables multi-device use without server decryption capability.
- **T:** Phase 2 (Weeks 5–7).

**O5 — Authentication/Encryption Key Separation**
- **S:** The server authentication credential (a separate randomly-generated token or OPAQUE-style password hash) must be independent of the vault encryption key. Compromise of the server auth layer must not enable vault decryption.
- **M:** Static analysis confirms no key derivation from auth credentials on server. Auth token ≠ encryption key at any code path.
- **A:** Auth uses Argon2id-hashed password stored server-side (standard); vault key derived separately client-side from master password.
- **R:** Prevents server compromise → vault decryption escalation path.
- **T:** Phase 2 (Week 5).

**O6 — Memory Safety and Secret Zeroization**
- **S:** All plaintext key material and vault entries must be zeroized from memory immediately after use. Use `zeroize` crate on all sensitive types.
- **M:** Valgrind / `cargo-valgrind` shows no retained key material in heap dumps after vault lock. Memory sanitizer clean.
- **A:** Rust ownership model enforces single-use; `Zeroize` trait drops enforce cleanup.
- **R:** Reduces attack surface for process memory dumps / cold boot attacks.
- **T:** Phase 1 (Week 3).

---

## 3. Scope

### 3.1 In Scope — Prototype (v0.1)

| Component | Description |
|-----------|-------------|
| `nullwarden-core` | Rust library: Argon2id KDF, XChaCha20-Poly1305 encrypt/decrypt, vault format serialization (MessagePack), zeroization |
| `nullwarden-cli` | Rust CLI: init, add, get, list, delete, push, pull, lock, unlock commands |
| `nullwarden-server` | Rust/Axum REST API: user registration, login, vault blob upload/download, version management |
| Vault format spec | Binary layout: version byte, KDF params, salt, nonce, ciphertext, format documented |
| Authentication | Argon2id password hashing server-side, JWT session tokens (short-lived), refresh token rotation |
| Conflict detection | Optimistic locking via version counter, client-side conflict resolution prompt |
| Static binary build | `x86_64-unknown-linux-musl` and `x86_64-pc-windows-msvc` targets via cross-compilation |
| Release signing | `cosign` or `minisign` for release artifact signing |
| Test suite | Unit (crypto), integration (sync), property-based (fuzz) |
| Security documentation | Threat model, attack assumptions, security design rationale |

### 3.2 Out of Scope — v0.1

| Feature | Reason deferred |
|---------|-----------------|
| Password sharing between users | Requires asymmetric key exchange layer (planned v0.3) |
| Browser extension / autofill | Separate attack surface; planned post-core audit |
| GUI (desktop native) | Planned post-CLI stabilisation; Tauri candidate |
| TOTP / MFA on server auth | Planned v0.2 |
| Password recovery / escrow | Architecturally incompatible with zero-knowledge guarantee |
| Multi-tenant RBAC | Enterprise tier, deferred |
| Server-side search | Impossible without plaintext; not planned |
| OPAQUE protocol | Preferred long-term but complex; v0.4 |
| Tor / anonymous transport | Planned optional overlay |
| Mobile clients | Rust → React Native FFI planned v0.3 |

---

## 4. Development Methodology

### 4.1 Recommended: Security-Hardened Agile (Scrum + Security Gates)

Standard Agile is modified for a cryptographic security product. The key addition is **mandatory security gates** at each sprint boundary and a parallel **threat model sprint** that runs alongside feature sprints.

### 4.2 Rationale

| Criterion | Decision |
|-----------|----------|
| Team size | Small (1–3 engineers) → Scrum with lightweight ceremonies |
| Requirement stability | Core crypto stable; sync/auth subject to discovery → iterative |
| Security criticality | HIGH → security review at every sprint, not just at release |
| Prototype nature | Fast iteration needed → 2-week sprints, not waterfall |
| Quality bar | Enterprise → TDD mandatory, no story merges without tests |

### 4.3 Sprint Structure

```
Sprint Cadence: 2 weeks
Ceremonies:
  Sprint Planning        → Monday Week 1 (2h)
  Daily Standup          → 15 min async (written)
  Security Checkpoint    → Thursday Week 2 (1h) — mandatory per sprint
  Sprint Review          → Friday Week 2 (1h)
  Retrospective          → Friday Week 2 (30 min)
```

### 4.4 Security Gate Criteria (per sprint)

Before merging any sprint to `main`:

- [ ] `cargo clippy -- -D warnings` passes clean
- [ ] `cargo test` — 100% pass, coverage > 80% on `nullwarden-core`
- [ ] `cargo audit` — zero critical/high CVEs in dependency tree
- [ ] All new crypto paths reviewed by at least one additional engineer (four-eyes)
- [ ] Threat model updated for any new component added
- [ ] No secrets, keys, or passwords in git history (`git-secrets` or `trufflehog` scan)

### 4.5 Branching Strategy

```
main          ← protected, release-tagged
develop       ← integration branch
feature/*     ← per-story branches
hotfix/*      ← critical bug patches
security/*    ← security fix branches (private until patched)
```

### 4.6 Definition of Done

1. Functionality implemented per acceptance criteria
2. Unit tests written and passing
3. Integration test updated if sync/API touched
4. `cargo fmt`, `cargo clippy`, `cargo audit` all clean
5. Documentation updated (inline doc + CHANGELOG entry)
6. Security gate passed
7. PR reviewed and approved

---

## 5. Project Plan — WBS and Gantt

### 5.1 Work Breakdown Structure (WBS)

```
NullWarden Prototype
├── 1. Project Initiation
│   ├── 1.1 Requirements elicitation
│   ├── 1.2 Threat model (initial)
│   ├── 1.3 Architecture decision records (ADRs)
│   └── 1.4 Repository bootstrap + CI/CD skeleton
│
├── 2. Core Library (nullwarden-core)
│   ├── 2.1 Vault format definition
│   │   ├── 2.1.1 Header schema (version, KDF params, salt, nonce)
│   │   ├── 2.1.2 Payload schema (MessagePack-encoded entries)
│   │   └── 2.1.3 Serialization/deserialization (serde + rmp-serde)
│   ├── 2.2 Key derivation
│   │   ├── 2.2.1 Argon2id implementation with tunable params
│   │   ├── 2.2.2 Salt generation (CSPRNG, 32 bytes)
│   │   └── 2.2.3 Key stretching tests + benchmarks
│   ├── 2.3 Encryption engine
│   │   ├── 2.3.1 XChaCha20-Poly1305 encrypt
│   │   ├── 2.3.2 XChaCha20-Poly1305 decrypt
│   │   └── 2.3.3 Nonce generation (CSPRNG, 192-bit)
│   ├── 2.4 Memory safety
│   │   ├── 2.4.1 Zeroize integration on all sensitive types
│   │   └── 2.4.2 Secure memory allocation patterns
│   ├── 2.5 Vault operations
│   │   ├── 2.5.1 Add entry
│   │   ├── 2.5.2 Get entry
│   │   ├── 2.5.3 List entries
│   │   ├── 2.5.4 Delete entry
│   │   └── 2.5.5 Vault lock/unlock state machine
│   └── 2.6 Unit test suite (crypto + vault ops)
│
├── 3. CLI (nullwarden-cli)
│   ├── 3.1 Command parser (clap v4)
│   ├── 3.2 Secure password input (rpassword)
│   ├── 3.3 Local vault file management
│   ├── 3.4 Command implementations
│   │   ├── 3.4.1 init
│   │   ├── 3.4.2 add / get / list / delete
│   │   ├── 3.4.3 push / pull
│   │   └── 3.4.4 lock / unlock
│   ├── 3.5 Config file (TOML, XDG base dirs)
│   └── 3.6 Error handling + user-facing messages
│
├── 4. Backend Server (nullwarden-server)
│   ├── 4.1 Database schema (PostgreSQL)
│   │   ├── 4.1.1 users table
│   │   └── 4.1.2 vaults table (versioned blobs)
│   ├── 4.2 Authentication
│   │   ├── 4.2.1 Registration endpoint (Argon2id hash)
│   │   ├── 4.2.2 Login endpoint (JWT issuance)
│   │   ├── 4.2.3 Token refresh
│   │   └── 4.2.4 Logout / token revocation
│   ├── 4.3 Vault API
│   │   ├── 4.3.1 PUT /vault (upload blob)
│   │   ├── 4.3.2 GET /vault (download blob)
│   │   └── 4.3.3 Version conflict handling
│   ├── 4.4 Middleware
│   │   ├── 4.4.1 Rate limiting (tower-governor)
│   │   ├── 4.4.2 Request ID tracing
│   │   └── 4.4.3 Auth middleware (JWT validation)
│   └── 4.5 Integration test suite
│
├── 5. Sync Engine
│   ├── 5.1 Push protocol (version check → upload)
│   ├── 5.2 Pull protocol (download → integrity check → write)
│   └── 5.3 Conflict detection and resolution (client-side)
│
├── 6. Security Review and Hardening
│   ├── 6.1 Internal security audit
│   ├── 6.2 Threat model finalisation
│   ├── 6.3 Dependency audit (cargo audit + cargo deny)
│   ├── 6.4 Fuzz testing harness (cargo-fuzz)
│   └── 6.5 Static analysis (clippy + rudra if applicable)
│
├── 7. Build and Distribution
│   ├── 7.1 Cross-compilation targets (musl Linux, Windows MSVC)
│   ├── 7.2 Release signing (minisign)
│   ├── 7.3 GitHub Actions release pipeline
│   └── 7.4 Docker image for server
│
└── 8. Documentation
    ├── 8.1 Vault format specification (RFC-style)
    ├── 8.2 Security design document
    ├── 8.3 API reference (OpenAPI 3.1)
    ├── 8.4 CLI user manual
    └── 8.5 Deployment guide
```

### 5.2 Gantt Chart (12-Week Schedule)

```
WEEK        │ 1  2  3  4  5  6  7  8  9  10 11 12
────────────┼────────────────────────────────────
1. Initiation
  1.1 Reqts │ ██
  1.2 ThrMdl│ ██ ██
  1.3 ADRs  │ ██
  1.4 CI/CD │    ██
────────────┼────────────────────────────────────
2. Core Lib
  2.1 Format│    ██ ██
  2.2 KDF   │    ██ ██
  2.3 Crypto│       ██ ██
  2.4 Mem   │       ██ ██
  2.5 Vault │          ██ ██
  2.6 Tests │    ░░ ██ ██ ██
────────────┼────────────────────────────────────
3. CLI
  3.1-3.3   │             ██ ██
  3.4 Cmds  │                ██ ██
  3.5-3.6   │                   ██
────────────┼────────────────────────────────────
4. Server
  4.1 DB    │          ██
  4.2 Auth  │          ██ ██
  4.3 API   │             ██ ██
  4.4 Mid   │                ██
  4.5 Tests │             ░░ ██ ██
────────────┼────────────────────────────────────
5. Sync
  5.1-5.3   │                   ██ ██
────────────┼────────────────────────────────────
6. Security
  6.1 Audit │                      ██ ██
  6.2 ThrMdl│                      ██
  6.3 DepAud│                         ██
  6.4 Fuzz  │                         ██ ██
────────────┼────────────────────────────────────
7. Build
  7.1-7.4   │                            ██ ██
────────────┼────────────────────────────────────
8. Docs
  8.1-8.5   │                      ░░ ░░ ██ ██
────────────┼────────────────────────────────────

██ = active work    ░░ = ongoing / parallel

Milestones:
  M1 → Week 4:  Core library crypto tested and complete
  M2 → Week 7:  CLI + Server integration working end-to-end
  M3 → Week 9:  Sync engine complete, conflict detection verified
  M4 → Week 10: Security audit complete
  M5 → Week 12: Signed release binaries published
```

---

## 6. Risks, Mitigations, and Failure Modes

### 6.1 Risk Register

| ID | Risk | Likelihood | Impact | Severity | Mitigation | Residual Risk |
|----|------|-----------|--------|----------|-----------|---------------|
| R1 | **Server compromise — full DB exfiltration** | Medium | Low (encrypted blobs only) | LOW | Argon2id KDF makes offline attack costly. Unique salts per vault. No keys stored. | Accepted — attacker gains encrypted blobs only |
| R2 | **Nonce reuse in XChaCha20-Poly1305** | Low | CRITICAL (full decryption) | CRITICAL | CSPRNG nonce per operation. Nonce never stored or reused. Fuzz harness validates uniqueness. | Near-zero |
| R3 | **Weak master password chosen by user** | High | HIGH (offline crack succeeds) | HIGH | Minimum entropy enforcement (zxcvbn score ≥ 3). KDF tuned to ≥ 300 ms. User education. | Medium — user control |
| R4 | **Auth credential reuse = encryption key** | Low (by design) | CRITICAL | CRITICAL | Architecturally separated: server auth uses independent Argon2id hash; vault key derived client-side from master password only. No code path connects them. | Near-zero |
| R5 | **Replay attack — stale vault version returned** | Medium | Medium (data loss) | MEDIUM | Version counter in DB. Client validates version on pull. Server rejects stale pushes. TLS transit. | Low |
| R6 | **Sync conflict — concurrent multi-device write** | Medium | Medium (last-write-wins data loss) | MEDIUM | Optimistic locking. Client detects version mismatch, prompts user. Merge strategy (last-write-wins or user choice) documented. | Low |
| R7 | **Client-side compromise (malware, keylogger)** | Medium | CRITICAL (plaintext in memory) | HIGH | Minimise plaintext lifetime. Zeroize immediately after use. mlocked memory where OS permits. **Accept residual** — malware with ring-3 access is game-over by definition. | Accepted |
| R8 | **Metadata leakage (service names visible)** | Low | Medium | MEDIUM | Entire vault payload encrypted, not individual fields. Server only sees opaque blob. Blob size leaks entry count range — documented. | Low |
| R9 | **Timing oracle on server auth comparison** | Low | Medium (username enumeration) | MEDIUM | `constant_time_eq` crate for all credential comparisons. Generic error messages regardless of failure cause. | Low |
| R10 | **Supply chain attack via dependency** | Low | HIGH | HIGH | `cargo audit` + `cargo deny` in CI. Minimal dependency footprint. Lock file committed. SBOM generated per release. | Low |
| R11 | **JWT secret key leak** | Low | CRITICAL (auth bypass) | CRITICAL | JWT signing key from env var. 256-bit random key. Key rotation procedure documented. Server-side token blocklist for logout. | Low |
| R12 | **Argon2 parameters too weak / too strong** | Medium | Medium | MEDIUM | Baseline: m=65536, t=3, p=4. Benchmark on reference hardware. CI test asserts ≥ 300 ms wall clock. Document param upgrade path for vault migration. | Low |
| R13 | **Vault file corruption (write interrupted)** | Medium | HIGH (data loss) | HIGH | Atomic write: write to `.tmp`, fsync, rename. Backup before any destructive operation. Integrity check on open (AEAD tag validates ciphertext). | Low |
| R14 | **TLS misconfiguration — traffic interceptable** | Low | HIGH | HIGH | TLS 1.3 only. Strong cipher suite enforcement. Certificate pinning optional. HSTS on server. | Low |

### 6.2 Failure Mode Analysis — Critical Paths

#### Failure Mode A: Nonce Reuse
```
Trigger:   CSPRNG failure (OS entropy pool exhausted or seeding bug)
Symptom:   Two ciphertexts share a nonce under the same key
Impact:    XOR of plaintexts recoverable; AEAD broken; full plaintext leak
Detection: Fuzz harness; property test asserting nonce uniqueness; OS entropy monitoring
Recovery:  Re-encrypt entire vault with fresh nonce; rotate if suspected
```

#### Failure Mode B: KDF Downgrade
```
Trigger:   Developer reduces Argon2 params for "performance" without approval
Symptom:   KDF wall-clock drops below 100 ms; offline attack window widens dramatically
Detection: CI benchmark asserts ≥ 300 ms; param values stored in vault header → auditable
Recovery:  Re-derive key with original params; re-encrypt vault; deploy param enforcement
```

#### Failure Mode C: Vault Corruption on Write
```
Trigger:   Process kill / power loss mid-write to vault file
Symptom:   Truncated or partially written ciphertext; AEAD tag invalid on open
Detection: AEAD decryption failure → explicit error; no silent data serving
Recovery:  Restore from last-synced server blob (pull command)
```

#### Failure Mode D: Sync Conflict
```
Trigger:   Two devices push independently before either pulls
Symptom:   Second push rejected by server (version mismatch)
Detection: Server returns HTTP 409 Conflict with current version
Recovery:  Client prompts user; user chooses: keep local, keep remote, or manual merge
```

---

## 7. Deliverables Summary

| ID | Deliverable | Owner | Target Milestone |
|----|-------------|-------|-----------------|
| D1 | `nullwarden-core` — Rust crate: KDF + AEAD + vault format | Core eng | M1 (Wk 4) |
| D2 | `nullwarden-cli` — Rust binary: full CLI command set | CLI eng | M2 (Wk 7) |
| D3 | `nullwarden-server` — Rust/Axum REST API service | Backend eng | M2 (Wk 7) |
| D4 | PostgreSQL migration scripts + schema | Backend eng | M2 (Wk 7) |
| D5 | Sync engine integration (push/pull/conflict) | All | M3 (Wk 9) |
| D6 | Vault format specification document (RFC-style) | Core eng | M4 (Wk 10) |
| D7 | Threat model and security design document | Security | M4 (Wk 10) |
| D8 | Test suite: unit (≥ 80% coverage), integration, fuzz | All | M4 (Wk 10) |
| D9 | OpenAPI 3.1 spec for server API | Backend eng | M4 (Wk 10) |
| D10 | Signed release binaries (Linux musl + Windows MSVC) | DevOps | M5 (Wk 12) |
| D11 | Docker image for `nullwarden-server` | DevOps | M5 (Wk 12) |
| D12 | Deployment guide + operator runbook | All | M5 (Wk 12) |
| D13 | SBOM (Software Bill of Materials) per release | DevOps | M5 (Wk 12) |

---

## 8. Requirements Specification

### 8.1 System Overview

NullWarden is a distributed, zero-knowledge password vault system comprising three components:

1. **`nullwarden-core`** — A Rust library implementing all cryptographic primitives: key derivation, authenticated encryption, vault format serialization. This crate contains **no network code** and **no file I/O** — it is a pure cryptographic engine callable from any host.

2. **`nullwarden-cli`** — A Rust command-line interface that uses `nullwarden-core` for all cryptographic operations, manages local vault files, and communicates with the server for sync operations. It is the primary user-facing interface for v0.1.

3. **`nullwarden-server`** — A Rust/Axum HTTP service acting as a **zero-knowledge blob store**: it accepts authentication credentials, stores encrypted vault blobs, and returns them on request. It has no knowledge of vault contents, no decryption capability, and no access to user keys.

### 8.2 Core Security Invariants

These are not preferences — they are architectural invariants that must hold at all times. Any feature or change that violates one of these invariants is rejected outright:

```
INVARIANT 1: The server MUST NOT store or transmit plaintext vault entries or encryption keys.
INVARIANT 2: Encryption keys MUST be derived exclusively on the client from the master password.
INVARIANT 3: All encryption operations MUST use AEAD with a unique random nonce per operation.
INVARIANT 4: Sensitive types MUST implement Zeroize and be zeroized immediately after use.
INVARIANT 5: Authentication credentials MUST be independent of vault encryption key material.
INVARIANT 6: Vault writes MUST be atomic (write-temp → fsync → rename pattern).
```

### 8.3 Assumed Attack Model

| Attacker | Capability | NullWarden's Guarantee |
|---------|-----------|------------------------|
| Passive network observer | Full traffic capture | TLS 1.3; only ciphertext in transit |
| Compromised server / DB admin | Full database read | Encrypted blobs only; no keys; Argon2id KDF for auth hashes |
| Physical device theft (locked) | Read disk | Vault file is ciphertext; KDF makes offline attack expensive |
| Physical device theft (unlocked, vault open) | Process memory dump | Zeroize minimizes window; accept residual per R7 |
| Active MITM | TLS stripping | TLS 1.3 + HSTS; optional cert pinning |
| Malicious server returning stale blob | Version forgery | Client validates version; server-signed version not in scope for v0.1 |

---

## 9. Functional Requirements

### FR1 — User Registration

| Field | Value |
|-------|-------|
| **ID** | FR1 |
| **Title** | User Registration |
| **Priority** | MUST |
| **Description** | The system shall allow a new user to register with a username and a server authentication password. The server shall hash the authentication password with Argon2id (m=65536, t=3, p=4) and store only the hash. It shall never store the plaintext. |
| **Input** | Username (UTF-8, 3–64 chars), auth password (UTF-8, ≥ 12 chars) |
| **Output** | 201 Created with user ID; or 409 Conflict if username taken |
| **Security** | Auth password ≠ vault master password. Server derives no key material from auth password. |
| **Acceptance** | POST `/auth/register` with valid credentials returns 201. Duplicate username returns 409. Plaintext password does not appear in DB or logs. |

### FR2 — User Authentication

| Field | Value |
|-------|-------|
| **ID** | FR2 |
| **Title** | User Authentication |
| **Priority** | MUST |
| **Description** | The system shall authenticate users and issue a short-lived JWT access token (15 min) and a longer-lived refresh token (7 days). All token comparisons shall use constant-time equality. |
| **Input** | Username, auth password |
| **Output** | 200 OK with `{ access_token, refresh_token, expires_in }`; or 401 Unauthorized |
| **Security** | Generic 401 regardless of whether username or password is wrong (prevents enumeration). Rate limited: 5 attempts per 10 min per IP. |
| **Acceptance** | Valid credentials → JWT returned. Invalid credentials → generic 401. Brute force → 429 after 5 failures. Timing delta between valid/invalid < 5 ms (constant-time). |

### FR3 — Token Refresh

| Field | Value |
|-------|-------|
| **ID** | FR3 |
| **Title** | Token Refresh |
| **Priority** | MUST |
| **Description** | The system shall accept a valid refresh token and return a new access token. The old refresh token shall be invalidated (rotation). |
| **Input** | Refresh token (Bearer) |
| **Output** | 200 OK with new `{ access_token, refresh_token }` |
| **Security** | Refresh token stored as Argon2id hash in DB. Single-use: used token → immediately revoked. |

### FR4 — Logout

| Field | Value |
|-------|-------|
| **ID** | FR4 |
| **Title** | Logout / Session Termination |
| **Priority** | MUST |
| **Description** | The system shall invalidate the user's current access and refresh tokens upon logout. |
| **Input** | Valid access token (Bearer) |
| **Output** | 204 No Content |
| **Security** | Revoked token added to server-side blocklist (Redis or DB). Subsequent requests with revoked token → 401. |

### FR5 — Vault Initialization (Client)

| Field | Value |
|-------|-------|
| **ID** | FR5 |
| **Title** | Local Vault Initialization |
| **Priority** | MUST |
| **Description** | The CLI shall generate a new empty vault: generate 32-byte CSPRNG salt, derive key via Argon2id from master password + salt, encrypt empty payload with XChaCha20-Poly1305, write to disk atomically. |
| **Input** | Master password (entered twice for confirmation, no echo) |
| **Output** | Vault file at `~/.local/share/nullwarden/vault.nw` (XDG) |
| **Security** | Master password zeroized after key derivation. KDF params stored in vault header (version, m, t, p, salt). |

### FR6 — Add Entry

| Field | Value |
|-------|-------|
| **ID** | FR6 |
| **Title** | Add Vault Entry |
| **Priority** | MUST |
| **Description** | The CLI shall allow the user to add a named entry (service, username, password, optional notes, optional TOTP secret). The entry is appended to the decrypted vault, the vault is re-encrypted with a new nonce, and written atomically to disk. |
| **Input** | Entry fields (service name required, others optional) |
| **Output** | Updated vault file. Confirmation message. |
| **Security** | Entire vault re-encrypted on each write (not individual entries). New nonce per write. Entry ID is a random UUID, not sequential. |

### FR7 — Get Entry

| Field | Value |
|-------|-------|
| **ID** | FR7 |
| **Title** | Retrieve Vault Entry |
| **Priority** | MUST |
| **Description** | The CLI shall retrieve a named entry, decrypt it, and display it to the user. The password field shall be optionally copied to clipboard (cleared after 30 seconds) rather than printed to stdout. |
| **Input** | Service name or UUID; master password (if vault not unlocked) |
| **Output** | Entry fields. Password to clipboard or stdout per flag. |
| **Security** | Clipboard cleared after 30 s. Password field not written to shell history. |

### FR8 — List Entries

| Field | Value |
|-------|-------|
| **ID** | FR8 |
| **Title** | List Vault Entries |
| **Priority** | MUST |
| **Description** | The CLI shall list all entry names/services without revealing passwords. |
| **Input** | Master password (if vault not unlocked) |
| **Output** | Table: UUID, service name, username, last modified |
| **Security** | Passwords never displayed in list output. |

### FR9 — Delete Entry

| Field | Value |
|-------|-------|
| **ID** | FR9 |
| **Title** | Delete Vault Entry |
| **Priority** | MUST |
| **Description** | The CLI shall delete a named entry from the vault after confirmation. Vault re-encrypted with new nonce. |
| **Input** | Service name or UUID; confirmation prompt |
| **Output** | Updated vault file. Confirmation message. |
| **Security** | Confirmation required; no silent deletes. Atomic write. |

### FR10 — Upload Vault (Push)

| Field | Value |
|-------|-------|
| **ID** | FR10 |
| **Title** | Push Encrypted Vault to Server |
| **Priority** | MUST |
| **Description** | The CLI shall upload the current local encrypted vault blob to the server. The server shall store it associated with the authenticated user and increment the version counter. If the server's current version ≠ expected version, the server shall return 409 Conflict. |
| **Input** | Encrypted vault blob (bytes), expected version (integer), JWT |
| **Output** | 200 OK with new version; or 409 Conflict |
| **Security** | Server stores only opaque bytes. No inspection of contents. HTTPS only. |

### FR11 — Download Vault (Pull)

| Field | Value |
|-------|-------|
| **ID** | FR11 |
| **Title** | Pull Encrypted Vault from Server |
| **Priority** | MUST |
| **Description** | The CLI shall download the latest encrypted vault blob from the server, validate its AEAD integrity locally, and write it to disk atomically. |
| **Input** | JWT |
| **Output** | Encrypted vault blob written to local disk |
| **Security** | AEAD decryption attempted before overwriting local file. Failed integrity check → abort, preserve local file, alert user. |

### FR12 — Conflict Detection

| Field | Value |
|-------|-------|
| **ID** | FR12 |
| **Title** | Sync Conflict Detection |
| **Priority** | MUST |
| **Description** | The system shall detect when a push would overwrite a server version newer than the client's last-known version. Present user with choice: keep local, keep remote, or abort. |
| **Input** | Local version counter, server version counter |
| **Output** | Resolution action or abort |
| **Security** | No silent data loss. User decides conflict resolution. |

### FR13 — Vault Lock

| Field | Value |
|-------|-------|
| **ID** | FR13 |
| **Title** | Vault Lock |
| **Priority** | MUST |
| **Description** | The CLI shall support an explicit lock command that zeroizes the in-memory derived key (if cached between operations) and clears any session state. |
| **Input** | Lock command |
| **Output** | Confirmation. Subsequent operations require master password re-entry. |
| **Security** | Derived key zeroized from memory. No key written to disk. |

### FR14 — Secure Password Input

| Field | Value |
|-------|-------|
| **ID** | FR14 |
| **Title** | Secure Password Input |
| **Priority** | MUST |
| **Description** | All password entry points shall disable terminal echo (no characters displayed while typing). Passwords shall not appear in shell history (input not from shell args). |
| **Input** | Password entered via terminal prompt |
| **Output** | Password read into memory without display |
| **Security** | `rpassword` crate. Never pass passwords as CLI arguments. |

---

## 10. Non-Functional Requirements

### Security NFRs

| ID | Requirement | Metric / Verification |
|----|-------------|----------------------|
| NFR-S1 | **Argon2id KDF** — mandatory for vault key derivation | Code review; no other KDF path exists |
| NFR-S2 | **Argon2id params** — m ≥ 65536 KB, t ≥ 3, p ≥ 4 | CI benchmark asserts ≥ 300 ms on reference HW |
| NFR-S3 | **AEAD-only encryption** — XChaCha20-Poly1305 | No non-AEAD cipher in codebase (`cargo audit` + grep) |
| NFR-S4 | **Unique nonce per operation** — CSPRNG-generated 192-bit | Fuzz harness; property test |
| NFR-S5 | **Zeroize** — all sensitive types implement `Zeroize` | Rustdoc + unit test asserting memory zeroed post-drop |
| NFR-S6 | **No plaintext in DB** — server stores only opaque blobs | DB schema audit; 0 plaintext columns for vault data |
| NFR-S7 | **Constant-time comparisons** — auth and token operations | `constant_time_eq` crate; timing test ± 5 ms delta |
| NFR-S8 | **TLS 1.3 only** — no TLS 1.2 or below | TLS config audit; `nmap` ssl-scan |
| NFR-S9 | **JWT HS256 minimum** — prefer RS256 for key rotation | JWT decode validation test |
| NFR-S10 | **Rate limiting** — auth endpoints ≤ 5 req/10 min/IP | Load test verification; integration test |
| NFR-S11 | **No secrets in git** — enforced via `git-secrets` / `trufflehog` | CI scan on every push |
| NFR-S12 | **Dependency audit** — zero critical/high CVEs at release | `cargo audit` in CI; blocks merge on failure |

### Performance NFRs

| ID | Requirement | Metric |
|----|-------------|--------|
| NFR-P1 | **KDF latency** — intentionally slow: ≥ 300 ms | CI benchmark on i7-equivalent |
| NFR-P2 | **Sync round-trip** — ≤ 500 ms (10 Mbps link, 1 MB vault) | Integration test + `criterion` benchmark |
| NFR-P3 | **CLI startup** — ≤ 100 ms to interactive prompt | Hyperfine measurement in CI |
| NFR-P4 | **Vault file size** — overhead ≤ 256 bytes for header (excl. entries) | Unit test asserts header size |
| NFR-P5 | **Concurrent server requests** — ≥ 100 RPS on blob API (stateless) | Load test (wrk / oha) |

### Reliability NFRs

| ID | Requirement | Metric |
|----|-------------|--------|
| NFR-R1 | **Atomic vault writes** — write-tmp → fsync → rename pattern | Fault injection test (kill mid-write) |
| NFR-R2 | **Vault integrity check on open** — AEAD tag failure = explicit error | Unit test with corrupted ciphertext |
| NFR-R3 | **No silent data loss** — all error paths return explicit error | Code review; error handling audit |
| NFR-R4 | **Server availability** — 99.5% uptime target (SLO for prototype) | Uptime monitoring |

### Scalability NFRs

| ID | Requirement | Metric |
|----|-------------|--------|
| NFR-SC1 | **Stateless backend** — no server-side session state (JWT) | Architecture review; no session table required |
| NFR-SC2 | **Horizontal scaling** — multiple server instances behind LB | Deployment test with 2 instances + round-robin |
| NFR-SC3 | **User capacity** — ≥ 10,000 registered users (prototype scale) | DB load test |

### Portability NFRs

| ID | Requirement | Metric |
|----|-------------|--------|
| NFR-PO1 | **CLI on Linux (x86_64, musl)** — static binary, no libc dependency | Build matrix in CI |
| NFR-PO2 | **CLI on Windows (x86_64, MSVC)** — native Windows build | Build matrix in CI |
| NFR-PO3 | **Vault file portable** — same vault file readable on any supported OS | Cross-platform integration test |

### Usability NFRs

| ID | Requirement | Metric |
|----|-------------|--------|
| NFR-U1 | **No sensitive data in logs** — passwords, keys, tokens redacted | Log audit; grep for key patterns in test log output |
| NFR-U2 | **Deterministic CLI interface** — same input → same output format | CLI snapshot tests |
| NFR-U3 | **Explicit error messages** — no "null pointer exception" leaks | Error handling review; user-facing messages reviewed |

---

## 11. Requirements Traceability Matrix

| Req ID | Requirement | Component | Test Type | Test ID | Status |
|--------|-------------|-----------|-----------|---------|--------|
| FR1 | Registration | `nullwarden-server` | Integration | IT-01 | Planned |
| FR2 | Authentication | `nullwarden-server` | Integration | IT-02 | Planned |
| FR3 | Token Refresh | `nullwarden-server` | Integration | IT-03 | Planned |
| FR4 | Logout | `nullwarden-server` | Integration | IT-04 | Planned |
| FR5 | Vault Init | `core` + `cli` | Unit + E2E | UT-01, E2E-01 | Planned |
| FR6 | Add Entry | `core` + `cli` | Unit + E2E | UT-02, E2E-02 | Planned |
| FR7 | Get Entry | `core` + `cli` | Unit + E2E | UT-03, E2E-03 | Planned |
| FR8 | List Entries | `core` + `cli` | Unit + E2E | UT-04, E2E-04 | Planned |
| FR9 | Delete Entry | `core` + `cli` | Unit + E2E | UT-05, E2E-05 | Planned |
| FR10 | Push Vault | `cli` + `server` | Integration | IT-05 | Planned |
| FR11 | Pull Vault | `cli` + `server` | Integration | IT-06 | Planned |
| FR12 | Conflict Detection | `cli` + `server` | Integration | IT-07 | Planned |
| FR13 | Vault Lock | `cli` | Unit + E2E | UT-06, E2E-06 | Planned |
| FR14 | Secure Input | `cli` | Manual | M-01 | Planned |
| NFR-S1 | Argon2id KDF | `core` | Code audit + Unit | UT-07 | Planned |
| NFR-S2 | Argon2id params | `core` | Benchmark | BN-01 | Planned |
| NFR-S3 | AEAD-only | `core` | Code audit | CA-01 | Planned |
| NFR-S4 | Unique nonce | `core` | Fuzz + Property | FZ-01, PT-01 | Planned |
| NFR-S5 | Zeroize | `core` | Unit + Valgrind | UT-08, VG-01 | Planned |
| NFR-S6 | No plaintext in DB | `server` | Schema audit | SA-01 | Planned |
| NFR-S7 | Constant-time | `server` | Timing test | TT-01 | Planned |
| NFR-S8 | TLS 1.3 | `server` | ssl-scan | TL-01 | Planned |
| NFR-S10 | Rate limiting | `server` | Load test | LT-01 | Planned |
| NFR-P1 | KDF latency | `core` | Benchmark | BN-01 | Planned |
| NFR-P2 | Sync round-trip | `cli`+`server` | Integration | IT-08 | Planned |
| NFR-R1 | Atomic writes | `core` | Fault injection | FI-01 | Planned |
| NFR-R2 | Integrity check | `core` | Unit | UT-09 | Planned |
| NFR-PO1 | Linux binary | build | CI matrix | CI-01 | Planned |
| NFR-PO2 | Windows binary | build | CI matrix | CI-02 | Planned |

---

## 12. System Modelling — UML

### 12.1 Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        CLIENT DEVICE (Trusted)                          │
│                                                                         │
│  ┌──────────────────┐    ┌────────────────────────────────────────┐    │
│  │  nullwarden-cli  │───▶│            nullwarden-core             │    │
│  │                  │    │                                        │    │
│  │  • clap v4 CLI   │    │  ┌─────────────┐  ┌────────────────┐  │    │
│  │  • rpassword     │    │  │  kdf module  │  │  crypto module │  │    │
│  │  • config (TOML) │    │  │  Argon2id    │  │  XChaCha20-    │  │    │
│  │  • sync engine   │    │  │  KDF params  │  │  Poly1305      │  │    │
│  │  • clipboard     │    │  └─────────────┘  └────────────────┘  │    │
│  └──────────────────┘    │  ┌─────────────┐  ┌────────────────┐  │    │
│          │               │  │ vault module │  │  zeroize       │  │    │
│          │               │  │ serialise    │  │  SecretVec     │  │    │
│          │               │  │ deserialise  │  │  SecretBox     │  │    │
│          │               │  └─────────────┘  └────────────────┘  │    │
│          │               └────────────────────────────────────────┘    │
│          │                              │                               │
│          │                    ┌─────────▼────────┐                     │
│          │                    │  Local Vault File │                     │
│          │                    │  vault.nw         │                     │
│          │                    │  (encrypted blob) │                     │
│          │                    └──────────────────┘                     │
│          │                                                               │
└──────────┼───────────────────────────────────────────────────────────────┘
           │ HTTPS / TLS 1.3
           │
┌──────────▼───────────────────────────────────────────────────────────────┐
│                      UNTRUSTED SERVER BOUNDARY                            │
│                                                                           │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │                    nullwarden-server (Axum)                        │  │
│  │                                                                    │  │
│  │  ┌──────────────┐  ┌────────────────┐  ┌──────────────────────┐   │  │
│  │  │ Auth Router  │  │  Vault Router  │  │    Middleware Stack   │   │  │
│  │  │              │  │                │  │                      │   │  │
│  │  │ POST /auth/  │  │ PUT  /vault    │  │ • Rate limiter       │   │  │
│  │  │   register   │  │ GET  /vault    │  │ • JWT validator      │   │  │
│  │  │ POST /auth/  │  │                │  │ • Request ID tracer  │   │  │
│  │  │   login      │  │ (opaque blobs  │  │ • Error handler      │   │  │
│  │  │ POST /auth/  │  │  only — no     │  └──────────────────────┘   │  │
│  │  │   refresh    │  │  decryption)   │                              │  │
│  │  │ POST /auth/  │  └────────────────┘                              │  │
│  │  │   logout     │                                                  │  │
│  │  └──────────────┘                                                  │  │
│  └───────────────────────────────────┬────────────────────────────────┘  │
│                                      │ sqlx                               │
│                             ┌────────▼────────┐                          │
│                             │   PostgreSQL     │                          │
│                             │                  │                          │
│                             │  users table     │                          │
│                             │  vaults table    │                          │
│                             │  (blobs only)    │                          │
│                             └──────────────────┘                          │
└───────────────────────────────────────────────────────────────────────────┘
```

### 12.2 Vault File Format (Binary Layout)

```
nullwarden vault file — version 1 format (.nw)

Offset  Size   Field              Description
──────  ────   ─────              ───────────
0       4      magic              0x4E574152 ("NWAR")
4       1      version            Format version (currently 0x01)
5       1      kdf_algo           0x01 = Argon2id
6       4      kdf_m_cost         Argon2 memory cost (KiB) — u32 LE
10      4      kdf_t_cost         Argon2 time cost (iterations) — u32 LE
14      4      kdf_p_cost         Argon2 parallelism — u32 LE
18      32     salt               KDF salt (CSPRNG, 32 bytes)
50      24     nonce              XChaCha20 nonce (CSPRNG, 24 bytes)
74      8      payload_len        Length of encrypted payload — u64 LE
82      N      ciphertext         Encrypted MessagePack payload (N bytes)
82+N    16     aead_tag           Poly1305 authentication tag (16 bytes)
```

Payload (plaintext before encryption, MessagePack encoded):
```
{
  "version":  u32,          // vault data version (for sync)
  "entries":  [
    {
      "id":       UUID v4,  // random, non-sequential
      "service":  String,
      "username": String,
      "password": String,   // zeroized after use
      "notes":    String?,
      "totp":     String?,  // TOTP secret, optional
      "created":  u64,      // Unix timestamp
      "modified": u64
    }
  ]
}
```

### 12.3 Class Diagram (Core Library)

```
┌─────────────────────────────────────┐
│           VaultHeader               │
├─────────────────────────────────────┤
│ + magic: [u8; 4]                    │
│ + version: u8                       │
│ + kdf_params: KdfParams             │
│ + salt: [u8; 32]                    │
│ + nonce: [u8; 24]                   │
│ + payload_len: u64                  │
├─────────────────────────────────────┤
│ + serialize() → Vec<u8>             │
│ + deserialize(bytes) → Result<Self> │
└──────────────────┬──────────────────┘
                   │ contains
        ┌──────────▼────────────┐
        │       KdfParams       │
        ├───────────────────────┤
        │ + m_cost: u32         │
        │ + t_cost: u32         │
        │ + p_cost: u32         │
        └───────────────────────┘

┌─────────────────────────────────────┐
│           VaultEntry                │
├─────────────────────────────────────┤
│ + id: Uuid                          │
│ + service: String                   │
│ + username: String                  │
│ + password: SecretString            │  ← implements Zeroize
│ + notes: Option<String>             │
│ + totp: Option<SecretString>        │
│ + created: u64                      │
│ + modified: u64                     │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│           VaultData                 │
├─────────────────────────────────────┤
│ + version: u32                      │
│ + entries: Vec<VaultEntry>          │
├─────────────────────────────────────┤
│ + add_entry(entry) → Result         │
│ + get_entry(id) → Option<&Entry>    │
│ + delete_entry(id) → Result         │
│ + list_entries() → Vec<EntrySummary>│
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│           VaultKey                  │  ← Zeroized on Drop
├─────────────────────────────────────┤
│ - key_bytes: SecretVec<u8>          │  // 32 bytes
├─────────────────────────────────────┤
│ + derive(password, salt, params)    │
│   → Result<VaultKey>                │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│           CryptoEngine              │
├─────────────────────────────────────┤
│ (stateless — all methods static)    │
├─────────────────────────────────────┤
│ + encrypt(key, plaintext)           │
│   → Result<(nonce, ciphertext)>     │
│ + decrypt(key, nonce, ciphertext)   │
│   → Result<Vec<u8>>                 │
│ + generate_salt() → [u8; 32]        │
│ + generate_nonce() → [u8; 24]       │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│           VaultStore                │
├─────────────────────────────────────┤
│ + path: PathBuf                     │
├─────────────────────────────────────┤
│ + open(password) → Result<VaultData>│
│ + save(key, data) → Result<()>      │
│ + init(password, params) → Result   │
│   [atomic: write tmp → fsync →      │
│    rename]                          │
└─────────────────────────────────────┘
```

### 12.4 Sequence Diagram — Vault Unlock and Entry Add

```
User         CLI          VaultStore      CryptoEngine       KDF
 │            │                │               │              │
 │──unlock──▶│                │               │              │
 │            │──prompt pwd───▶│               │              │
 │──password─▶│               │               │              │
 │            │──open(pwd)───▶│               │              │
 │            │               │──read header──▶               │
 │            │               │──derive_key(pwd, salt, params)──▶│
 │            │               │               │◀──VaultKey────│
 │            │               │──decrypt(key, nonce, ct)──▶   │
 │            │               │◀──plaintext payload────────   │
 │            │               │──parse_entries()──▶           │
 │            │◀──VaultData───│               │              │
 │            │               │               │              │
 │──add entry─▶│              │               │              │
 │            │──add_entry()─▶│               │              │
 │            │               │──generate_nonce()─────────▶   │
 │            │               │◀──nonce(192-bit CSPRNG)──     │
 │            │               │──encrypt(key, new_pt)──────▶  │
 │            │               │◀──ciphertext──────────────    │
 │            │               │──atomic_write(tmp→rename)     │
 │            │◀──OK──────────│               │              │
 │            │               │──zeroize(key) │              │
 │            │               │──zeroize(plaintext)           │
```

### 12.5 State Diagram — Vault Lifecycle

```
         ┌──────────────┐
         │  UNINIT      │
         │ (no vault    │
         │  file)       │
         └──────┬───────┘
                │ nullwarden init
                ▼
         ┌──────────────┐
         │   LOCKED     │◀────────────────────────────┐
         │ (vault file  │                              │
         │  on disk,    │                              │
         │  encrypted)  │                              │
         └──────┬───────┘                             │
                │ unlock (master pwd)                  │
                ▼                                      │
         ┌──────────────┐    timeout / lock cmd        │
         │  UNLOCKED    │──────────────────────────────┘
         │ (key in RAM, │
         │  ops allowed)│
         └──────┬───────┘
                │ push / pull
                ▼
         ┌──────────────┐
         │   SYNCING    │
         │ (HTTP in     │
         │  progress)   │
         └──────┬───────┘
                │ success / conflict / error
                ▼
         ┌──────────────┐
         │  UNLOCKED    │ (back to unlocked, or conflict resolution)
         └──────────────┘
```

### 12.6 Database Entity Relationship Diagram

```
┌───────────────────────────────┐
│            users              │
├───────────────────────────────┤
│ PK  id              UUID      │
│     username        VARCHAR   │ UNIQUE NOT NULL
│     password_hash   VARCHAR   │ Argon2id hash of auth password
│     created_at      TIMESTAMPTZ│
│     updated_at      TIMESTAMPTZ│
└───────────────────┬───────────┘
                    │ 1
                    │
                    │ 1..*
┌───────────────────▼───────────┐
│            vaults             │
├───────────────────────────────┤
│ PK  id              UUID      │
│ FK  user_id         UUID      │ → users.id  NOT NULL
│     blob            BYTEA     │ Encrypted vault data (opaque)
│     version         BIGINT    │ Optimistic lock counter
│     size_bytes      BIGINT    │ Blob size
│     created_at      TIMESTAMPTZ│
│     updated_at      TIMESTAMPTZ│
└───────────────────────────────┘

┌───────────────────────────────┐
│        refresh_tokens         │
├───────────────────────────────┤
│ PK  id              UUID      │
│ FK  user_id         UUID      │ → users.id  NOT NULL
│     token_hash      VARCHAR   │ Argon2id hash of refresh token
│     expires_at      TIMESTAMPTZ│
│     revoked         BOOLEAN   │ DEFAULT false
│     created_at      TIMESTAMPTZ│
└───────────────────────────────┘

Constraints:
  - vaults.user_id: UNIQUE (one vault blob per user, prototype)
  - refresh_tokens: index on (token_hash, revoked, expires_at)
  - users: index on username (for login lookup)
```

---

## 13. Use Case Descriptions · System Architecture & Security Design

### 13.1 Use Case Descriptions

#### UC-01: Register Account

| Field | Value |
|-------|-------|
| **Use Case ID** | UC-01 |
| **Name** | Register Account |
| **Actor** | New User |
| **Precondition** | No account exists with the chosen username |
| **Trigger** | User runs `nullwarden register` |
| **Main Flow** | 1. User enters username and auth password (no echo, confirm). 2. CLI sends `POST /auth/register` with credentials. 3. Server hashes auth password with Argon2id. 4. Server stores user record. 5. CLI confirms success. |
| **Alternate Flow** | 3a. Username already taken → server returns 409 → CLI: "Username unavailable." |
| **Exception Flow** | 2a. Network unavailable → CLI: "Cannot reach server. Try again." |
| **Postcondition** | User account exists on server. No vault created yet. |
| **Security** | Auth password never transmitted plaintext (TLS). Auth hash ≠ vault key. |

#### UC-02: Initialize Local Vault

| Field | Value |
|-------|-------|
| **Use Case ID** | UC-02 |
| **Name** | Initialize Local Vault |
| **Actor** | Registered User |
| **Precondition** | No vault file exists at XDG data path |
| **Trigger** | User runs `nullwarden init` |
| **Main Flow** | 1. User enters master password (no echo, confirmed). 2. Password entropy checked (zxcvbn ≥ 3). 3. 32-byte CSPRNG salt generated. 4. Argon2id derives 256-bit vault key. 5. Empty payload encrypted with XChaCha20-Poly1305 + new nonce. 6. Vault header + ciphertext written atomically to disk. 7. Master password and key zeroized. |
| **Alternate Flow** | 2a. Entropy < 3 → CLI: "Password too weak. Choose a stronger password." → repeat. |
| **Exception Flow** | 6a. Disk write fails → temp file removed; error reported. |
| **Postcondition** | Vault file exists, encrypted, on disk. |

#### UC-03: Add Password Entry

| Field | Value |
|-------|-------|
| **Use Case ID** | UC-03 |
| **Name** | Add Password Entry |
| **Actor** | Authenticated User (vault unlocked) |
| **Precondition** | Vault file exists and is unlocked (or master password available) |
| **Trigger** | User runs `nullwarden add --service github.com` |
| **Main Flow** | 1. CLI prompts for service, username, password, optional notes. 2. UUID v4 generated for entry. 3. Vault decrypted (if not already). 4. Entry appended to VaultData. 5. Vault re-encrypted with new nonce. 6. Atomic write to disk. 7. Plaintext entry and key zeroized. |
| **Exception Flow** | 6a. Write fails → temp file cleaned up; original vault preserved. |
| **Postcondition** | New entry persisted in encrypted vault. Server not yet notified (requires explicit push). |

#### UC-04: Retrieve Password

| Field | Value |
|-------|-------|
| **Use Case ID** | UC-04 |
| **Name** | Retrieve Password |
| **Actor** | Authenticated User |
| **Trigger** | User runs `nullwarden get github.com` |
| **Main Flow** | 1. Vault decrypted. 2. Entry matching service name returned. 3. Password copied to clipboard (cleared after 30 s) or printed to stdout per `--print` flag. 4. Key and plaintext zeroized. |
| **Alternate Flow** | 3a. `--print` flag set → password written to stdout (user accepts risk). |
| **Exception Flow** | 2a. No matching entry → "Entry not found." |

#### UC-05: Sync Vault to Server (Push)

| Field | Value |
|-------|-------|
| **Use Case ID** | UC-05 |
| **Name** | Push Vault to Server |
| **Actor** | Authenticated User |
| **Trigger** | User runs `nullwarden push` |
| **Main Flow** | 1. CLI reads local vault file (encrypted blob, not decrypted). 2. CLI reads local version counter. 3. CLI sends `PUT /vault` with blob + expected_version + JWT. 4. Server checks version: if matches → updates blob, increments version → 200 OK. 5. CLI updates local version counter. |
| **Alternate Flow** | 4a. Version mismatch → server returns 409 Conflict → UC-07 (Conflict Resolution). |
| **Exception Flow** | 3a. JWT expired → CLI auto-refreshes token → retry. 3b. Network failure → retry with exponential backoff (3 attempts). |
| **Security** | Server never decrypts blob. Transport: TLS 1.3. |

#### UC-06: Sync Vault from Server (Pull)

| Field | Value |
|-------|-------|
| **Use Case ID** | UC-06 |
| **Name** | Pull Vault from Server |
| **Actor** | Authenticated User |
| **Trigger** | User runs `nullwarden pull` |
| **Main Flow** | 1. CLI sends `GET /vault` with JWT. 2. Server returns encrypted blob + version. 3. CLI validates AEAD integrity (decryption attempted with master password). 4. If valid, atomic write to disk. 5. Local version counter updated. |
| **Exception Flow** | 3a. AEAD decryption fails → "Vault integrity check failed. Server blob may be corrupted or tampered. Local vault preserved." |

#### UC-07: Conflict Resolution

| Field | Value |
|-------|-------|
| **Use Case ID** | UC-07 |
| **Name** | Sync Conflict Resolution |
| **Actor** | Authenticated User |
| **Trigger** | Push returns 409 Conflict |
| **Main Flow** | 1. CLI informs user: "Remote vault has changed since your last sync." 2. Presents three options: (a) Keep local — overwrite server with local version (forced push). (b) Keep remote — overwrite local with server version (pull). (c) Abort — no changes made. 3. User selects option. 4. Chosen action executed. |

### 13.2 System Architecture Design

#### Trust Boundary Architecture

```
═══════════════════════════════════════════════════════════════════
 TRUST ZONE: CLIENT (fully trusted by design)
 All cryptographic authority resides here exclusively.
 
 Key material:    Exists only in RAM, never persisted
 Plaintext vault: Exists only in RAM during operations
 Decryption:      Only possible here
═══════════════════════════════════════════════════════════════════
                              ↕  TLS 1.3
═══════════════════════════════════════════════════════════════════
 UNTRUSTED ZONE: SERVER (zero trust — treated as adversarial)
 
 What server knows:          username, Argon2id(auth_password)
 What server does NOT know:  master password, vault key, vault contents
 What server stores:         opaque encrypted bytes + version number
═══════════════════════════════════════════════════════════════════
```

#### Security Architecture — Key Derivation Flow

```
User Input: Master Password (UTF-8 string, never leaves client)
                    │
                    ▼
        ┌─────────────────────────────┐
        │     Argon2id KDF            │
        │  m = 65536 KB (64 MB RAM)   │
        │  t = 3 passes               │
        │  p = 4 lanes                │
        │  output_len = 32 bytes      │
        │  salt = vault_header.salt   │
        └──────────────┬──────────────┘
                       │
                       ▼
        ┌─────────────────────────────┐
        │      Vault Key (32 B)       │  ← VaultKey { key_bytes: SecretVec<u8> }
        │   implements Zeroize        │  ← Dropped immediately after use
        └──────────────┬──────────────┘
                       │
          ┌────────────▼──────────────┐
          │   XChaCha20-Poly1305      │
          │   nonce: 24-byte CSPRNG   │
          │   aad: vault header bytes │
          └────────────┬──────────────┘
                       │
                       ▼
              Ciphertext + Auth Tag
              (written to vault file)
```

#### Authentication Architecture (Server-Side)

```
Registration:
  auth_password → Argon2id(m=65536, t=3, p=4, salt=random_16B) → password_hash
  password_hash stored in DB. auth_password never stored.

Login:
  auth_password (from user) → Argon2id(same salt from DB) → candidate_hash
  constant_time_eq(candidate_hash, stored_hash) → bool
  
  If true:
    access_token  = JWT(sub=user_id, exp=now+15min, iat=now)
                    signed with HS256/RS256
    refresh_token = random_256bit_token
    refresh_hash  = Argon2id(refresh_token) → stored in DB
  
  Tokens returned to client.
  Refresh token: single-use rotation enforced.
```

#### API Endpoint Design

```
Base URL: https://api.nullwarden.io/v1

Authentication:
  POST   /auth/register      → { username, password } → 201 | 409
  POST   /auth/login         → { username, password } → 200 { access_token, refresh_token }
  POST   /auth/refresh       → Bearer refresh_token   → 200 { access_token, refresh_token }
  POST   /auth/logout        → Bearer access_token    → 204

Vault:
  PUT    /vault              → Bearer + { blob: bytes, expected_version: u64 }
                             → 200 { version: u64 } | 409 { current_version: u64 }
  GET    /vault              → Bearer → 200 { blob: bytes, version: u64 } | 404

Rate Limits:
  /auth/login:    5 req / 10 min / IP
  /auth/register: 3 req / hour / IP
  /vault PUT:     60 req / min / user
  /vault GET:     120 req / min / user

Headers required on all responses:
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Content-Security-Policy: default-src 'none'
```

---

## 14. Testing Strategy and Test Cases · Evaluation and Recommendations

### 14.1 Testing Strategy

The testing strategy is layered. Cryptographic correctness is verified first (unit), then component integration, then system-level behavior, then adversarial testing.

```
Layer         │ Scope                           │ Tool              │ Coverage target
──────────────┼─────────────────────────────────┼───────────────────┼────────────────
Unit          │ crypto primitives, vault format  │ Rust #[test]      │ ≥ 85% line cov
Integration   │ CLI + server round-trips         │ tokio-test + reqwest│ all FRs
End-to-End    │ full user flows (shell scripts)  │ bats / cargo test │ all use cases
Fuzz          │ deserialization, decrypt input   │ cargo-fuzz / AFL  │ 24h minimum run
Property      │ nonce uniqueness, encode/decode  │ proptest          │ 10k iterations
Benchmark     │ KDF timing, sync latency         │ criterion         │ blocking CI gate
Fault Inject  │ mid-write kills, corrupt blobs   │ custom harness    │ all failure modes
Security      │ dependency CVEs, static analysis │ cargo-audit, clippy│ zero findings
```

### 14.2 Unit Test Cases

#### UT-01: Vault Initialization

```
Test: test_vault_init_creates_valid_file
Setup: Temp directory, master password "correct-horse-battery-staple-42"
Steps:
  1. Call VaultStore::init(password, kdf_params, &tmp_path)
  2. Assert vault file created at path
  3. Read raw bytes — assert magic bytes = 0x4E574152
  4. Assert version byte = 0x01
  5. Assert salt length = 32 bytes
  6. Assert nonce length = 24 bytes
  7. Assert payload_len > 0
Expected: All assertions pass
```

#### UT-02: Round-Trip Encrypt/Decrypt

```
Test: test_encrypt_decrypt_roundtrip
Setup: Random 32-byte key, test plaintext "super secret vault payload"
Steps:
  1. nonce = CryptoEngine::generate_nonce()
  2. ct = CryptoEngine::encrypt(&key, &nonce, plaintext.as_bytes())
  3. pt = CryptoEngine::decrypt(&key, &nonce, &ct)
  4. Assert pt == plaintext.as_bytes()
Expected: Decrypted plaintext matches original
```

#### UT-03: AEAD Tamper Detection

```
Test: test_tamper_ciphertext_fails_auth
Setup: Valid ciphertext from UT-02
Steps:
  1. Flip bit 42 in ciphertext
  2. Attempt decrypt with same key + nonce
  3. Assert Err(DecryptionError::AuthenticationFailed)
Expected: Decryption fails — authentication tag rejected
```

#### UT-04: Argon2id Parameter Enforcement

```
Test: test_argon2_params_meet_minimum
Setup: Password "testpassword", random salt
Steps:
  1. Record wall-clock time T1
  2. Derive key with default KdfParams
  3. Record wall-clock time T2
  4. Assert (T2 - T1) >= 300ms
  5. Assert derived_key.len() == 32
Expected: KDF meets latency floor, key length correct
```

#### UT-05: Zeroize on Drop

```
Test: test_vault_key_zeroizes_on_drop
Setup: Known password + salt
Steps:
  1. Let key_ptr: *const u8;
  2. {
       let key = VaultKey::derive(&password, &salt, &params).unwrap();
       key_ptr = key.key_bytes.as_ptr();
     } // key dropped here
  3. Read 32 bytes from key_ptr (unsafe)
  4. Assert bytes == [0u8; 32]
Expected: Memory zeroized after drop
Note: This test requires unsafe and is marked #[cfg(test)] only
```

#### UT-06: Add and Retrieve Entry

```
Test: test_add_and_get_entry
Setup: Initialized vault, known master password
Steps:
  1. Open vault
  2. Add entry: { service: "github.com", username: "user", password: "pw123" }
  3. Save vault
  4. Reopen vault (re-derive key)
  5. Retrieve entry by service "github.com"
  6. Assert entry.username == "user"
  7. Assert entry.password == "pw123"
Expected: Entry survives re-encryption and re-derivation round-trip
```

#### UT-07: Vault Corruption Detection

```
Test: test_corrupted_vault_returns_error
Setup: Valid vault file
Steps:
  1. Read vault bytes
  2. Overwrite bytes [82..88] (start of ciphertext) with random bytes
  3. Write corrupted bytes back to file
  4. Attempt VaultStore::open(password, path)
  5. Assert Err(VaultError::IntegrityCheckFailed)
Expected: AEAD tag rejection; original file not modified
```

### 14.3 Integration Test Cases

#### IT-01: Registration → Login → Get Vault

```
Test: test_register_login_push_pull_full_flow
Setup: Test server instance (SQLite in test, Postgres in CI)
Steps:
  1. POST /auth/register { username: "alice", password: "testauth123!" } → 201
  2. POST /auth/login    { same creds }                                   → 200 + tokens
  3. PUT  /vault { blob: test_encrypted_bytes, expected_version: 0 }      → 200 { version: 1 }
  4. GET  /vault                                                           → 200 { blob, version: 1 }
  5. Assert downloaded blob == uploaded blob (byte-for-byte)
Expected: Full push/pull round-trip preserves exact blob bytes
```

#### IT-02: Version Conflict Detection

```
Test: test_concurrent_push_returns_conflict
Setup: Test server, registered user, vault at version 1
Steps:
  1. Device A: PUT /vault { blob: blob_a, expected_version: 1 } → 200 { version: 2 }
  2. Device B: PUT /vault { blob: blob_b, expected_version: 1 } → 409 { current_version: 2 }
Expected: Second push rejected; server version unchanged at 2; blob_a preserved
```

#### IT-03: Rate Limit Enforcement

```
Test: test_login_rate_limit
Setup: Test server
Steps:
  1. Send 6 POST /auth/login with invalid credentials from same IP
  2. Assert first 5 return 401
  3. Assert 6th returns 429 Too Many Requests
  4. Assert Retry-After header present
Expected: Rate limit triggers at 6th attempt
```

#### IT-04: Token Revocation After Logout

```
Test: test_access_token_revoked_after_logout
Setup: Logged-in user with valid access token
Steps:
  1. POST /auth/logout (with valid access token) → 204
  2. GET  /vault using same access token         → 401 Unauthorized
Expected: Token rejected after logout
```

#### IT-05: Atomic Write Survives Kill

```
Test: test_atomic_write_survives_kill_signal
Setup: Initialized vault, test harness
Steps:
  1. Spawn child process performing vault write
  2. SIGKILL child at a random point during write (10 attempts, random timing)
  3. For each: attempt to open vault
  4. Assert: either pre-write vault intact OR post-write vault intact — never a partial write
Expected: Original vault never in corrupted intermediate state
```

### 14.4 Fuzz Test Cases

#### FZ-01: Decrypt with Mutated Input

```
Harness: fuzz/fuzz_targets/decrypt_input.rs
Input: arbitrary bytes fed as ciphertext to CryptoEngine::decrypt
Goal: No panics, no undefined behavior. Only valid errors returned.
Run: cargo fuzz run decrypt_input -- -max_total_time=86400 (24h)
```

#### FZ-02: Vault Deserialization

```
Harness: fuzz/fuzz_targets/vault_deserialize.rs
Input: arbitrary bytes fed to VaultHeader::deserialize
Goal: No panics. All malformed inputs return Err. No stack overflow.
```

### 14.5 Security Test Cases

#### ST-01: Timing Attack on Login

```
Test: test_login_timing_is_constant
Setup: Test server, one valid user
Measure: 1000 login attempts with valid username + wrong password
         1000 login attempts with invalid username
Statistical test: Welch's t-test on timing distributions
Accept: p > 0.05 (no statistically significant timing difference)
Tool: Custom Rust harness + statistical library
```

#### ST-02: No Plaintext in Server Logs

```
Test: test_no_plaintext_in_server_logs
Setup: Full flow (register, login, push, pull)
Steps:
  1. Capture all server log output during flow
  2. Search for: test password, test vault plaintext, any known secret
  3. Assert: zero matches
```

#### ST-03: No Plaintext in Database

```
Test: test_no_plaintext_in_database
Setup: Registered user, pushed vault
Steps:
  1. Direct DB query: SELECT * FROM vaults
  2. Assert blob column contains AEAD ciphertext (first 4 bytes = magic 0x4E574152 when decrypted, but opaque as stored)
  3. Assert no column named: password, secret, key, plaintext
  4. Query all text columns in users: assert password_hash is Argon2 encoded string ($argon2id$...)
```

### 14.6 Evaluation and Recommendations

#### 14.6.1 Prototype Evaluation Criteria

| Criterion | Target | Evaluation Method |
|-----------|--------|------------------|
| Zero-knowledge guarantee holds | Server cannot decrypt any vault | Architecture review + pentest |
| KDF is computation-heavy enough | ≥ 300 ms derivation on reference HW | CI benchmark |
| AEAD nonce uniqueness | 0 reuse across 1M operations | Property test |
| Atomic writes prevent corruption | 0 corrupt vaults in fault injection | 100 kill-mid-write tests |
| Sync conflict detection is reliable | 100% conflicts detected | 1000 concurrent-push tests |
| Rate limiting is enforced | ≤ 5 auth req / 10 min / IP | Load test |
| No secrets in logs | 0 findings | Log audit |
| cargo audit clean | 0 critical/high CVEs | CI gate |

#### 14.6.2 Recommendations for v0.2+

**R1 — Adopt OPAQUE Protocol for Authentication**
Current: User sends auth password to server over TLS. If TLS is stripped or server is malicious, auth password is exposed.
Recommendation: Implement OPAQUE (RFC draft) for password-authenticated key exchange. The server never sees the auth password, even in transit. Libraries: `opaque-ke` crate.
Priority: HIGH — addresses the single remaining server-trust assumption.

**R2 — Migrate to ChaCha20-Poly1305 + HKDF for Key Separation**
Current: Single key derived from Argon2id used for all encryption.
Recommendation: Use HKDF to derive separate keys for different purposes (vault encryption key, MAC key, future key version upgrades) from the Argon2id master key.
Priority: MEDIUM — future-proofs key derivation architecture.

**R3 — Add TOTP/WebAuthn as Second Factor on Server Auth**
Priority: HIGH for production. Auth password alone is a single factor.

**R4 — Implement Server-Side Blob Signing**
Current: Version counter only. A compromised server could downgrade the version and return a stale blob.
Recommendation: Include a server-side HMAC (with a server key) over `user_id || version || blob_hash`. Client verifies signature before accepting blob.
Priority: MEDIUM.

**R5 — Release Process: Reproducible Builds**
All binaries must be reproducible (`cargo build --frozen` + pinned toolchain). Publish SHA-256 checksums and `minisign` signatures with every GitHub Release.
Priority: HIGH — supply chain security requirement.

**R6 — Plan for Argon2 Parameter Migration**
As hardware gets faster, Argon2 params will need to increase. The vault header stores current params, enabling in-place migration: re-derive key with new params → re-encrypt → rewrite vault header. Document and implement migration CLI command before v0.2.

**R7 — Memory-Locked Allocator**
For platforms supporting `mlock()`, use a memory-locked allocator for secret material. `memsec` or `secmem-proc` crate. Prevents swap and core dump exposure.
Priority: MEDIUM — accept residual on platforms without `mlock`.

---

## 15. Full Project File Structure

```
nullwarden/
├── Cargo.toml                        # Workspace root
├── Cargo.lock                        # Committed — deterministic builds
├── .cargo/
│   └── config.toml                   # Cross-compilation targets, build config
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                    # PR checks: lint, test, audit, coverage
│   │   ├── release.yml               # Tagged release: cross-compile, sign, publish
│   │   └── fuzz.yml                  # Scheduled 24h fuzz runs
│   └── SECURITY.md                   # Vulnerability disclosure policy
├── deny.toml                         # cargo-deny: license + advisory policy
├── rust-toolchain.toml               # Pinned toolchain version
├── .env.example                      # Server env var template (no secrets)
├── docker-compose.yml                # Local dev: server + postgres
├── Dockerfile                        # nullwarden-server production image
│
├── crates/
│   │
│   ├── nullwarden-core/              # Pure crypto library — no I/O, no network
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs                # Crate root — public API exports
│   │   │   ├── error.rs              # VaultError enum (thiserror)
│   │   │   ├── kdf.rs                # Argon2id key derivation + KdfParams
│   │   │   ├── crypto.rs             # XChaCha20-Poly1305 encrypt/decrypt
│   │   │   ├── vault/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── header.rs         # VaultHeader — binary layout serde
│   │   │   │   ├── data.rs           # VaultData, VaultEntry structs
│   │   │   │   ├── key.rs            # VaultKey — Zeroize wrapper
│   │   │   │   └── store.rs          # VaultStore — file I/O + atomic write
│   │   │   └── types.rs              # SecretString, SecretBytes newtypes
│   │   ├── tests/
│   │   │   ├── crypto_roundtrip.rs   # UT-02, UT-03
│   │   │   ├── kdf_params.rs         # UT-04
│   │   │   ├── vault_lifecycle.rs    # UT-01, UT-06, UT-07
│   │   │   ├── zeroize.rs            # UT-05 (unsafe, cfg(test))
│   │   │   └── atomic_write.rs       # UT fault injection
│   │   └── benches/
│   │       ├── kdf_bench.rs          # criterion: Argon2id timing gate
│   │       └── encrypt_bench.rs      # criterion: throughput
│   │
│   ├── nullwarden-cli/               # CLI binary
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── main.rs               # clap App, command dispatch
│   │   │   ├── commands/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── init.rs           # `nullwarden init`
│   │   │   │   ├── add.rs            # `nullwarden add`
│   │   │   │   ├── get.rs            # `nullwarden get`
│   │   │   │   ├── list.rs           # `nullwarden list`
│   │   │   │   ├── delete.rs         # `nullwarden delete`
│   │   │   │   ├── push.rs           # `nullwarden push`
│   │   │   │   ├── pull.rs           # `nullwarden pull`
│   │   │   │   ├── lock.rs           # `nullwarden lock`
│   │   │   │   └── register.rs       # `nullwarden register`
│   │   │   ├── client/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── auth.rs           # HTTP auth client (reqwest)
│   │   │   │   └── sync.rs           # push/pull HTTP client
│   │   │   ├── config.rs             # TOML config (server URL, vault path)
│   │   │   ├── session.rs            # Token storage (OS keyring / file)
│   │   │   ├── input.rs              # rpassword wrappers, zxcvbn check
│   │   │   └── error.rs              # CliError enum
│   │   └── tests/
│   │       ├── e2e_init.rs           # E2E-01
│   │       ├── e2e_add_get.rs        # E2E-02, E2E-03
│   │       └── e2e_sync.rs           # E2E push/pull flow
│   │
│   ├── nullwarden-server/            # Axum REST API
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── main.rs               # Server startup, tracing init
│   │   │   ├── app.rs                # Axum router construction
│   │   │   ├── config.rs             # Environment config (envy)
│   │   │   ├── db/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── pool.rs           # sqlx PgPool init
│   │   │   │   ├── users.rs          # User CRUD
│   │   │   │   └── vaults.rs         # Vault blob CRUD + version
│   │   │   ├── handlers/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── auth.rs           # register, login, refresh, logout
│   │   │   │   └── vault.rs          # PUT /vault, GET /vault
│   │   │   ├── middleware/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── auth.rs           # JWT extraction + validation
│   │   │   │   ├── rate_limit.rs     # tower-governor config
│   │   │   │   └── request_id.rs     # UUID per request
│   │   │   ├── auth/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── password.rs       # Argon2id hash + verify
│   │   │   │   ├── jwt.rs            # JWT issue + validate
│   │   │   │   └── token.rs          # Refresh token management
│   │   │   └── error.rs              # AppError → HTTP response mapping
│   │   ├── migrations/
│   │   │   ├── 20260101_create_users.sql
│   │   │   ├── 20260102_create_vaults.sql
│   │   │   └── 20260103_create_refresh_tokens.sql
│   │   └── tests/
│   │       ├── auth_integration.rs   # IT-01 through IT-04
│   │       ├── vault_integration.rs  # IT-05, IT-06
│   │       ├── conflict_test.rs      # IT-02 concurrent push
│   │       └── rate_limit_test.rs    # IT-03
│   │
│   └── nullwarden-fuzz/              # Fuzz targets (cargo-fuzz)
│       ├── Cargo.toml
│       └── fuzz_targets/
│           ├── decrypt_input.rs      # FZ-01
│           └── vault_deserialize.rs  # FZ-02
│
├── docs/
│   ├── vault-format-spec.md          # RFC-style binary format spec
│   ├── security-design.md            # Crypto rationale, threat model
│   ├── threat-model.md               # STRIDE analysis, attack trees
│   ├── api-reference.yaml            # OpenAPI 3.1 spec
│   ├── cli-manual.md                 # User manual for CLI
│   ├── deployment-guide.md           # Operator runbook
│   └── adr/
│       ├── 001-xchacha20-poly1305.md # Why XChaCha20 over AES-GCM
│       ├── 002-argon2id-params.md    # KDF parameter rationale
│       ├── 003-rust-core.md          # Why Rust for core library
│       ├── 004-axum-server.md        # Server framework choice
│       └── 005-no-recovery.md        # Why no password recovery
│
└── scripts/
    ├── build-release.sh              # Cross-compile all targets
    ├── sign-release.sh               # minisign signing automation
    ├── run-fuzz.sh                   # Fuzz harness launcher
    └── db-migrate.sh                 # sqlx migrate run wrapper
```

### 15.1 Critical Dependency List

```toml
# nullwarden-core/Cargo.toml

[dependencies]
argon2        = "0.5"           # Argon2id KDF — maintained, audited
chacha20poly1305 = "0.10"       # XChaCha20-Poly1305 AEAD — RustCrypto
zeroize       = { version = "1.7", features = ["derive"] }
rand          = "0.8"           # CSPRNG — OsRng
rmp-serde     = "1.1"           # MessagePack serialization
serde         = { version = "1", features = ["derive"] }
uuid          = { version = "1", features = ["v4"] }
thiserror     = "1"

# nullwarden-cli/Cargo.toml
clap          = { version = "4", features = ["derive"] }
rpassword     = "7"             # Secure terminal password input
zxcvbn        = "3"             # Password strength estimation
reqwest       = { version = "0.11", features = ["rustls-tls", "json"] }
tokio         = { version = "1", features = ["full"] }
toml          = "0.8"
dirs          = "5"             # XDG base directories

# nullwarden-server/Cargo.toml
axum          = "0.7"
tokio         = { version = "1", features = ["full"] }
sqlx          = { version = "0.7", features = ["postgres", "runtime-tokio-rustls", "uuid"] }
argon2        = "0.5"
jsonwebtoken  = "9"
tower-governor = "0.3"          # Rate limiting
tracing       = "0.1"
tracing-subscriber = "0.3"
constant_time_eq = "0.3"        # Timing-safe comparison
envy          = "0.4"           # Env var config
thiserror     = "1"
uuid          = { version = "1", features = ["v4"] }
```

### 15.2 Environment Variables (.env.example)

```bash
# nullwarden-server — REQUIRED

# Database
DATABASE_URL=postgres://nullwarden:password@localhost:5432/nullwarden

# JWT signing key — generate: openssl rand -hex 32
JWT_SECRET=CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32

# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=8080

# Rate limiting (requests / window_seconds / ip)
RATE_LIMIT_AUTH_REQUESTS=5
RATE_LIMIT_AUTH_WINDOW_SECS=600

# Token lifetimes
JWT_ACCESS_EXPIRE_SECS=900      # 15 min
JWT_REFRESH_EXPIRE_DAYS=7

# Argon2 params for auth password hashing (server-side)
AUTH_ARGON2_M_COST=65536
AUTH_ARGON2_T_COST=3
AUTH_ARGON2_P_COST=4

# TLS (production)
TLS_CERT_PATH=/etc/nullwarden/tls/cert.pem
TLS_KEY_PATH=/etc/nullwarden/tls/key.pem
```

---

## Appendix A — Architecture Decision Records (ADR Index)

| ADR | Decision | Rationale |
|-----|----------|-----------|
| ADR-001 | XChaCha20-Poly1305 over AES-256-GCM | 192-bit nonce eliminates nonce collision risk at scale. No hardware acceleration required on all targets. Resistant to timing side-channels on software implementations. Widely audited (libsodium lineage). |
| ADR-002 | Argon2id over bcrypt/scrypt | Argon2id is memory-hard and time-hard simultaneously. Winner of the Password Hashing Competition 2015. Tunable m/t/p. scrypt has no official test vectors and parameter complexity is higher. bcrypt is limited to 72-byte passwords and has no memory hardness. |
| ADR-003 | Rust for core library | Memory safety without garbage collector. Ownership enforces single-use of secrets. `zeroize` crate composes naturally with Drop. Zero-cost abstractions enable constant-time code. Static binary output — no runtime dependency. |
| ADR-004 | Axum for server | Type-safe routing, tower middleware ecosystem (rate limiting, tracing, timeouts). Async-first with Tokio. Strong community, actively maintained. Compatible with `axum-test` for integration testing without spawning process. |
| ADR-005 | No password recovery | Zero-knowledge guarantee is architecturally incompatible with server-assisted recovery. Recovery requires key escrow, which gives the server decryption capability. Out of scope by design. |
| ADR-006 | MessagePack over JSON for payload | Binary encoding — smaller payload size, faster parse. No floating-point ambiguity. serde + rmp-serde → same derive macros as JSON but ~30% smaller in practice for vault entry maps. |
| ADR-007 | Stateless JWT over server sessions | Server remains stateless — horizontal scaling without shared session store. Refresh token rotation provides revocation. Short access token lifetime (15 min) limits blast radius of token theft. |

---

## Appendix B — Vault Format Version Compatibility Policy

| Version | KDF | Cipher | Notes |
|---------|-----|--------|-------|
| 0x01 | Argon2id | XChaCha20-Poly1305 | Initial format |
| 0x02 | Argon2id (updated params) | XChaCha20-Poly1305 | Parameter migration via `nullwarden migrate` |
| 0xFF | Reserved | — | Experimental / pre-release |

Migration procedure: `nullwarden migrate` command reads vault at version N, decrypts with old params, re-derives key with new params, re-encrypts, writes new header with updated version byte. Atomic write — no data loss on failure.

---

*NullWarden Project Documentation v1.0*  
*Classification: Internal Engineering*  
*Generated: 2026-04-15*  
*Next review: Upon M1 milestone (Week 4)*
# nullwarden
