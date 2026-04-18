# ADR-003: Rust for Core Library and CLI

## Status
Accepted

## Context
The core cryptographic logic and the user-facing CLI require high performance, strict memory safety, and easy distribution as static binaries.

## Decision
We chose Rust.

## Rationale
- **Memory Safety:** Prevents entire classes of vulnerabilities (buffer overflows, use-after-free) without requiring a garbage collector.
- **Ownership Model:** Enforces strict control over secret material and ensures zeroization can be performed reliably via the `Drop` trait.
- **Performance:** C/C++ level performance with zero-cost abstractions.
- **Tooling:** Excellent package management (Cargo) and ecosystem for cryptography (RustCrypto).

## Consequences
- Steep learning curve for new contributors.
- Slow compilation times compared to some other languages.
