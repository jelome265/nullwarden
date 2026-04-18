# ADR-004: Axum for Synchronization Server

## Status
Accepted

## Context
The synchronization server needs to handle concurrent connections efficiently, provide a type-safe API, and support various middleware (rate limiting, tracing, security headers).

## Decision
We chose Axum.

## Rationale
- **Type-Safety:** Leverages Axum's extractor pattern for type-safe request parsing and state management.
- **Ecosystem:** Compatible with the broad Tower/Tower-HTTP middleware ecosystem.
- **Async First:** Built on top of Tokio, the industry-standard async runtime for Rust.
- **Ease of Testing:** Supports in-memory testing of routers without requiring a network socket.

## Consequences
- Requires understanding of the Tower ecosystem and complex trait bounds.
