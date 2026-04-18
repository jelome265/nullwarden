# ADR-005: No Password Recovery

## Status
Accepted

## Context
Traditional systems offer "forgot password" flows. However, such flows usually rely on the server having the ability to reset or bypass existing keys.

## Decision
We decided NOT to implement any form of password recovery.

## Rationale
- **Zero-Knowledge Guarantee:** The entire security model rests on the server never having access to decryption keys. Recovery mechanisms almost always involve key escrow, which would violate this guarantee.
- **Architectural Simplicity:** Eliminates the complexity and attack surface of a recovery system.
- **User Responsibility:** Users are clearly informed that losing the master password means permanent loss of vault data, aligning expectations with the security model.

## Consequences
- Data is irrecoverable if the master password is forgotten.
- Requires robust UI/UX to warn users about this during setup.
