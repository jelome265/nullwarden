Project Description

A zero-knowledge password vault with cloud sync is a system in which users store passwords inside an encrypted vault. The vault is synchronized across devices through a server, but the server never stores plaintext passwords or encryption keys. Encryption and decryption happen only on the user’s device using a master password. This means that even if the server or database is breached, the attacker only obtains encrypted data that should be computationally impractical to decrypt without the correct password and key derivation parameters.

1) Identify Problems This Project Addressed

This project exists to solve a set of real operational and security problems that traditional password storage approaches fail to handle properly.

1.1 Password loss due to device failure or replacement

Local-only password storage is fragile. If a device is lost, stolen, formatted, or damaged, all locally stored credentials can be lost as well. Users often keep passwords in notes, browsers, spreadsheets, or plaintext files, which are not designed for durability or recovery.

Problem impact
Permanent loss of credentials
Account lockout across multiple services
Operational downtime for the user
Support burden for account recovery
Why this project matters

Cloud sync ensures that encrypted data is not tied to one physical machine. The vault can be restored on a new device if the user knows the master password.

1.2 Unsafe password storage habits

Many users reuse passwords or store them in insecure locations because secure alternatives are inconvenient or hard to manage.

Typical bad practices
Plaintext .txt files
Browser-saved passwords without central control
Notes apps
Reused credentials across services
Weak passwords chosen for memorability
Problem impact
Credential stuffing exposure
Breach amplification across accounts
Easy theft by malware or local attackers
Why this project matters

A password vault gives users one secure place to store many unique passwords, reducing password reuse and human memory pressure.

1.3 Overtrust in servers and cloud providers

Many storage systems assume the server is trusted. That is a poor assumption for security-critical data.

Problem impact
Server compromise exposes sensitive data
Malicious admin access can leak user secrets
Misconfigured backups can expose plaintext
Database snapshots may be accessible outside intended boundaries
Why this project matters

Zero-knowledge architecture ensures the server is only a ciphertext store. Even if the backend is breached, the attacker should not gain usable passwords.

1.4 Lack of confidentiality in sync systems

Cloud sync is convenient, but ordinary sync platforms often rely on server-side access to make indexing, search, and password recovery easier. That breaks confidentiality.

Problem impact
Passwords visible to backend operators
Metadata leakage
Weak access boundaries
Increased legal and compliance exposure
Why this project matters

The system must support sync without sacrificing secrecy. That forces encryption to happen before upload and decryption to happen only after download on the client.

1.5 Tampering and silent corruption

If data integrity is not protected, a malicious actor or corrupted storage layer can alter the vault without detection.

Problem impact
Modified secrets
Broken vault structure
Silent corruption leading to data loss
Potential logic abuse if malformed vaults are accepted
Why this project matters

Authenticated encryption and integrity checks ensure modified vault data fails closed rather than opening incorrectly.

1.6 Weak cryptographic design in DIY solutions

Users and junior developers often build “encrypted storage” with poor primitives, wrong modes, or no key derivation.

Common mistakes
Reusing IVs/nonces
Encrypting without authentication
Storing encryption keys next to data
Using weak hashes instead of KDFs
Hardcoding keys or salts
Problem impact
Crypto that looks secure but is not secure
Offline cracking becomes trivial
Tampering goes undetected
Why this project matters

It forces a proper architecture: strong KDF, authenticated encryption, local decryption, and server-side blindness.

1.7 Lack of portable secure access

Passwords should be available across devices, but not through insecure replication or plaintext synchronization.

Problem impact
Users sacrifice security for convenience
Manual backup is error-prone
Device migration becomes painful
Why this project matters

The system provides portability while preserving the security boundary.

1) Aims and SMART Objectives
2.1 Overall Aim

Design and implement a secure, zero-knowledge password vault that allows users to store, retrieve, and synchronize credentials across devices while ensuring the server never gains access to plaintext secrets or encryption keys.

2.2 SMART Objectives
Objective 1: Implement client-side encryption for all vault contents
Specific: Encrypt all vault records before any upload.
Measurable: 100% of stored vault payloads must be encrypted.
Achievable: Use authenticated encryption libraries in the client.
Relevant: Core zero-knowledge guarantee.
Time-bound: Completed in the initial core implementation phase.
Objective 2: Prevent server-side access to secrets
Specific: Ensure the backend stores only ciphertext and non-sensitive metadata.
Measurable: No plaintext password, master key, or derived encryption key exists in server storage, logs, or responses.
Achievable: Use a client-only decryption model.
Relevant: Defines the security model.
Time-bound: Enforced before deployment.
Objective 3: Support secure account access across multiple devices
Specific: Allow a user to retrieve the same encrypted vault on a new device.
Measurable: Vault can be opened on a second device using the same credentials and master password.
Achievable: Store encrypted vault blobs in a sync backend.
Relevant: Solves device-loss and portability issues.
Time-bound: Implemented in the sync release.
Objective 4: Use a strong key derivation function
Specific: Derive keys from the user’s master password using a modern KDF.
Measurable: Each unlock operation must run through a configurable, high-cost KDF such as Argon2id.
Achievable: Cryptographic libraries support this directly.
Relevant: Protects against offline brute force.
Time-bound: Mandatory from the first secure version.
Objective 5: Ensure tamper detection and safe failure
Specific: Reject any modified or corrupted vault blob.
Measurable: Tampered data must fail decryption or integrity verification.
Achievable: Use AEAD and explicit versioning.
Relevant: Prevents silent corruption and malicious modification.
Time-bound: Validated during testing and release preparation.
3) Scope
3.1 In Scope
User account and vault access
User registration
User login
Secure authentication flow
Vault unlock using master password
Client-side security functions
Master password handling
Key derivation
Encryption and decryption
Zeroization of sensitive memory where practical
Secure clipboard or display behavior if secrets are shown
Vault operations
Create vault
Add credential entries
View credential entries
Update credential entries
Delete credential entries
Export/import encrypted vault blobs
Sync capabilities
Upload encrypted vault blob to server
Download encrypted vault blob from server
Restore vault on a new device
Basic conflict detection
Backend responsibilities
User identity management
Authentication token issuance
Secure storage of encrypted vault blobs
Version tracking for sync
Access control and request validation
Security controls
Authenticated encryption
Tamper detection
Strong password hashing for login
Secure handling of tokens
Logging without secret leakage
3.2 Out of Scope
Not included in the initial version
Server-side decryption
Password recovery by administrators
Sharing vault entries with other users
Team or enterprise access control
Browser autofill extensions
Mobile biometric unlock
Contact sync or file storage
Full-text server-side search across vault contents
Collaboration features
Real-time multi-editor conflict merging
Why these are out of scope

These features expand the attack surface, complicate the trust model, and require additional security and consistency controls that are not necessary for a secure first version.

1) Risks, Mitigations, and Failure Modes

This section should be read as a practical engineering risk analysis, not a generic list.

4.1 Server compromise
Failure mode

An attacker gains access to the database or application server.

What happens
Encrypted vault blobs may be stolen
Metadata may be exposed
User account records may be used for offline attacks
Mitigations
Store only encrypted blobs
Never store encryption keys or plaintext vault contents
Hash login passwords with Argon2id or equivalent
Minimize metadata exposure
Separate auth data from vault data
Use least-privilege database access
Residual risk

Offline brute force remains possible if the user chose a weak master password.

4.2 Weak master password
Failure mode

The user chooses a low-entropy password.

What happens

An attacker with the encrypted vault blob can perform offline cracking.

Mitigations
Enforce password strength rules
Use a memory-hard KDF with strong parameters
Provide password strength feedback
Encourage long passphrases
Rate-limit login attempts on the auth system, even though the real risk is offline
Residual risk

No KDF fully saves a terrible password.

4.3 Reuse of login password and vault master password
Failure mode

The same password is used for both backend login and vault encryption.

What happens

A compromise in one layer weakens the other.

If login hashes leak, offline cracking may also reveal the vault key.
If vault access logic and auth logic are coupled, the model becomes brittle.
Mitigations
Separate authentication password from vault encryption key material
Use distinct salts and derivation contexts
Consider independent keys for login and vault encryption
Residual risk

User confusion and implementation mistakes if the UX is not clear.

4.4 Sync conflict between devices
Failure mode

Two devices modify the vault independently and upload different versions.

What happens
Last write may overwrite a newer change
Some credentials may disappear
User may see stale entries
Mitigations
Version numbers
Update timestamps
Conflict detection rules
Explicit user resolution for conflicting updates
Optional per-entry merge later, but that is complex
Residual risk

True multi-device concurrent editing is hard and can still cause data loss if conflict handling is weak.

4.5 Replay or rollback attack
Failure mode

Server returns an older encrypted version of the vault.

What happens

The user may unknowingly re-open stale data.

Mitigations
Include version counters
Store last-known version locally
Detect rollback attempts
Alert the user when server state regresses
Residual risk

If the client has no trusted reference for freshness, rollback detection is limited.

4.6 Tampered vault blob
Failure mode

Data is modified in transit or at rest.

What happens
Corruption may break decryption
Malicious alterations may attempt logic abuse
Mitigations
Use authenticated encryption
Verify tag before processing data
Fail closed on any integrity failure
Residual risk

If the implementation decrypts before verifying integrity, the design is broken.

4.7 Client compromise
Failure mode

Malware or a local attacker gains access to the user’s unlocked session.

What happens
Decrypted secrets may be read from memory, screen, clipboard, or logs
Mitigations
Minimize the plaintext lifetime
Zeroize sensitive buffers
Avoid logging secrets
Use secure clipboard timeout if clipboard is supported
Lock vault after inactivity
Residual risk

A compromised client can still steal data while the vault is unlocked. Zero-knowledge does not protect against a fully compromised endpoint.

4.8 Bad dependency or supply-chain compromise
Failure mode

A third-party package is vulnerable or malicious.

What happens
Secret leakage
Build compromise
Dependency drift
Hidden backdoors
Mitigations
Pin dependency versions
Review transitive dependencies
Use lockfiles
Run vulnerability scans
Keep the dependency count low
Residual risk

All software supply chains are attack surfaces.

4.9 Crash during write
Failure mode

The app crashes while saving the vault.

What happens
Partial writes may corrupt the vault file or blob
User may lose changes
Mitigations
Atomic write strategy
Write to temporary file first
Fsync before rename
Keep previous valid version until new write succeeds
Residual risk

Disk or filesystem failure can still cause data loss.

4.10 Metadata leakage
Failure mode

Unencrypted metadata reveals too much.

What happens

Even if passwords stay encrypted, attackers may infer service names, entry counts, timestamps, or usage patterns.

Mitigations
Encrypt the full vault payload
Minimize exposed metadata
Avoid unnecessary server-visible fields
Residual risk

Some metadata may still be visible for sync and auth purposes.

1) Deliverables Summary
Core deliverables
Client application
CLI for login, vault access, and credential management
Crypto engine
KDF
Encryption/decryption
Authentication tag handling
Memory hygiene helpers
Sync backend
User authentication
Storage of encrypted vault blobs
Version tracking
Secure API endpoints
Database schema
User accounts
Encrypted vault records
Sync metadata
Vault format specification
File/blob structure
Versioning rules
Encoding and parsing rules
Test suite
Unit tests
Integration tests
Tamper tests
Recovery tests
Sync conflict tests
Security documentation
Threat model
Assumptions
Attack boundaries
Failure handling rules
Deployment/build artifacts
Release builds
Docker image or deployment manifest if applicable
Signed binaries if supported
2) Requirements Specification
6.1 System overview

The system shall provide a zero-knowledge password vault that allows users to store, retrieve, and synchronize credentials securely across devices. The backend shall only store encrypted vault data and shall not have access to plaintext passwords or vault keys. The client shall perform all encryption and decryption locally.

6.2 High-level constraints
The server must be untrusted with respect to user secrets.
Decryption must occur only on the client.
The vault must remain recoverable across devices.
Tampered or corrupted data must fail closed.
The system should remain usable through a CLI interface.
6.3 Security assumptions
The master password is not known to the server.
The server may be compromised.
The database may be breached.
The client device is not assumed to be secure when actively compromised.
Offline brute-force is the primary post-breach threat.
7) Functional Requirements (FR)

Below is a more detailed functional requirement set.

FR1: User registration

The system shall allow a new user to create an account using valid registration credentials.

Why it matters

This establishes identity for sync and access control.

FR2: User authentication

The system shall verify a user’s login credentials and issue a valid session token or equivalent authenticated session.

Why it matters

Without authentication, the sync backend cannot distinguish legitimate users.

FR3: Vault creation

The system shall create a new encrypted vault for a registered user.

Why it matters

This is the starting point for secure storage.

FR4: Vault unlock

The system shall derive a local encryption key from the user’s master password and decrypt the vault on the client device.

Why it matters

The vault contents must be accessible only locally.

FR5: Add credential entry

The system shall allow users to add a credential entry containing at least service name, username, and password.

Why it matters

This is the core purpose of the vault.

FR6: View credential entry

The system shall allow users to retrieve and display stored credentials after successful vault unlock.

Why it matters

Users must be able to use the saved credentials.

FR7: Update credential entry

The system shall allow users to edit existing entries and re-encrypt the updated vault state.

Why it matters

Passwords change over time.

FR8: Delete credential entry

The system shall allow users to delete stored entries.

Why it matters

Users must be able to remove outdated or compromised credentials.

FR9: Encrypt before upload

The system shall encrypt vault data locally before sending it to the backend.

Why it matters

This is the zero-knowledge guarantee.

FR10: Download encrypted vault

The system shall retrieve encrypted vault data from the backend for authorized users.

Why it matters

This enables sync and restoration.

FR11: Sync vault across devices

The system shall allow a user to access the same encrypted vault from multiple devices.

Why it matters

This is the key benefit of cloud sync.

FR12: Detect version conflict

The system shall detect when a stored vault version differs from the client’s current version.

Why it matters

This prevents silent overwrite and data loss.

FR13: Detect tampering

The system shall reject any vault data that fails integrity verification.

Why it matters

Modified data must not be trusted.

FR14: Secure password entry

The system shall accept passwords without exposing them in terminal echo, logs, or command-line history.

Why it matters

This reduces local disclosure risk.

FR15: Logout and session invalidation

The system shall invalidate the current session when the user logs out.

Why it matters

This limits token abuse if a session is stolen.

FR16: Error handling without leakage

The system shall report errors without revealing sensitive contents or cryptographic secrets.

Why it matters

Error messages often leak more than data paths do.

1) Non-Functional Requirements (NFR)
NFR1: Confidentiality

No plaintext vault data, passwords, or encryption keys shall be stored on the backend.

NFR2: Integrity

All vault data shall be protected against unauthorized modification using authenticated encryption or an equivalent integrity mechanism.

NFR3: Availability

The system shall permit vault restoration from any authorized device with the correct credentials.

NFR4: Usability

The CLI shall provide clear commands for common vault operations without requiring users to understand internal cryptographic details.

NFR5: Performance

Vault unlock, encryption, and sync operations shall complete within acceptable time for interactive CLI use.

Practical implication

The KDF should be intentionally expensive, but not unusably slow.

NFR6: Reliability

The system shall avoid data loss during normal operations and shall use crash-safe write behavior where applicable.

NFR7: Portability

The client shall run on supported desktop platforms such as Windows and Linux.

NFR8: Maintainability

The codebase shall separate crypto logic, storage logic, auth logic, and CLI logic into distinct modules or crates.

NFR9: Auditability

Security-critical decisions, dependencies, and data formats shall be documented well enough to support review.

NFR10: Scalability

The backend shall support multiple users and many encrypted vault blobs without requiring vault decryption on the server.

NFR11: Observability without leakage

Logging, metrics, and diagnostics shall not expose secrets or plaintext vault data.

NFR12: Compatibility

The vault format shall be versioned so future clients can detect and handle supported formats safely.

NFR13: Security of secret handling

Sensitive in-memory data shall be minimized and cleared when no longer needed where feasible.

1) Requirements Traceability

Requirements traceability links each requirement to design, implementation, and verification. This is what stops the spec from being decorative nonsense.

ID Requirement Design/Component Verification Method
FR1 User registration Auth backend API tests, registration tests
FR2 User authentication Auth backend Login tests, token validation tests
FR3 Vault creation Client + core crypto Unit and integration tests
FR4 Vault unlock Client crypto module Decryption tests, negative password tests
FR5 Add credential entry Vault data model CRUD tests
FR6 View credential entry Client CLI End-to-end tests
FR7 Update credential entry Vault update flow Update and persistence tests
FR8 Delete credential entry Vault mutation logic Deletion tests
FR9 Encrypt before upload Client sync layer Packet inspection / integration tests
FR10 Download encrypted vault Sync backend API integration tests
FR11 Cross-device sync Backend + client Multi-device integration tests
FR12 Conflict detection Sync/version logic Conflict simulation tests
FR13 Tamper detection AEAD / integrity logic Corruption and replay tests
FR14 Secure password entry CLI input handling Manual validation and UI tests
FR15 Logout/session invalidation Auth/session layer Session expiry tests
FR16 Safe error handling All layers Negative tests and log review
NFR1 No server plaintext Backend architecture Security review, DB inspection
NFR2 Integrity protection Crypto layer Cryptographic tests and code review
NFR3 Availability via restore Sync and client restore flow Recovery tests
NFR4 CLI usability CLI design Usability testing
NFR5 Performance KDF and sync path Benchmarks
NFR6 Reliability Storage/write path Crash simulation
NFR7 Portability Build pipeline Cross-platform builds
NFR8 Maintainability Project structure Architecture review
NFR9 Auditability Docs and code structure Documentation review
NFR10 Backend scalability Stateless API + DB design Load tests
NFR11 Observability without leakage Logging subsystem Log review and red-team tests
NFR12 Format compatibility Versioned vault spec Migration and compatibility tests
NFR13 Secret handling Memory lifecycle Code review, inspection
What this means in practice

The most important idea in this project is simple:

The server is storage, not trust.

That single rule drives the entire architecture, the threat model, and every requirement.

Advantages
Strong confidentiality model.
Good recovery across devices.
Server breach does not directly expose plaintext secrets.
Clear separation of concerns between client, backend, and storage.
Disadvantages
More complex than local-only storage.
Sync conflicts must be handled carefully.
Weak passwords still create offline brute-force risk.
Client compromise can still expose decrypted data.
