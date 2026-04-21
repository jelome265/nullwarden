# Privacy Policy

NullWarden is a self-hosted password vault system.

## Data Collected

- Usernames for account identification.
- Server-side authentication password hashes.
- Encrypted vault blobs.
- Refresh-token hashes and token-blocklist hashes for session management.

## Data Not Collected

- Master passwords.
- Vault encryption keys.
- Decrypted vault contents.
- Telemetry, analytics, or usage tracking.

## Storage

- The server stores only encrypted vault blobs and authentication/session material.
- The CLI may store session tokens in the OS keyring or, as a fallback, in local session files.

## Retention

- Access tokens are short-lived.
- Refresh tokens expire automatically.
- Expired session records should be cleaned up by the server background cleanup task.
- Vault data and accounts are retained until deleted by the operator or user deletion endpoint.

## User Rights

- Users can delete their account through the authenticated `DELETE /auth/user` endpoint.
- Deleting a user cascades to stored vault blobs and refresh-token records.

## Third Parties

NullWarden does not transmit vault data to third-party analytics or advertising systems.
