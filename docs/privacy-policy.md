# NullWarden Privacy Policy

## Vault History Retention

NullWarden stores the current encrypted vault blob and a short encrypted history for recovery from sync conflicts.

- Vault history is retained for up to 30 days by default.
- Vault history is capped to the 3 most recent prior versions per user.
- Users can purge retained history through the authenticated `DELETE /vault/history` endpoint.
- Vault history is removed when the associated account is deleted.

## Zero-Knowledge Boundary

- The server stores opaque encrypted blobs only.
- The server does not receive master passwords or vault encryption keys.
- All vault encryption and decryption occurs client-side.
