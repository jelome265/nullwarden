# Deployment Guide

## Prerequisites
- PostgreSQL 16+ or Supabase.
- TLS certificates (PEM format).
- Rust toolchain (for building from source) or Docker.

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | REQUIRED |
| `JWT_SECRET` | Signing key for session tokens | REQUIRED |
| `SERVER_HOST` | Interface to bind to | `0.0.0.0` |
| `SERVER_PORT` | Port to listen on | `8080` |
| `JWT_ISSUER` | JWT issuer claim value | `nullwarden-server` |
| `JWT_AUDIENCE` | JWT audience claim value | `nullwarden-cli` |
| `DB_MAX_CONNECTIONS` | PostgreSQL pool size | `10` |
| `CLEANUP_INTERVAL_SECS` | Background cleanup interval for expired tokens/blocklist rows | `3600` |
| `TLS_CERT_PATH` | Path to TLS certificate | None |
| TLS_KEY_PATH | Path to TLS private key | None |

### Supabase Configuration
- **Connection String:** Use the **Direct Connection** string (e.g., `postgresql://postgres.[ref]:[pass]@aws-0-[region].pooler.supabase.com:5432/postgres`) rather than the transaction pooler URL for best compatibility with SQLx.
- **Connection Pool:** Set `DB_MAX_CONNECTIONS` based on your Supabase tier. For the Free tier, a value of `50` is recommended to stay within the 60-connection limit while leaving room for migrations and dashboard access.


## Security Hardening
1. **Enable TLS:** Always provide `TLS_CERT_PATH` and `TLS_KEY_PATH` in production.
2. **Database Permissions:** Use a dedicated database user with least privilege.
3. **Network Isolation:** Run the server behind a reverse proxy (e.g., Nginx, Caddy) or within a private network.
4. **Secrets Management:** Use a secure secret manager (e.g., Vault, AWS Secrets Manager) instead of plaintext `.env` files.

## Database Migrations
Migrations are automatically run on server startup using SQLx.
To manually run migrations:
```bash
./scripts/db-migrate.sh
```

## JWT Secret Rotation

Recommended zero-downtime procedure:

1. Generate a new 256-bit `JWT_SECRET`.
2. Shorten access-token lifetime temporarily if you want faster cutover.
3. Deploy the new secret to all server instances at once.
4. Keep refresh-token storage intact. Existing refresh tokens remain valid and will mint new access tokens under the new secret.
5. Expect all existing access tokens to stop working immediately after the rollout. Users will transparently recover on refresh or will need to log in again if they only hold an expired/blocked access token.
6. If compromise is suspected, revoke refresh tokens as well and notify users to re-authenticate.

## Incident Response Pointers

- Use [incident-response.md](incident-response.md) for compromise, corruption, and rollback procedures.
- Maintain regular PostgreSQL backups and validate restoration before production go-live.
