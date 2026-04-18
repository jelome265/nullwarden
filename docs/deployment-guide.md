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
| `TLS_CERT_PATH` | Path to TLS certificate | None |
| `TLS_KEY_PATH` | Path to TLS private key | None |

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
