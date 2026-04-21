# Incident Response

## Severity Levels

- `P0`: Active compromise or widespread authentication bypass.
- `P1`: Data corruption, durable outage, or significant security defect without confirmed active exploitation.
- `P2`: Localized bug, recoverable sync issue, or documentation/process gap.

## JWT Secret Compromise

1. Generate a new `JWT_SECRET` immediately.
2. Deploy the new secret to every server instance.
3. Monitor login and refresh failures during cutover.
4. If compromise scope is unclear, revoke refresh tokens and require full re-authentication.
5. Document the incident timeline and affected users.

## Database Breach

1. Contain the database exposure and rotate infrastructure credentials.
2. Revoke refresh tokens for all users.
3. Notify users that usernames, auth password hashes, encrypted vault blobs, and session hashes may have been exposed.
4. Advise users to rotate authentication passwords and any high-risk credentials stored in the vault.
5. Preserve forensic evidence before destructive cleanup.

## Corrupted Server Vault Blob

1. Restore the affected user's vault from PostgreSQL backup or retained history.
2. Verify the restored version number and blob integrity.
3. Inform the user which backup point was restored.

## Bad Deployment Rollback

1. Stop the new server deployment.
2. Redeploy the previous known-good image or binary.
3. Verify health checks, auth flow, and vault GET/PUT behavior.
4. Preserve the failed build artifacts and logs for postmortem analysis.
