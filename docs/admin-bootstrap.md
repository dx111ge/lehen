# Admin bootstrap and emergency procedure

The Hub has a deliberately small local-admin path that exists for two situations only:

1. **First boot** — a fresh Hub has no SIAM IdP configured yet, so an administrator can't sign in via SSO. The local admin account is the way you log into the admin UI to configure Keycloak or Entra.
2. **Emergency break-glass** — your SIAM IdP is unreachable, your Entra app got revoked, or your only SIAM admin account is locked out. The local admin path lets you back in to fix it.

It is **not** a parallel auth system. There is exactly one local admin account per Hub install. It auto-disables on the first successful SIAM admin login. Re-enabling for an emergency requires shell access on the Hub host.

This is the trust model: anyone with shell access to the Hub host can rotate the local admin password and authenticate. That is the same level of access that already lets you stop containers, read the database, or replace the binary. The local admin path does not weaken your existing security posture; it just makes operational recovery possible without bypassing the abstraction.

If your environment requires further hardening of this path (time-windowed validity, IP allowlists, multi-eye principle, 2FA), see `docs/backlog.md` for the planned options.

## 1. First-boot bootstrap

### Prerequisites

Set the local-admin signing key in the Hub config (`.env` or your secret manager). Generate it with:

```bash
python -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

```
LEHEN_LOCAL_ADMIN__ENABLED=true
LEHEN_LOCAL_ADMIN__SIGNING_KEY=<32-byte url-safe-base64>
```

Restart the Hub so the signing key takes effect. Verify the path is enabled:

```bash
curl -s http://localhost:8000/health/ready | jq .
```

The response includes the active SIAM provider's check. There is no separate health check for local-admin (intentional — the path is invisible to consumers until they POST to it).

### Create the bootstrap admin

On the Hub host, with the same environment the Hub uses:

```bash
cd hub
uv run python -m lehen_hub.cli create-admin --username admin
```

The CLI prints output like:

```
Local-admin bootstrap credential created/rotated.
  Username: admin
  Password: <32+ char url-safe random>

Save this password now — it cannot be recovered. Re-running this
command invalidates it. The local-admin path auto-disables after
the first successful SIAM admin login; re-run to re-enable for an
emergency.
```

**The password is shown exactly once. Capture it before the terminal scrolls.** It is stored in the database only as an argon2id hash — there is no recovery path; only rotation.

### Sign in

The admin UI calls `POST /admin/local-login` with a JSON body:

```bash
curl -X POST http://localhost:8000/admin/local-login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<the printed password>"}'
```

A successful response:

```json
{
  "access_token": "<Hub-self-issued JWT>",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

A failed response is always `401 {"detail": "authentication failed"}` regardless of the actual reason (wrong username, wrong password, account disabled, locked out, rate-limited). The audit trail records the actual reason in `LocalAdminLoginEvent`.

Use the returned access token as a bearer token against any `/admin/*` endpoint. The same token is **not** valid on user-surface endpoints (`/me/*`) — it gets rejected by issuer claim. This is the strict separation rule from DESIGN.md §10.

### Configure SIAM, then move on

Once you've signed in with the local admin:

1. Configure your SIAM IdP via the admin UI (or via the env vars and a Hub restart, depending on your deployment).
2. Sign out of the local-admin session.
3. Sign in via SIAM. The first SIAM admin login auto-disables the local-admin row.
4. Verify the local-admin path is now disabled by attempting another `POST /admin/local-login` with the same password — you should get the same vague `401 authentication failed`.

The local admin row stays in the database with `enabled=false`, `disabled_at=<timestamp>`, and `disabled_by_siam_username=<the admin who disabled it>`.

## 2. Emergency procedure

### When to use

Use this procedure when:

- Your SIAM IdP is unreachable (Keycloak down, Entra outage) and you need to access the admin UI for any reason.
- Your only SIAM admin account is locked out, deleted, or otherwise unusable.
- A configuration change broke SIAM authentication and you need admin access to fix it.

Do **not** use this procedure as a routine bypass. Every local-admin login is recorded in `LocalAdminLoginEvent`, separate from the regular audit stream, so ops alerting can fire on it. Treat each emergency login as an incident worth a postmortem.

### Procedure

You need shell access on the Hub host. If you don't have shell access, the procedure cannot help you — escalate to whoever does.

```bash
cd hub
uv run python -m lehen_hub.cli create-admin --username admin
```

Re-running the CLI:

- Generates a fresh password (the previous one, if any, is permanently invalidated by the overwrite).
- Sets `enabled=true` on the `LocalAdmin` row.
- Emits a `LocalAdminCredentialRotated` audit event.

Sign in via `POST /admin/local-login` as in the bootstrap section. Fix the underlying problem. After SIAM is back, sign in via SIAM — the auto-disable rule fires again and turns off the local-admin path.

### What the audit trail records

Every local-admin login attempt — successful, failed, rate-limited, locked-out, no-such-user, or auto-disable triggered — emits a `LocalAdminLoginEvent` with:

- `ts` — UTC timestamp
- `username` — the username from the login attempt (note: not validated against existence)
- `client_ip` — source IP from the request
- `user_agent` — truncated to 512 chars
- `outcome` — one of: `success`, `bad_password`, `no_such_user`, `disabled`, `locked_out`, `rate_limited`, `auto_disabled_on_siam_login`
- `request_id` — for correlation with the request log

Use this stream to verify after the incident that the only logins during the emergency window were yours.

## 3. Properties to verify after first install

Smoke-test the security-critical invariants before moving the Hub to production:

1. **User-surface rejection.** A Hub-self-issued JWT must NOT be accepted on `/me/*`:
   ```bash
   curl -i http://localhost:8000/me/connections \
     -H "Authorization: Bearer <token from /admin/local-login>"
   # expect: 401 Unauthorized
   ```
2. **Vague failure messages.** Wrong username, wrong password, and locked-out all return the same `401 authentication failed` body. Vary one variable at a time and confirm.
3. **Auto-disable.** Sign in via SIAM with a SIAM admin user. Then attempt local-login with the bootstrap password. Confirm 401. Confirm the `LocalAdmin` row's `enabled` is `false` in the database.
4. **CLI re-enable.** Re-run `create-admin`. Confirm a `LocalAdmin` row has `enabled=true` again. Confirm the previous password no longer works.

If any of these fail, do not put the Hub into production — open an issue.

## 4. What is intentionally not provided

- **No password recovery.** Lost the printed password? Re-run the CLI. The previous password is gone forever.
- **No web UI for managing local admin.** It is bootstrap and break-glass, not a parallel admin user system. The admin UI does not surface this row.
- **No multiple local admins.** Single account per Hub install.
- **No 2FA.** On the backlog (`docs/backlog.md` item 1). Argon2id + rate-limit + lockout is the floor; 2FA is the ceiling and lands additively when needed.
- **No direct database edit path.** The CLI is the supported interface. Editing the `LocalAdmin` row by hand bypasses the rotation audit event and is a configuration smell — investigate why the CLI didn't work for you instead.
