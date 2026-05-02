# Keycloak Setup for Lehen

Lehen's Hub validates JWTs against a Keycloak realm. This directory holds an
idempotent provisioner that creates the realm, roles, users, OIDC clients,
and audience client-scope that Journey 1 needs.

The script is **dev-oriented**: it seeds test users with a documented
password and enables Direct Access Grants (ROPC) on the Edge client so curl
can mint tokens for verification. **Do not run as-is against a production
Keycloak.** For production, see the *Hardening for production* section.

---

## What this provisions

| Resource | Name | Purpose |
|---|---|---|
| Realm | `lehen` | Home for all Lehen users / clients |
| Realm role | `lehen-admin` | Gates `/admin/*` endpoints in the Hub |
| Realm role | `change-manager` | Example role mapped via SIAM |
| Realm role | `service-desk` | Example role mapped via SIAM |
| User | `dx-admin` | Holds `lehen-admin` |
| User | `cm-test` | Holds `change-manager` |
| User | `sd-test` | Holds `service-desk` |
| User | `multi-test` | Holds BOTH `change-manager` and `service-desk` (for the multi-role-union test) |
| OIDC client | `lehen-hub` | Bearer-only audience identifier — the Hub validates `aud == lehen-hub` |
| OIDC client | `lehen-edge` | Public PKCE-S256 client used by `/app/` SPA and (later) Tauri Edge |
| OIDC client | `lehen-admin-ui` | Public PKCE-S256 client used by `/admin/` SPA |
| Client scope | `lehen-hub-audience` | OIDC audience-mapper that adds `lehen-hub` to access tokens; attached as default scope to both public clients |

All test users get the password `test1234` (dev-only). The script can be
re-run safely; existing items are detected and skipped or refreshed
(passwords reset, role mappings re-applied).

---

## Prerequisites

- A running Keycloak server reachable from where you run the script
- An admin account in Keycloak's `master` realm that can create realms,
  users, and clients
- Python 3.12+ (the script uses only the standard library — no `pip install`)

---

## Run it

Set the required environment variables first; never commit them.

```pwsh
# from the repo root
$env:KEYCLOAK_BASE_URL = "http://<your-keycloak-host>:8180"
$env:KEYCLOAK_ADMIN_USER = "admin"      # or whatever your Keycloak master-realm admin user is
$env:KEYCLOAK_ADMIN_PASSWORD = "<your master-realm admin password>"
python ops/keycloak/setup_realm.py
```

You should see lines like:

```
auth.start base_url=http://<your-keycloak-host>:8180 admin_user=admin
auth.ok
realm.created realm=lehen
role.created role=lehen-admin
role.created role=change-manager
role.created role=service-desk
user.created username=dx-admin
user.roles_assigned username=dx-admin roles=['lehen-admin']
...
client.created client=lehen-hub
client.created client=lehen-edge
client.created client=lehen-admin-ui
client_scope.created scope=lehen-hub-audience
client_scope.audience_mapper_added scope=lehen-hub-audience
audience_scope.attached clients=['lehen-edge', 'lehen-admin-ui']
done realm=lehen
```

A second run prints `*.exists` instead of `*.created` lines and exits clean.

### Configuration

| Env var | Default | Notes |
|---|---|---|
| `KEYCLOAK_BASE_URL` | (required, no default) | Trailing slash is stripped |
| `KEYCLOAK_ADMIN_USER` | `admin` | Keycloak's stock default; set to whatever your install uses |
| `KEYCLOAK_ADMIN_REALM` | `master` | The realm where the admin token is minted (NOT the Lehen realm) |
| `KEYCLOAK_ADMIN_PASSWORD` | (required, no default) | Never commit |

CLI flags (overrides env): `--base-url`, `--admin-user`, `--admin-realm`,
`--realm`.

After running, also point the Hub at the same Keycloak by setting
`LEHEN_KEYCLOAK__BASE_URL` in `ops/.env`. See `ops/.env.example`.

---

## Verify the setup

Quick smoke test using a token minted via Direct Access Grants:

```pwsh
# $env:KEYCLOAK_BASE_URL must already be set
$body = "grant_type=password&client_id=lehen-edge&username=cm-test&password=test1234"
$tok  = (Invoke-RestMethod -Method Post `
    -Uri "$env:KEYCLOAK_BASE_URL/realms/lehen/protocol/openid-connect/token" `
    -ContentType "application/x-www-form-urlencoded" -Body $body).access_token
Invoke-RestMethod -Headers @{Authorization="Bearer $tok"} -Uri http://localhost:8000/me
```

Expected: HTTP 200 with `roles: ["change-manager"]` and an `integrations`
list reflecting whatever the admin has saved into the SIAM mapping.

For the user with both roles:

```pwsh
$body = "grant_type=password&client_id=lehen-edge&username=multi-test&password=test1234"
$tok  = (Invoke-RestMethod -Method Post `
    -Uri "$env:KEYCLOAK_BASE_URL/realms/lehen/protocol/openid-connect/token" `
    -ContentType "application/x-www-form-urlencoded" -Body $body).access_token
Invoke-RestMethod -Headers @{Authorization="Bearer $tok"} -Uri http://localhost:8000/me
```

Expected: `roles: ["change-manager", "service-desk"]` and the deduped union
of integrations.

---

## Browser flow

After the realm is provisioned and the dev stack is up
(`docker compose -f ops/docker-compose.dev.yml --env-file ops/.env up`):

* Open <http://localhost:8000/admin/>, sign in as `dx-admin` / `test1234`,
  configure LLM / integrations / SIAM, watch entries land in the Audit
  pane.
* Open <http://localhost:8000/app/>, sign in as `cm-test`, click Connect
  on the integrations the SIAM mapping allows for `change-manager`.

---

## Hardening for production

Before deploying to a real customer, in addition to the per-deployment
gates documented in `docs/policy/scope-and-data-handling.md`:

1. **Disable Direct Access Grants on `lehen-edge`** (set
   `directAccessGrantsEnabled=false` in the Keycloak admin console). It is
   only enabled here so the curl-based verification works in dev.
2. **Replace test users with real ones** sourced from the customer's
   identity directory (LDAP federation, SAML broker, etc.). The four
   seeded `*-test` users are diagnostic-only.
3. **Use a Keycloak service account, not a human admin user**, for
   automation. Create a confidential client with realm-management
   service-account roles and use its credentials for re-runs of this
   script in CI.
4. **Restrict `valid redirect URIs` on each public client** to the
   real customer-deployed domain — the dev seed uses
   `http://localhost:8000/...` and a wildcard loopback for Tauri.
5. **Configure password policy + MFA** on the realm.
6. **Brute-force protection** is already enabled by the script; tune
   thresholds for the customer.
7. **Rotate any admin passwords** that may have been logged or exposed
   during initial provisioning.
8. **Enable email verification** as appropriate for your IdM workflow.
9. Consider switching from `lehen-edge` ROPC to **Kerberos / SPNEGO**
   for transparent sign-in on domain-joined workstations — the Edge
   IdentityProvider plugin contract is documented at
   `docs/plugin-interfaces/identity-provider.md`.

---

## Reset / clean slate

To start over (loses all the test users + their data history in
Keycloak — the realm is dropped):

```pwsh
# $env:KEYCLOAK_BASE_URL, $env:KEYCLOAK_ADMIN_USER, $env:KEYCLOAK_ADMIN_PASSWORD must already be set
$body = "grant_type=password&client_id=admin-cli&username=$env:KEYCLOAK_ADMIN_USER&password=$env:KEYCLOAK_ADMIN_PASSWORD"
$tok  = (Invoke-RestMethod -Method Post `
    -Uri "$env:KEYCLOAK_BASE_URL/realms/master/protocol/openid-connect/token" `
    -ContentType "application/x-www-form-urlencoded" -Body $body).access_token
Invoke-RestMethod -Method Delete `
    -Headers @{Authorization="Bearer $tok"} `
    -Uri "$env:KEYCLOAK_BASE_URL/admin/realms/lehen"
```

Then re-run `setup_realm.py`.

---

## Operational secrets — what NOT to put in the repo

The repository **must never** contain:

- Hostnames or IPs of customer / production Keycloak instances
- Hostnames or IPs of customer / production Hub deployments
- Real admin usernames (a username is mildly sensitive on its own — it's the
  first half of every credential-stuffing attempt)
- Any Keycloak / OAuth / database password, ever
- The contents of `ops/.env` (which is `.gitignore`d)
- The values from `LEHEN_CRYPTO__MASTER_KEY` or `LEHEN_CRYPTO__AUDIT_PEPPER`

If any of these were committed at any point in the repo's history, **rotate
them immediately**. Force-pushing a rewritten history does not help: anyone
with a clone or fork already has the old values. The fix is rotation at the
upstream system (Keycloak, the database, the master key), not history
rewriting.
