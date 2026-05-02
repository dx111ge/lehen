# IdentityProvider Plugin Contract (Edge-side)

**Status:** v1 contract — only the PKCE-OIDC implementation ships. Other adapters
(Kerberos/SPNEGO, embedded webview, ROPC) are out of scope for v1 and slot
into the same interface in later journeys.

**Plan reference:** Journey 1 §A1, §D1.

---

## 1. Purpose

The `IdentityProvider` is the Edge-side seam between "user wants to start using
Lehen" and "Edge has a valid bearer token to send to the Hub". The Hub never
calls this interface directly — it only validates the JWTs the Edge produced
through its IdentityProvider.

A compliant implementation:

1. Authenticates the user against the configured IdP.
2. Stores tokens for the duration of the user's session.
3. Refreshes access tokens before expiry.
4. Surfaces a sign-out hook that revokes tokens client-side and (where
   supported) server-side.

## 2. Required operations

```text
authenticate() -> Tokens
    Trigger an interactive sign-in flow. Blocks until the user has signed in
    or the flow is cancelled. Returns access + refresh tokens with their
    expiries. Idempotent: if a valid access token is already cached, may
    return immediately without prompting.

refresh(tokens: Tokens) -> Tokens
    Exchange the refresh token for a fresh access token. Throws
    ``IdpExpired`` if the refresh token is no longer valid (forces a new
    interactive sign-in).

revoke(tokens: Tokens) -> None
    Best-effort: invalidate refresh token at the IdP (e.g. Keycloak
    /logout endpoint) and discard local copies. Must always discard local
    copies even if the remote call fails.

current_user_claims(tokens: Tokens) -> dict
    Decode the access token's claims. Useful for offline display of the
    signed-in identity. Does NOT validate signature against JWKS — that is
    the Hub's responsibility.

health() -> bool
    Quick reachability probe of the IdP discovery endpoint. Used by the Edge
    UI to surface "IdP unreachable" banners.
```

The `Tokens` shape is a minimal record: `{access_token, refresh_token,
access_token_expires_at, refresh_token_expires_at?}`. All times in UTC.

## 3. v1 default: PKCE-OIDC via system browser

**Implementation in v1:** `hub/src/lehen_hub/user_ui/app.js` (browser SPA today,
bundled into Tauri Edge later — D5).

Flow per RFC 8252:

1. Generate a 32-byte random `code_verifier`; `code_challenge = base64url(sha256(verifier))`.
2. Open the system browser to the authorization endpoint with `client_id =
   lehen-edge`, `code_challenge`, `code_challenge_method=S256`, `state` (CSRF),
   `redirect_uri = http://127.0.0.1:<ephemeral>/callback` (Tauri loopback) or
   `http://localhost:8000/app/callback.html` (browser dev).
3. User signs in to Keycloak. Browser redirects to the loopback URI with
   `code` + `state`.
4. Edge exchanges code+verifier at the token endpoint for `{access_token,
   refresh_token, ...}`.
5. Tokens stored: in browser dev mode, in `sessionStorage`; in Tauri Edge,
   refresh token in Windows Credential Manager via the
   `tauri-plugin-keyring` plugin.

Sign-out: `POST {issuer}/protocol/openid-connect/logout` with the refresh
token, then clear local storage.

## 4. Future plug-in: Kerberos/SPNEGO trusted sign-in

Same contract, different backend:

- `authenticate()` would issue an SPNEGO request via the Windows
  `Negotiate` SSP, returning a Kerberos ticket; Keycloak (configured with the
  SPNEGO broker) exchanges that ticket for OIDC tokens.
- Compatible with the Hub side because the Hub only sees JWTs — it does not
  care how the Edge obtained them.

Activation: the Edge's local IdentityProvider config selects the
implementation; the Hub config does not change.

## 5. What this contract does **not** cover

- Token validation. That happens in the Hub against the cached JWKS — see
  `hub/src/lehen_hub/auth/jwt.py`.
- Per-user authorization at the Hub. Realm-role membership is read by the
  Hub from the JWT's `realm_access.roles` claim.
- Source-system credentials. Per-user OAuth refresh tokens for Outlook,
  Teams, ITSM are NOT this interface's concern — they live in
  `IntegrationConnection.encrypted_credentials` (Hub-stored, AES-256-GCM at
  rest). The Edge requests fresh access tokens for source systems via
  `POST /me/connections/{id}/access-token` (reserved in v1, returns 501).
