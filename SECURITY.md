# Security Policy

Lehen handles enterprise communication metadata, identity tokens, and OAuth
credentials for source systems. We treat its security posture as
load-bearing rather than aspirational. This document is the binding policy
for both maintainers and contributors.

---

## 1. Supported versions

| Version | Status | Security patches |
|---------|--------|------------------|
| `0.1.x` | Pre-release; **not** for production deployment | Best-effort, no SLA |
| `< 0.1` | Internal demonstrators (incl. the predecessor `central-knowledge` artifact) | None — do not deploy |

A formal supported-versions matrix will be published with the first
non-pre-release tag. Until then, only the `main` branch receives security
fixes.

---

## 2. Reporting a vulnerability

**Do not open a public GitHub issue for security-relevant findings.**

Use the **GitHub Private Security Advisory** channel — open a draft at
<https://github.com/dx111ge/lehen/security/advisories/new>. This gives us a
private discussion thread, optional CVE coordination, and a tracked
timeline. It is currently the only supported reporting channel; the
maintainer does not operate a separately-monitored security mailbox.

Please include, where possible:

- Affected version / commit SHA
- A minimal reproduction or proof-of-concept
- The impact you demonstrated (auth bypass, info disclosure, RCE, etc.)
- Whether the finding has been disclosed elsewhere

**Response targets** (best-effort while we are pre-1.0):

| Severity | Acknowledgement | Triage start | Fix target |
|----------|-----------------|--------------|------------|
| Critical (auth bypass, RCE, key exposure) | within 48h | within 5 business days | within 30 days |
| High (privilege escalation, persistent XSS, unauthenticated data exposure) | within 5 business days | within 10 business days | within 60 days |
| Medium / Low | within 10 business days | within 30 business days | next minor release |

We will coordinate disclosure with the reporter. Default disclosure window
is 90 days from acknowledgement; we will request an extension explicitly
if a fix is not yet ready and agree on a revised date.

---

## 3. What is and is not a vulnerability

**In scope:**

- Anything that compromises identity, authentication, or authorization
  (token forgery, JWT validation bypasses, audience confusion, role-claim
  injection).
- Exposure of credentials at rest or in flight beyond their documented
  boundary (per `docs/policy/scope-and-data-handling.md`).
- Cryptographic mistakes in `hub/src/lehen_hub/crypto/` or how the master
  key / audit pepper are loaded, used, or rotated.
- Privilege escalation in the admin gate or the SIAM mapping resolution.
- Persistent XSS / CSRF / open redirect in the SPAs at `/admin/` or
  `/app/`.
- Container image / dependency vulnerabilities affecting a default Hub
  deployment.

**Not in scope** (please don't file these as security issues):

- Findings that require changing files in the repo (e.g., "if the master
  key in `ops/.env` is committed, it leaks" — yes, that's why
  `ops/.env` is gitignored).
- Defaults documented as dev-only (e.g., the `test1234` seed password,
  Direct Access Grants on `lehen-edge`, the Apache-style `mode=development`
  flag on ArcadeDB) used in production. The fix is to follow
  `ops/keycloak/README.md` § Hardening for production.
- Brute-force of intentionally weak dev seed credentials.
- Missing security headers on the static SPAs in dev mode (production
  deployments are expected to terminate TLS in front of the Hub and add
  the relevant headers there).

---

## 4. Operational secrets — binding rules for contributors

The repository **must never** contain:

- Hostnames or IPs of customer / production Keycloak, ArcadeDB, Ollama,
  ITSM, or any other source-system endpoint.
- Real admin usernames (a username is the first half of every
  credential-stuffing attempt).
- Any password, API key, OAuth client secret, refresh token, or other
  credential — in any file, in any form, in any commit, ever.
- The contents of `ops/.env`, `hub/.env`, or any other `.env*` that is not
  `.env.example`.
- The contents of `LEHEN_CRYPTO__MASTER_KEY`, `LEHEN_CRYPTO__AUDIT_PEPPER`,
  or any other key material.

Pull requests that include any of the above will be rejected and the
underlying credential treated as compromised.

If you accidentally commit a secret:

1. **Rotate the credential at the upstream system immediately**, before
   anything else. Force-pushing a rewritten history does not undo a
   public push.
2. Open a private security advisory (see § 2) so the maintainer can scrub
   the GitHub-side reflog and search caches.
3. Do not force-push a "fix" without coordinating — premature force
   pushes can disturb other contributors' clones without solving the
   actual exposure.

---

## 5. Cryptographic primitives

Lehen uses well-established AEAD and signature algorithms; do not propose
custom or non-NIST-blessed alternatives in PRs without prior agreement.

| Use | Algorithm | Library |
|-----|-----------|---------|
| Symmetric encryption of secrets at rest | AES-256-GCM (NIST AEAD), per-record nonce, versioned envelope | `cryptography` |
| Audit-log fingerprints over secret values | HMAC-SHA256 keyed by an audit-pepper distinct from the master key | stdlib `hmac` |
| JWT signature validation | RS256 against Keycloak JWKS | `python-jose[cryptography]` |
| OIDC PKCE | S256 code-challenge | browser SubtleCrypto / Tauri-native |
| Random key/nonce generation | `secrets.token_bytes` / `crypto.getRandomValues` | stdlib / browser |

Master-key rotation is supported via the `{key_version, nonce, ct}`
envelope format. v1 ships rotation-by-redeploy; an automated rotation
flow is on the roadmap.

---

## 6. Privacy & compliance

Lehen is privacy-first by architecture, not by retrofit. The boundary is
documented in `docs/policy/scope-and-data-handling.md`, including the
DACH / EU framework references (DSGVO Art. 35 DSFA, BDSG §26, BetrVG §87
Mitbestimmung, TTDSG §25, EU AI Act 2024/1689).

Any change that broadens what data the Hub sees, what is captured by
SourceAdapters, or how long any of it is retained, **must update**
`docs/policy/scope-and-data-handling.md` in the same pull request. PRs
that change data flows without the corresponding policy edit will be
held until both land together.

---

## 7. Coordinated disclosure

We commit to:

- Acknowledging good-faith research and crediting reporters in release
  notes (unless they request anonymity).
- Not pursuing legal action against researchers acting in good faith
  within the scope of this policy.
- Publishing a public advisory once a fix is released — including the
  vulnerability class, affected versions, the fix, and the reporter's
  name (with permission).

We do not currently operate a paid bug bounty.

---

## 8. Updates to this document

`SECURITY.md` is a binding policy. Any change to it requires a pull
request from the maintainer (dx111ge) with a brief rationale in the
commit message. Changes that materially weaken any rule above must
also be reflected in the next release's CHANGELOG.
