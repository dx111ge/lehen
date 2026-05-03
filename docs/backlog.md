# Backlog — Lehen

Decisions and features that have been deliberately deferred out of active sprints. This is a living document. New items get appended; items pulled into a sprint get removed from here and recorded in that sprint's design doc.

## Format

Each item carries enough context that it can be picked up cold months later without rereading old conversations.

- **Title** — short name
- **Surfaced in:** sprint or context where it first came up, with date
- **Why deferred:** the tradeoff that pushed it out of an active sprint
- **Trigger to revisit:** the concrete signal that should pull this back into planning
- **Notes:** additional design detail captured at the time the decision was made

---

## Items

### 1. 2FA on local admin login

**Surfaced in:** Sprint 1.5 planning (2026-05-03)

**Why deferred:** Local admin is emergency-only break-glass, used rarely. Adding TOTP to Sprint 1.5 would expand scope by approximately half a day plus the QR and recovery-code UX. The floor for Sprint 1.5 is argon2id password storage + rate-limit + lockout; 2FA is the ceiling and can land additively without rework.

**Trigger to revisit:** First customer deployment that audits local admin access (SOC2 prep, BSI Grundschutz review, internal pen-test report). Or: any reported local admin credential incident, even hypothetical. Or: a contributor PR that adds it.

**Notes:**
- TOTP via authenticator app is sufficient for this admin tier. WebAuthn complexity not justified for an emergency-only path.
- Recovery codes printed once at setup, hashed in DB.
- Configuration flag in Hub config: `admin.local_auth.require_2fa`. Defaults to false in dev, true in production deployment templates.
- The Hub-self-issued JWT format from Sprint 1.5 already supports an `amr` (authentication methods reference) claim — adding 2FA later means populating it with `["pwd", "otp"]` instead of `["pwd"]`. No JWT format change needed.

---

### 2. Further hardening of local admin path

**Surfaced in:** Sprint 1.5 planning (2026-05-03)

**Why deferred:** Sprint 1.5 ships the floor (argon2id, rate-limit, lockout, dedicated audit event, auto-disable after first SSO admin login). Sprint 1.5 accepts the trust model "anyone with shell access to the Hub host can rotate the bootstrap password and log in" — because that level of access is already root-equivalent in any on-prem deployment. Hardening beyond the floor is real but not urgent.

**Trigger to revisit:** Audit findings from a real customer deployment. Or: a documented incident where the floor proved insufficient.

**Notes — concrete hardening items to consider when this is picked up:**
- **Time-windowed bootstrap password validity.** CLI-generated password expires after a configurable window (e.g., 1 hour). Forces operator to use it promptly or regenerate.
- **IP allowlist on the local-login endpoint.** Configurable list of source IP CIDRs allowed to hit `/admin/local-login`. Default empty = block all = local-login disabled. Operator must opt in per-deployment.
- **Multi-eye principle.** Require N admins to co-sign a local login. Heavyweight; only worth it for very strict environments.
- **Out-of-band confirmation.** Local login generates an event that must be acknowledged in a separate channel (signed Slack/email message, or a second admin's SIAM session) before the JWT is issued.
- **Audit alerting integration.** Built-in webhook/syslog/PagerDuty for `LocalAdminLoginEvent` so ops are paged on every emergency login by default.
- **HSM-backed JWT signing key.** The Hub-self-issued JWT signing key lives in an HSM rather than on disk, so a compromised disk does not allow forging admin JWTs.
