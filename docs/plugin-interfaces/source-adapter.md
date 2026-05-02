# SourceAdapter Plugin Contract

**Status:** v1 contract definition — no real adapters ship yet. The Hub admin
layer registers types and persists configurable instances, but the Connect
button records consent only and `POST /me/connections/{id}/access-token`
returns 501 until a real adapter implements this interface.

**Plan reference:** Journey 1 §6 (Hub additions), §8 (out of scope).

---

## 1. Purpose

A `SourceAdapter` is the bridge between a real source system (Outlook,
Microsoft Teams, an ITSM REST API) and the Lehen capture pipeline. It sits
on the Edge — never on the Hub — and is responsible for:

1. Fetching events / mails / tickets from the configured source.
2. Subscribing to changes (push or polling).
3. Reporting health to the Hub (`/me/connections/{id}` `last_health_*`).
4. Acquiring access tokens via the Hub's credential broker
   (`POST /me/connections/{id}/access-token`).

Privacy boundary: the SourceAdapter ships content through the
`PrivacyFilter` plugin (defined separately) before anything crosses to the
Hub. The Hub never sees raw mail bodies, Teams message text, or ticket
descriptions — only the abstracted output of the filter.

## 2. Required operations

```text
discover() -> InventoryReport
    Enumerate what the user has access to in this source: mailbox folders,
    Teams channels, ITSM queues. The Edge UI shows this so the user can
    opt-in / opt-out per scope (deferred to next journey).

subscribe(filter: SubscriptionFilter) -> AsyncIterator[SourceEvent]
    Stream new events matching the filter. Implementations may use push
    (Graph webhooks, COM event sinks) or polling. The Edge runtime owns
    the lifecycle of the iterator.

fetch(event_id: str) -> RawSourceEvent
    Retrieve a single event by id. Used for late-arrival processing and
    audit-trail re-fetch. Raw bodies returned here NEVER cross the Hub
    boundary; the PrivacyFilter operates on the result.

health() -> HealthStatus
    Quick reachability + auth probe. Returns "ok" if the source is
    reachable AND the cached/refreshed access token is still valid.
    Surfaces in /me/connections as last_health_status / last_health_check_at.
```

## 3. Token acquisition flow (Hub credential broker)

When the SourceAdapter needs an access token to call its source system:

1. Adapter calls the Hub: `POST /me/connections/{id}/access-token`.
2. Hub looks up the user's `IntegrationConnection` row, decrypts the stored
   refresh token using the master key from `LEHEN_CRYPTO__MASTER_KEY`.
3. Hub exchanges the refresh token at the source system's token endpoint
   (e.g. Microsoft `/oauth2/v2.0/token`). The exchange uses the
   per-instance OAuth client config persisted as
   `IntegrationInstance.config_secrets_encrypted`.
4. Hub returns a short-lived access token (no refresh token) to the Edge.
5. Edge uses that access token directly against the source system.

This pattern means:

- **Edge never holds long-lived source-system credentials** — they live
  centrally on the Hub, encrypted at rest. PC switches and role handovers
  are no-ops for the credential side (D4 reasoning).
- **Hub never sees source content** — only credentials and abstracted
  output via the filter. Privacy boundary intact for content (DESIGN.md §7).

## 4. Adapter activation lifecycle

1. Admin creates an `IntegrationInstance` of a known type (e.g.
   `teams-graph`) in the admin UI, providing the per-tenant OAuth config
   (client_id, client_secret).
2. Admin adds the instance to the SIAM mapping for the relevant role(s).
3. User signs in to the Edge — `/me` returns the instance with status
   `needs_connect`.
4. User clicks Connect → Edge opens a per-source OAuth consent flow
   (Microsoft consent prompt for Graph, etc.) → on success, Edge POSTs
   the resulting refresh token to the Hub via a future
   `POST /me/connections/{id}/credentials` endpoint (NOT in v1).
5. Hub encrypts the refresh token and stores it on `IntegrationConnection`.
   `status` flips from `stub-connected` (v1 placeholder) to `connected`.
6. Adapter starts subscribing.

## 5. What this contract does **not** cover

- The on-Edge schedule / batching / backoff strategy for `subscribe`.
- The Hub's graph schema for capture-pattern detection (deferred to a
  later journey).
- The `PrivacyFilter` interface — separate contract.
- Multi-tenant isolation — v1 is single-tenant per Hub.
