# Lehen — Scope & Data Handling Policy

**Status:** v1 product policy. Reflects journey 1 architecture decisions D6
(scope of capturable sources) and D7 (legal/compliance pre-deploy gates).

**Audience:** customer DPO, customer legal, customer Betriebsrat / Personalrat,
Lehen vendor team.

---

## 1. What Lehen is, in one paragraph

Lehen is an on-premise platform that captures organizational knowledge as a
side effect of normal work. It triangulates events across mail, Teams, and
ITSM systems to detect "capture moments" — where the same person has a
ticket, a Teams conversation, and a mail thread that together represent a
decision or a runbook variation. The captured knowledge is abstracted at the
Edge (privacy filter), then transmitted to the central Hub for projection
onto a role-based knowledge graph. The principle is *capture-as-side-effect*:
no separate documentation task; the work *is* the record.

## 2. Scope of capturable sources (D6)

**Default (v1):** Lehen captures only from **company-managed sources**:

- Microsoft 365 Exchange mailboxes provisioned by the customer's IT
- Microsoft Teams accounts within the customer's tenant
- ITSM systems whose REST APIs are configured by the customer's admin

**Out of scope by policy:** personal mailboxes (Gmail, web.de, GMX), personal
chat platforms (WhatsApp, Signal, personal Teams), file shares not under
customer governance.

**Architectural back door for explicit privacy separation:** the data model
supports multiple `IntegrationConnection` rows per (user, instance) and a
`privacy_class` field on each. A future UI gesture lets a user register a
second connection marked `excluded` so the company can offer a "company
mailbox + private mailbox not included" model. v1 does not surface this; the
operator decides per deployment whether to enable it.

## 3. Data flow boundaries

| Where the data is | What it can contain | What it must NOT contain |
|-------------------|--------------------|--------------------------|
| Source system     | Raw mail body, Teams text, ticket description (governed by customer's existing retention policy) | (everything is fine — owned by the source) |
| Edge (workstation)| Raw source content fetched on demand, ephemeral; user-side OAuth tokens for the IdP | Long-lived source-system credentials (those live centrally on the Hub, encrypted) |
| Hub               | Encrypted source-system credentials; abstracted knowledge artifacts (decisions, runbook variations); audit trail | Raw mail bodies, raw Teams messages, raw ticket descriptions |
| Backups (operator-owned) | Whatever the operator's backup policy captures from the Hub volume | (governed by operator's backup retention) |

## 4. Legal frameworks relevant to deployment (DACH / EU)

**Not legal advice. Read with your DPO and legal counsel. v1 ships templates
referenced from this section; the customer is responsible for completing them.**

- **DSGVO (GDPR)** — Art. 6 lawful basis, Art. 5(1)(c) data minimization,
  Art. 5(1)(b) purpose limitation, Art. 35 DSFA/DPIA required for "umfangreiche
  Verarbeitung im Beschäftigungskontext". v1 ships a DSFA skeleton at
  `docs/policy/dsfa-skeleton.md` (scheduled for next journey).
- **BDSG §26** — Beschäftigtendatenschutz. Verarbeitung zulässig für
  Durchführung des Beschäftigungsverhältnisses oder mit Einwilligung;
  freiwillige Einwilligung im Arbeitsverhältnis ist umstritten —
  Betriebsvereinbarung empfohlen.
- **BetrVG §87 Abs. 1 Nr. 6** (DE) — Mitbestimmung des Betriebsrats bei
  technischen Einrichtungen, "die geeignet sind, das Verhalten oder die
  Leistung der Arbeitnehmer zu überwachen". Lehen fällt darunter.
  **Betriebsvereinbarung erforderlich** vor Deployment in deutschen
  Unternehmen mit Betriebsrat. Mustertext geplant für nächste Journey.
- **TTDSG §25** (DE) — Einwilligung für Speicherung auf Endgeräten. Relevant
  ab dem Tauri-Edge mit Keyring-Speicherung.
- **EU AI Act 2024/1689** — wenn Lehens LLM Entscheidungen über Beschäftigte
  beeinflusst (z.B. Empfehlungen für Change-Approvals), Risikoklassifizierung
  prüfen. Wenn als "Hochrisiko" klassifiziert, weitere Pflichten (CE-konformer
  Konformitätsbewertungsprozess, technische Dokumentation, Transparenz,
  menschliche Aufsicht).

## 5. Pre-deploy gates (D7)

These are organizational, not technical. v1 ships, dev environments run, but
no production deployment to actual users should happen until:

1. **DSFA / DPIA** completed by the customer's DPO using the v1 template.
2. **Betriebsvereinbarung** (DE) negotiated and signed with the works
   council / Personalrat. Sample text geplant für die nächste Journey.
3. **DPO sign-off** on the per-customer instance configuration:
   - Which SourceAdapters are enabled
   - Which roles are mapped to which integrations (the SIAM mapping)
   - Retention windows configured (LEHEN_RETENTION__*)
4. **TTDSG-conform consent flow** when Tauri Edge with keyring storage ships.
5. **EU AI Act risk classification** documented if the LLM influences
   employee-affecting decisions.

These gates do not block v1 development; they block first production rollout.

## 6. Audit + user data rights (DSGVO Art. 15-22)

- **Per-user audit trail** is captured in `LoginEvent` and `ConsentEvent`
  document collections. v1 stores these centrally with `retain_until` set
  per ``LEHEN_RETENTION__*`` (default: LoginEvent 90d, ConsentEvent ~7y).
- **Export (Art. 15)** — endpoint planned for next journey. Until then, the
  operator can export via the underlying ArcadeDB document API.
- **Deletion (Art. 17)** — the request flows through the Hub which deletes
  Hub-side artifacts (graph projection, captured patterns); raw source
  content is unaffected (still governed by the source system's retention).

## 7. Roles and responsibilities

| Party | Owns |
|-------|------|
| Customer (deploying organization) | Source systems, source data, retention; DSFA; Betriebsvereinbarung; per-customer Hub configuration; backups |
| Lehen (vendor) | Code, default plugin contracts, security defaults, vulnerability response, this policy document, sample Betriebsvereinbarung text |
| Customer's DPO | Sign-off on data flows; supervisory authority interface |
| Customer's Betriebsrat / Personalrat | Co-determination per BetrVG; signs Betriebsvereinbarung |

## 8. Updates to this document

This document is part of the source repository (`docs/policy/`). Changes to
data-handling defaults must be reflected here in the same commit, with a
brief rationale. Customers should treat any change to this file as a
trigger for re-review by their DPO.
