# ARP Roadmap

This document records ARP's version history and, for the record, the exploratory v2.0 design from April 2026 (published as an individual Internet-Draft). The v2.0 design is not part of the current specification v1.3, has no implementation, and is not being developed further at this time. ARP is a single-author draft specification, not a standard; the Internet-Drafts have no IETF standing.

## Current Status (October 2026)

| Version | Status | Recommendation |
|---|---|---|
| **v1.3** ("Reader Profile", 2026-10-05) | ✅ Current draft specification | Use this for any new deployment today |
| **v1.2** | Previous version | Files remain valid and readable as v1.2; see the migration guide in SPEC.md §17.1 |
| **v2.0** | 📐 Archived exploratory Internet-Draft (`draft-deforth-arp-reasoning-protocol-00`, expires 2026-10-30 per IETF Datatracker) | Not part of v1.3; no implementation; not being developed further at this time |

The v1.2 signature layer is described in the individual Internet-Draft `draft-deforth-arp-00` (submitted 2026-04-18, expires 2026-10-20 per IETF Datatracker). A revision for v1.3 (`draft-deforth-arp-01`) is planned; it has not been submitted as of 2026-10-05.

## v1.3 "Reader Profile" (October 2026)

v1.3 is designed to make ARP files readable and correctly attributable for bots, agents, and people, without instruction language: a normative Wording Profile (third-person statements only), a required `provenance` object, a readable signature `statement` with `verify` pointers, rejection of legacy payload-only signatures, key revocation by an empty `p=` tag (`key_revoked`), the deterministic Markdown representation `/.well-known/reasoning.md`, and a signature-neutral Discovery Profile. Reference implementation: `arp_cli.py` v1.4.0. Details: [SPEC.md](SPEC.md). Whether and how AI systems retrieve and use ARP files is not established.

Open for a later version: v1.3 keeps the member names `verified_fact` and `last_verified` for compatibility, although item 5 of the Wording Profile (SPEC §11.2) otherwise excludes such terms unless the text names who checked what. Whether a later version renames them (for example to `stated_fact` and `last_reviewed`, with a transition period in which verifiers read both) is undecided.

The following sections describe the v2.0 draft as designed in April 2026. They have not been revised for v1.3 and are kept for the record only; the v2.0 design is not being developed further at this time. Only the label of inversion 4 was reworded editorially on 2026-10-05 (SPEC.md, changelog "v1.3 editorial").

## How v2.0 Was Designed

ARP v2.0 was designed through **counterfactual inversion** — a method where each assumption of v1.x was tested by asking "what if this assumption is wrong?" Six inversions emerged:

### 1. Static file → Live REST API

**v1.x assumption:** Entities broadcast all claims to all agents via a static JSON file.
**Inversion:** What if agents could ask for specific context relevant to their current task?
**v2.0 result:** A REST API at `/.well-known/arp/v2/` with endpoints including `POST /query` (semantic context request), `GET /trust` (trust manifest), and `GET /claims/{id}` (single claim with provenance).

### 2. Domain ownership = identity → W3C DID

**v1.x assumption:** Whoever controls the domain controls the claims (Ed25519 + DNS).
**Inversion:** What if entity identity were independent of any single domain?
**v2.0 result:** W3C Decentralized Identifier (DID) anchoring. An entity can move domains, consolidate subsidiaries, or be acquired — its DID remains stable.

### 3. 90-day TTL → Event-driven push

**v1.x assumption:** Periodic re-signing every 90 days is a sufficient freshness signal.
**Inversion:** What if claims could change in real time and agents knew immediately?
**v2.0 result:** Server-Sent Events (SSE) at `GET /subscribe`. Agents receive `claim:updated`, `correction:new`, and `trust:level:changed` events as they happen.

### 4. Entity's own signature → Multi-party co-signing

**v1.x assumption:** The entity's own cryptographic signature is the primary trust source.
**Inversion:** What if external parties could co-sign individual claims?
**v2.0 result:** A four-tier attester hierarchy (community, institutional, government, sovereign). In the draft's scoring model, the Trust Level escalates from CRYPTOGRAPHIC (0.70) to ATTESTED (0.90) to SOVEREIGN (1.00) based on co-signers. Co-signatures attest that the co-signer checked specific claims; how AI systems weigh them is not established.

### 5. One-way broadcast → Bidirectional feedback

**v1.x assumption:** Agents read; entities never know what agents thought.
**Inversion:** What if agents could report back which claims were useful, miscalibrated, or hallucinated?
**v2.0 result:** `POST /feedback` accepts anonymized confidence-alignment scores and hallucination flags. Entities learn which claims work; automatic claim degradation occurs if a claim systematically misaligns.

### 6. Implicit English → i18n first-class

**v1.x assumption:** English is the default language for all claims.
**Inversion:** What if language were a fundamental property of every claim?
**v2.0 result:** HTTP Accept-Language negotiation on every endpoint. Mandatory language coverage rules. Translation quality signals (`draft`, `reviewed`, `certified`).

## Migration Stages

Migration is **voluntary and incremental**. In the draft's scoring model, each stage increases the Trust Score and unlocks additional v2.0 features.

### Stage 0 — No action required

* **What:** Keep your existing v1.x `reasoning.json` (v1.2 or v1.3) unchanged.
* **Trust Level:** unchanged from v1.x: CRYPTOGRAPHIC only for signed, unexpired files with the Enveloped Pattern and a key that is published and not revoked; UNSIGNED for unsigned or expired files; INVALID otherwise (SPEC §13.7). The draft's scoring model assigns CRYPTOGRAPHIC the value 0.70.
* **What happens:** v2.0 loaders transparently serve your file via the compatibility alias at `/.well-known/reasoning.json`.

### Stage 1 — Add `entity_did` and `api_endpoint`

* **What:** Generate a `did:web` DID, publish a DID Document, deploy a minimal API endpoint with at least `GET /identity` and `GET /trust`.
* **Trust Level (draft's scoring model, signed files):** CRYPTOGRAPHIC (0.70-0.72 with DID bonus).
* **Why:** Enables A2A handshakes; future-proofs identity against domain changes.

### Stage 2 — Add i18n and implement `POST /query`

* **What:** Add `i18n` objects to all localizable text fields. Deploy `POST /query` and `GET /corrections`. Declare `supported_languages`.
* **Trust Level (draft's scoring model, signed files):** CRYPTOGRAPHIC (0.72-0.75).
* **Why (design goal of the draft):** Localized statements and query-specific context for agents that work in other languages; whether agents use them is not established.

### Stage 3 — First institutional attestation

* **What:** Obtain co-signatures from at least one institutional attester (e.g., an accredited certification body) for three or more claims.
* **Trust Level:** **ATTESTED (0.90)** in the draft's scoring model.
* **Why:** Individual claims carry a third-party co-signature that names who checked them; your Trust Score appears in `GET /trust`.

### Stage 4 — Activate Webhooks and Feedback

* **What:** Deploy `GET /subscribe` (SSE) and `POST /feedback`. Set `feedback_policy.accepts_feedback: true`.
* **Trust Level:** ATTESTED (0.90) in the draft's scoring model.
* **Why (design goal of the draft):** Real-time updates and a feedback channel through which agents could report which claims they found useful or miscalibrated; whether agents send such feedback is not established.

### Stage 5 — Government or sovereign attestation (optional)

* **What:** Obtain co-signatures from a government registry or qualified trust service provider for core identity claims.
* **Trust Level:** **SOVEREIGN (1.00)** for attested claims.
* **Why:** Recommended for entities in regulated industries (financial services, healthcare, pharmaceutical).

## Timeline

Done:

| Date | Milestone |
|---|---|
| 2026-04-18 | `draft-deforth-arp-00` (v1.2 signature layer) submitted to the IETF Datatracker as an individual submission (date per Datatracker; expires 2026-10-20). |
| 2026-04-28 | v2.0 Internet-Draft submitted to the IETF Datatracker as an individual submission (date per Datatracker; expires 2026-10-30). Submission does not imply IETF endorsement. |
| 2026-10-05 | v1.3 "Reader Profile" published in this repository. |

Plan as of April 2026 (not updated since; status of the individual items is not tracked here):

| Quarter | Milestone |
|---|---|
| **Q3 2026** | IETF Working Group outreach (HTTPAPI, DISPATCH). Pilot v2.0 API on arp-protocol.org alongside v1.x. |
| **Q4 2026** | First v2.0 reference loader. Pilot programs with first institutional attesters. |
| **Q1 2027** | v2.0 specification stabilizes. Migration tools released. |
| **2027–2028** | v2.0 promoted to "production" once at least one major AI platform supports native v2.0 retrieval. v1.x remains a supported compatibility layer. |

## Compatibility Guarantees

* v1.x files remain readable; v1.2 files remain valid as v1.2 alongside v1.3.
* Static `/.well-known/reasoning.json` is a permanent compatibility endpoint.
* Ed25519 + DNS signatures made with the Enveloped Pattern (SPEC §13.4) remain verifiable as long as the key record is published and not revoked. Legacy payload-only signatures (ARP CLI 1.2 and earlier) are rejected since v1.3, as are files with duplicate member names and signature values that are not in canonical Base64url form (SPEC §13.3, §13.4).
* The `version` field in `reasoning.json` is the canonical version signal. Loaders MUST handle `"1.2"`, `"1.3"`, and `"2.0"`.

## How to Contribute

* Read the Internet-Drafts: [draft-deforth-arp-00](https://datatracker.ietf.org/doc/draft-deforth-arp/) (v1.2 signature layer) and [drafts/ietf/draft-deforth-arp-reasoning-protocol-00.txt](drafts/ietf/) (v2.0 design, not revised for v1.3)
* Open an Issue with feedback on specific sections of v2.0
* Submit Pull Requests for example v2.0 implementations
* Discuss the migration path on GitHub Discussions

---

**Maintained by [Sascha Deforth](https://www.linkedin.com/in/deforth/) · [TrueSource](https://truesource.studio) · Düsseldorf · Last updated 2026-10-05**
