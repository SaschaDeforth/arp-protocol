# ARP Roadmap

This document describes the evolution path from ARP v1.x (current production) to ARP v2.0 (in IETF standardization).

## Current Status (April 2026)

| Version | Status | Recommendation |
|---|---|---|
| **v1.2** | ✅ Production / Stable | Use this for any new deployment today |
| **v2.0** | 📐 IETF Internet-Draft | Read for direction; do not deploy in production yet |

ARP v2.0 is fully backward compatible with v1.x. No file you create today will break.

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

### 4. Self-attestation → Multi-party co-signing

**v1.x assumption:** The entity's own cryptographic signature is the primary trust source.
**Inversion:** What if external parties could co-sign individual claims?
**v2.0 result:** A four-tier attester hierarchy (community, institutional, government, sovereign). Trust Level escalates from CRYPTOGRAPHIC (0.70) to ATTESTED (0.90) to SOVEREIGN (1.00) based on co-signers.

### 5. One-way broadcast → Bidirectional feedback

**v1.x assumption:** Agents read; entities never know what agents thought.
**Inversion:** What if agents could report back which claims were useful, miscalibrated, or hallucinated?
**v2.0 result:** `POST /feedback` accepts anonymized confidence-alignment scores and hallucination flags. Entities learn which claims work; automatic claim degradation occurs if a claim systematically misaligns.

### 6. Implicit English → i18n first-class

**v1.x assumption:** English is the default language for all claims.
**Inversion:** What if language were a fundamental property of every claim?
**v2.0 result:** HTTP Accept-Language negotiation on every endpoint. Mandatory language coverage rules. Translation quality signals (`draft`, `reviewed`, `certified`).

## Migration Stages

Migration is **voluntary and incremental**. Each stage increases the Trust Score and unlocks additional v2.0 features.

### Stage 0 — No action required

* **What:** Keep your existing v1.2 `reasoning.json` unchanged.
* **Trust Level:** CRYPTOGRAPHIC (0.70).
* **What happens:** v2.0 loaders transparently serve your file via the compatibility alias at `/.well-known/reasoning.json`.

### Stage 1 — Add `entity_did` and `api_endpoint`

* **What:** Generate a `did:web` DID, publish a DID Document, deploy a minimal API endpoint with at least `GET /identity` and `GET /trust`.
* **Trust Level:** CRYPTOGRAPHIC (0.70-0.72 with DID bonus).
* **Why:** Enables A2A handshakes; future-proofs identity against domain changes.

### Stage 2 — Add i18n and implement `POST /query`

* **What:** Add `i18n` objects to all localizable text fields. Deploy `POST /query` and `GET /corrections`. Declare `supported_languages`.
* **Trust Level:** CRYPTOGRAPHIC (0.72-0.75).
* **Why:** Your entity becomes accessible to non-English AI agents and benefits from query-specific context.

### Stage 3 — First institutional attestation

* **What:** Obtain co-signatures from at least one institutional attester (e.g., an accredited certification body) for three or more claims.
* **Trust Level:** **ATTESTED (0.90)** — major jump.
* **Why:** AI systems treat your claims with substantially higher confidence; your Trust Score appears in `GET /trust`.

### Stage 4 — Activate Webhooks and Feedback

* **What:** Deploy `GET /subscribe` (SSE) and `POST /feedback`. Set `feedback_policy.accepts_feedback: true`.
* **Trust Level:** ATTESTED (0.90).
* **Why:** Real-time bidirectional protocol active. Begin learning which claims work via aggregated agent feedback.

### Stage 5 — Government or sovereign attestation (optional)

* **What:** Obtain co-signatures from a government registry or qualified trust service provider for core identity claims.
* **Trust Level:** **SOVEREIGN (1.00)** for attested claims.
* **Why:** Recommended for entities in regulated industries (financial services, healthcare, pharmaceutical).

## Timeline

| Quarter | Milestone |
|---|---|
| **Q2 2026** (current) | v2.0 IETF Internet-Draft published. Open community review begins. |
| **Q3 2026** | IETF Working Group outreach (HTTPAPI, DISPATCH). Pilot v2.0 API deployed on arp-protocol.org alongside v1.2. |
| **Q4 2026** | First v2.0 reference loader. Pilot programs with first institutional attesters. |
| **Q1 2027** | v2.0 specification stabilizes. Migration tools released. |
| **2027–2028** | v2.0 promoted to "production" once at least one major AI platform supports native v2.0 retrieval. v1.2 remains a fully supported compatibility layer. |

## Compatibility Guarantees

* No v1.x deployment will ever break.
* Static `/.well-known/reasoning.json` is a permanent compatibility endpoint.
* Ed25519 + DNS signatures from v1.2 remain valid in v2.0 indefinitely.
* The `version` field in `reasoning.json` is the canonical version signal. Loaders MUST handle both `"1.2"` and `"2.0"`.

## How to Contribute

* Read the IETF draft: [drafts/ietf/draft-deforth-arp-reasoning-protocol-00.txt](drafts/ietf/)
* Open an Issue with feedback on specific sections of v2.0
* Submit Pull Requests for example v2.0 implementations
* Discuss the migration path on GitHub Discussions

---

**Maintained by [Sascha Deforth](https://www.linkedin.com/in/deforth/) · [TrueSource](https://truesource.studio) · Düsseldorf · Last updated April 2026**
