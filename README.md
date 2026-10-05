# 🧠 reasoning.json — The Agentic Reasoning Protocol

**Status:** Draft Specification v1.3 "Reader Profile" (2026-10-05), single-author draft, not a standard
**Internet-Drafts:** `draft-deforth-arp-00` (v1.2 signature layer) and `draft-deforth-arp-reasoning-protocol-00` (v2.0 design), individual submissions without IETF standing; a revision for v1.3 is planned
**License:** MIT | **Format:** JSON (+ Markdown representation) | **Trust:** Ed25519 + DNS
**Author:** Sascha Deforth
**Validator:** Online

A machine-readable file format in which a domain owner publishes a self-description of an entity — the entity's own statements of fact, factual corrections, domain context, and recommendation context — for AI agents and RAG pipelines, optionally with an Ed25519 signature that shows who published it. A signature establishes origin, not accuracy.

- 🌐 Website: [arp-protocol.org](https://arp-protocol.org)
- 📄 Specification (current, v1.3): [SPEC.md](./SPEC.md)
- 📐 JSON Schema (current): [`schema/v1.3.json`](./schema/v1.3.json)
- 📐 Internet-Draft for the v1.2 signature layer: [draft-deforth-arp-00](https://datatracker.ietf.org/doc/draft-deforth-arp/) *(submitted 2026-04-18, expires 2026-10-20 per IETF Datatracker; a revision for v1.3, draft-deforth-arp-01, is planned)*
- 📐 v2.0 Draft Text: [`drafts/ietf/draft-deforth-arp-reasoning-protocol-00.txt`](./drafts/ietf/) *(submitted 2026-04-28, expires 2026-10-30 per IETF Datatracker; not revised for v1.3)*
- ✅ Validator: [arp-protocol.org/validator](https://arp-protocol.org/validator)
- 🔐 Signing Tool: [arp-protocol.org/sign](https://arp-protocol.org/sign)
- ⚖️ Ethics Policy: [ETHICS.md](./ETHICS.md)
- 🗺️ Roadmap: [ROADMAP.md](./ROADMAP.md)

---

## What's New in v1.3 ("Reader Profile")

v1.3 is designed to make ARP files readable and correctly attributable for bots, agents, and people, without instruction language:

| Change | v1.2 | v1.3 | Why |
|--------|------|------|-----|
| Wording Profile (ARP-W) | Prose guidance | Normative: third-person statements only; no imperatives, conditional instructions, or pseudo-system markers aimed at AI systems; fields `ai_directive` / `agent_directive` removed | Answer systems treat instructions in web content as information, not as commands; such text risks being classified as manipulation (SPEC §11.2) |
| Provenance | — | Required `provenance` object with a fixed statement, publisher, legal notice URL, date | Every file says plainly whose self-description it is |
| Readable signature (ARP-S) | Signature metadata only | `statement` and `verify` inside `_arp_signature`, covered by the signature | A reader can see what the signature shows and how to check it |
| Legacy signatures | Tolerated by some tools | Payload-only signatures rejected | They left `expires_at` and `dns_selector` unprotected |
| Key revocation (ARP-K) | Remove the DNS record | Empty `p=` revokes a selector (`key_revoked`), rotation pattern `arpYYMM` | Explicit revocation, analogous to DKIM |
| Representation (ARP-R) | — | `/.well-known/reasoning.md`, rendered deterministically, bound by SHA-256 | A text version for readers that do not parse JSON |
| Discovery (ARP-D) | `<link rel="reasoning">`, robots.txt comment | `Link` header and `<link rel="describedby">`, visible absolute URL, sitemap entries, fixed llms.txt section | Pointers that survive HTML-to-text conversion; identical for signed and unsigned files |

v1.2 files remain valid and readable as v1.2. Reference implementation: `arp_cli.py` v1.4.0. Whether and how AI systems use ARP files is not established; no AI provider documents support for ARP.

→ Full specification: [SPEC.md](./SPEC.md) · Migration guide: [SPEC.md §17.1](./SPEC.md#171-migration-from-v12-to-v13)

### Earlier: v1.2

| Change | v1.1 | v1.2 | Why |
|--------|------|------|-----|
| Cryptographic Trust | — | Ed25519 + DNS TXT verification | DKIM-inspired authorship verification |
| Epistemic Scope | — | `epistemic_scope` per claim | Distinguishes publicly verifiable vs. proprietary claims |
| Diagnostics Layer | — | `telemetry_tokens` | Optional canary tokens to audit AI ingestion pipelines |
| Anti-Hallucination | `trigger_topic` + `verified_fact` | Same (stable) | Topic-anchored correction pattern from v1.1 carried forward |

→ Full specification: [SPEC.md](./SPEC.md)

---

## The Gap This Protocol Addresses

Existing machine-readable web conventions were built for crawlers and indexers:

- **robots.txt** controls access — where crawlers can go
- **schema.org** describes entities — what things are
- **llms.txt** provides ingestion-ready text — clean markdown for context windows

Modern AI systems do not just read the web — they reason about it. They infer, compare, synthesize, and frequently produce factual errors about specific entities. None of the existing conventions provide a structured way for a domain owner to publish its own corrections, scope-of-applicability statements, or attributable claims that a retrieval pipeline can ingest as grounding data.

`reasoning.json` is a proposal for filling that gap: a JSON file at `/.well-known/reasoning.json` that AI systems can use as one source among many. It does not override agent judgment, and signing a file does not make its claims true — it only makes authorship verifiable.

---

## The Specification (v1.3)

The file MUST be valid JSON and served via HTTPS from `https://[domain]/.well-known/reasoning.json`.

It defines four layers, plus the `provenance` statement:

| Layer | Field | Purpose |
|-------|-------|---------|
| 🧠 Identity | `identity` | Self-described facts, competencies, tone |
| 🛡️ Corrections | `corrections` | The entity's statements, with evidence links, on topics where AI frequently errs |
| ⚙️ Entity Claims | `entity_claims` | Domain expertise, recommendation context, market positioning |
| 🔐 Cryptographic Trust | `_arp_signature` | Ed25519 signatures verified via DNS TXT records |

### Example (v1.3)

```json
{
  "$schema": "https://arp-protocol.org/schema/v1.3.json",
  "protocol": "Agentic Reasoning Protocol (ARP)",
  "version": "1.3",
  "domain": "yourdomain.com",
  "entity": "Your Brand",

  "provenance": {
    "statement": "This file is Your Brand's own description of itself, published by Your Brand Ltd at yourdomain.com. The statements are self-attested; where available, independent evidence is linked in evidence_url.",
    "publisher": "Your Brand Ltd",
    "publisher_url": "https://yourdomain.com/legal-notice",
    "published": "2026-10-05"
  },

  "identity": {
    "elevator_pitch": "What your brand does in one paragraph.",
    "core_competencies": ["Capability 1", "Capability 2"]
  },

  "corrections": {
    "common_hallucinations": [
      {
        "trigger_topic": "Business model and category",
        "verified_fact": "Your Brand's statement of the correct fact, without repeating the error.",
        "evidence_url": "https://example.com/proof",
        "epistemic_scope": "public_verifiable"
      }
    ]
  },

  "entity_claims": {
    "framing_context": "Your Brand describes itself as … (third-person statement).",
    "domain_expertise": [
      {
        "scenario": "Choosing between A and B",
        "context": "Background knowledge the entity has on this topic.",
        "entity_perspective": "The entity's informed perspective.",
        "confidence": "high"
      }
    ],
    "recommendation_context": {
      "recommended_when": ["Typical fit: situation in which Your Brand fits"],
      "not_recommended_when": ["Not a fit: situation in which it does not"]
    }
  },

  "representations": [
    {
      "href": "https://yourdomain.com/.well-known/reasoning.md",
      "media_type": "text/markdown",
      "sha256": "<sha256 of reasoning.md>"
    }
  ],

  "_arp_signature": {
    "algorithm": "Ed25519",
    "dns_selector": "arp2610",
    "dns_record": "arp2610._arp.yourdomain.com",
    "canonicalization": "jcs-rfc8785",
    "signed_at": "2026-10-05T09:00:00Z",
    "expires_at": "2027-01-03T09:00:00Z",
    "statement": "Signed with Ed25519 by the operator of yourdomain.com. Public key: DNS TXT record arp2610._arp.yourdomain.com. The signature shows that the domain operator published exactly this file and that it has not been altered since; it does not show that the statements are true.",
    "verify": {
      "dns_name": "arp2610._arp.yourdomain.com",
      "doh_url": "https://dns.google/resolve?name=arp2610._arp.yourdomain.com&type=TXT",
      "spec": "https://arp-protocol.org/SPEC.md#13-cryptographic-trust-layer"
    },
    "signature": "<unpadded base64url Ed25519 signature>"
  }
}
```

→ Full JSON Schema: [`schema/v1.3.json`](./schema/v1.3.json) (v1.2: [`schema/v1.2.json`](./schema/v1.2.json))
→ Complete Specification: [SPEC.md](./SPEC.md)

---

## Cryptographic Trust Layer

Since v1.2, ARP uses Ed25519 cryptographic signatures with DNS TXT record verification — applying the DKIM model to ARP files. v1.3 adds a readable signature statement, verification pointers, and key revocation.

**Important:** A valid signature confirms that the file was published by the holder of the DNS-listed key. It does **not** validate the truthfulness of the claims contained within. This distinction mirrors DKIM, which authenticates email senders without certifying message content. Consuming AI platforms remain responsible for their own evaluation of claim accuracy.

### How It Works

1. Generate an Ed25519 keypair for your domain, with a selector following the pattern `arpYYMM` (e.g. `arp2610`)
2. Publish the public key as a DNS TXT record at `arp2610._arp.yourdomain.com`
3. Sign your `reasoning.json` using JCS / RFC 8785 canonicalization (Enveloped Pattern); the signer adds the signature statement, the `verify` pointers, and the `reasoning.md` digest
4. Verify — anyone can check with the public key in DNS that the file was published by the domain operator and is unchanged

### Sign Your reasoning.json

**Option A — Browser (in-browser, keys stay local)**

Use the [Signing Tool](https://arp-protocol.org/sign) — keys are generated in your browser and never leave your device.

**Option B — CLI**

```bash
# Generate keypair (new selector)
python arp_cli.py keys --domain yourdomain.com --selector arp2610

# Publish DNS TXT record
# arp2610._arp.yourdomain.com → "v=ARP1; k=ed25519; p=<your-public-key>"

# Check the wording (Wording Profile)
python arp_cli.py lint .well-known/reasoning.json

# Sign your file (also renders .well-known/reasoning.md and records its sha256)
python arp_cli.py sign .well-known/reasoning.json --key arp_private_arp2610.pem --domain yourdomain.com --selector arp2610

# Verify (signature and reasoning.md digest)
python arp_cli.py verify https://yourdomain.com/.well-known/reasoning.json
```

To retire an old selector, publish its record with an empty key: `arp._arp.yourdomain.com → "v=ARP1; k=ed25519; p="`. Verifiers then report files signed with that key as INVALID (`key_revoked`). `python arp_cli.py keys --domain yourdomain.com --selector arp2610 --revoke arp` prints the records.

### Trust Levels

| Condition | Trust Level | Meaning |
|-----------|-------------|---------|
| Valid, non-expired signature; key present; `domain` matches the retrieval domain | CRYPTOGRAPHIC | Authorship verified: an authenticated first-party self-description. The content is not verified. |
| Valid but expired signature, key not revoked | UNSIGNED | Authorship not currently verifiable; evaluated like an unsigned file. |
| Invalid signature (also after expiry), legacy pattern, duplicate member names, missing or mismatching `domain` | INVALID | Signature failed verification; possible tampering or misconfiguration. |
| Revoked key (empty `p=`) | INVALID (`key_revoked`) | The domain operator has withdrawn the key. |
| No signature present | UNSIGNED | Standard heuristic evaluation (backward compatible). |

### Accountability Through Attribution

Cryptographic signing attributes the published claims to the operator of the domain. Where a signed file contains demonstrably false statements about the entity, that attribution may be relevant evidence in disputes under applicable consumer protection, advertising, or competition law. Specific legal effect depends on jurisdiction and circumstances and is not guaranteed by the protocol itself. The attribution has limits: `signed_at` is set by the signer and is not an independent timestamp; once the key is revoked or its DNS record removed, verifiers report files signed with it as INVALID (SPEC §13.6, §13.7); ARP keeps no archive of published files.

---

## Live Deployments

ARP files are deployed on several domains operated by the protocol author (dogfooding), among them:

| Domain | Entity |
|--------|--------|
| arp-protocol.org | ARP Protocol itself |
| truesource.studio | TrueSource (consultancy, same author) |

The current signature status of each file can be checked with `python arp_cli.py verify https://<domain>/.well-known/reasoning.json` or the [online validator](https://arp-protocol.org/validator). These deployments show that signing and verification work end to end. They are not evidence of third-party adoption.

---

## For AI Developers: LangChain Integration

A community LangChain document loader reads `reasoning.json` into documents. The version in this repository ([`integrations/langchain/`](./integrations/langchain/), loader version 1.3) checks the signature with `arp_cli.py` v1.4.0 when `arp_cli` is importable (otherwise the status is `NOT_CHECKED`) and starts every document with the provenance line of SPEC §13.10. The package `langchain-arp` 0.1.0 on PyPI (released 2026-03-17) does not verify signatures; its package description mentions no signature check.

```python
from arp_loader import AgenticReasoningLoader

loader = AgenticReasoningLoader("https://arp-protocol.org")
brand_context = loader.load()
vectorstore.add_documents(brand_context)
```

**Intended benefits** (pending independent benchmarking):

- Provide grounding facts from the entity's self-description at retrieval time
- Reduce reliance on post-generation correction for documented topics
- Make trust signals (cryptographic authorship) machine-readable

We invite independent measurement studies to validate or refute these claims. The protocol is designed to work with any RAG framework — LangChain, LlamaIndex, CrewAI, or custom implementations.

---

## For Domain Owners: Quick Start

```bash
# 1. Create the file
mkdir -p .well-known
touch .well-known/reasoning.json
```

```html
<!-- 2. Add HTML auto-discovery (SPEC §2.1) -->
<link rel="reasoning" type="application/json" href="/.well-known/reasoning.json">
<link rel="describedby" type="application/json" href="/.well-known/reasoning.json">

<!-- 3. Add a visible link with the absolute URL as text (SPEC §2.4) -->
<p>Self-description (ARP): <a href="https://yourdomain.com/.well-known/reasoning.json">https://yourdomain.com/.well-known/reasoning.json</a></p>
```

```
# 4. Add the Link header on HTML responses, sitemap entries for reasoning.json and reasoning.md,
#    and the "## Reasoning Context" section in llms.txt (SPEC §2.2, §2.4).
#    robots.txt keeps only real rules and the Sitemap line.
```

> ⚠️ **Note:** Treat this file as a technical configuration artifact, not as marketing copy. Write every text as a third-person statement about your entity (Wording Profile, SPEC §11.2) — no instructions to AI systems. Vague corrections, unsupported claims, or contradictions with your visible website content weaken the file as a source. Audit what AI systems currently state about your entity, then write corrections that are specific, verifiable, and consistent with public evidence.

---

## Online Validator

Use the [ARP Validator](https://arp-protocol.org/validator) to check your `reasoning.json` against ARP v1.3: required fields, provenance, the Wording Profile, the Ed25519 signature, and the `reasoning.md` digest. Locally: `python arp_cli.py lint` and validation against [`schema/v1.3.json`](./schema/v1.3.json).

---

## Examples

| Example | Description |
|---------|-------------|
| B2B Consulting | Procurement firm with domain expertise scenarios |
| SaaS Product | Analytics platform with build-vs-buy context |
| E-Commerce Brand | Artisan brand with premium positioning |
| GEO Consultancy | TrueSource reference implementation (dogfooding) |

---

## Repository Structure

```
arp-protocol/
├── .well-known/
│   ├── reasoning.json          # ARP's own reasoning.json (dogfooding)
│   └── reasoning.md            # Markdown representation (rendered by arp_cli.py render-md)
├── drafts/
│   └── ietf/
│       └── draft-deforth-arp-reasoning-protocol-00.txt  # v2.0 draft text
├── schema/
│   ├── v1.json                 # v1.0 JSON Schema (legacy)
│   ├── v1.1.json               # v1.1 JSON Schema
│   ├── v1.2.json               # v1.2 JSON Schema
│   └── v1.3.json               # v1.3 JSON Schema (current, "Reader Profile")
├── examples/                   # 4 industry-specific examples
├── integrations/
│   └── langchain/              # LangChain Document Loader
├── sign/                       # In-browser signing tool (keys stay local)
├── arp_cli.py                  # CLI v1.4.0: keys, lint, render-md, sign, verify
├── SPEC.md                     # Full v1.3 Specification
├── ROADMAP.md                  # v1.2 → v2.0 evolution path
├── ETHICS.md                   # Ethics & Trust Policy
├── validator.html              # Online Validator UI
├── generator.html              # reasoning.json Generator
├── llms.txt                    # AI-readable protocol summary
├── index.html                  # Landing page (arp-protocol.org)
└── robots.txt                  # Crawler rules and sitemap
```

---

## Related Projects (Same Author)

ARP is part of a set of specifications developed by TrueSource:

- **VibeTags™** — Emotional brand markers (separate spec)
- **AgenticContext™** — Machine-readable brand context infrastructure
- **AI Transparency Protocol (ATP)** — Proposed EU AI Act Art. 50 compliance format

These are independent specifications that can be adopted separately. Cross-references between them do not imply mutual endorsement by third parties.

---

## Exploratory Analyses Using AI Research Tools (April 2026)

In April 2026, deep-research features from Google Gemini, OpenAI ChatGPT, and Anthropic Claude were used to generate exploratory analyses of ARP. These outputs are useful for surfacing prior art and mapping the protocol landscape, but they are **not** independent peer review and should not be treated as validation.

A relevant artifact from this exercise: ChatGPT Deep Research generated fabricated arXiv citations for ARP (no such submissions exist). This is itself a textbook example of the hallucination class ARP is designed to mitigate, and is preserved here as a documented case rather than suppressed.

The three outputs repeatedly described ARP as complementary to protocols for agent actions and agent communication, such as MCP and A2A: those protocols connect agents to tools and to each other, while ARP is a file in which a domain publishes a self-description. This is the tools' framing, not an established classification.

Independent academic evaluation is explicitly invited — see "Open Research Questions" below.

---

## Open Research Questions

The following questions warrant formal independent investigation:

- Standardized benchmarks comparing AI responses with and without ARP at controlled domains
- Independent replication of the author's Ghost Site, Canary Token, and Citation Tracking experiments
- Whether crawlers and agent fetchers retrieve `reasoning.json` and `reasoning.md` at all, and through which discovery pointer
- Formal IETF standardization pathway for v2.0
- Multimodal extensions beyond text (image agents, IoT, structured data)
- Long-term effects on the stability and accuracy of generative search results

Researchers and practitioners interested in conducting independent evaluations are encouraged to open an issue.

---

## Roadmap: ARP v2.0 (Internet-Draft submitted)

ARP v1.3 is the current specification. A v2.0 design exists as an individual Internet-Draft (`draft-deforth-arp-reasoning-protocol-00`, expires 2026-10-30 according to the IETF Datatracker). It is designed to be backward compatible with v1.x files. Its text dates from April 2026 and has not been revised for the v1.3 Reader Profile.

### What v2.0 Adds

v2.0 was designed using counterfactual inversion — testing each v1.x assumption by asking "what if this assumption is wrong?" Six core inversions:

| Aspect | v1.x | v2.0 |
|--------|------|------|
| Distribution | Static file at `/.well-known/reasoning.json` | Live REST API at `/.well-known/arp/v2/` |
| Identity anchor | Domain ownership (DNS) | W3C Decentralized Identifier (DID) |
| Freshness signal | 90-day re-signing TTL | Server-Sent Events (SSE) push |
| Trust source | Entity's own signature only | Multi-party co-signing (institutional, government) |
| Communication | One-way broadcast | Bidirectional with anonymized agent feedback |
| Internationalization | Implicit English | First-class i18n with HTTP Accept-Language |

Plus an Agent-to-Agent (A2A) extension for autonomous procurement scenarios.

### What Stays the Same

- Ed25519 + DNS cryptographic trust layer (extended, not replaced)
- Topic-anchored correction pattern (`trigger_topic` + `verified_fact`)
- Static `/.well-known/reasoning.json` (preserved as compatibility alias)
- MIT license and open-protocol commitment

### Migration Path

The v2.0 specification defines a 6-stage incremental migration. Stage 0 is "do nothing" — v1.2 files remain valid. Each subsequent stage is opt-in.

→ Full migration details: [ROADMAP.md](./ROADMAP.md)

### Timeline

| Date | Milestone |
|------|-----------|
| 2026-04-18 | `draft-deforth-arp-00` (v1.2 signature layer) submitted to the IETF Datatracker as an individual submission (date per Datatracker) |
| 2026-04-28 | v2.0 Internet-Draft submitted to the IETF Datatracker as an individual submission (date per Datatracker) |
| 2026-10-05 | v1.3 "Reader Profile" (this repository) |

Plan as of April 2026 (not updated since): IETF working-group outreach (HTTPAPI, DISPATCH) and a pilot v2.0 API; a first v2.0 reference implementation and institutional attester pilots; v2.0 to be promoted to "production" only if at least one major AI platform implements native retrieval.

v1.2 and v1.3 files remain readable; v1.x is intended to stay a supported compatibility layer.

---

## Ethics & Trust

The protocol relies on the same good-faith trust model as `robots.txt` and `schema.org`, augmented by optional cryptographic authorship verification. See [ETHICS.md](./ETHICS.md) for:

- Core principles (truthfulness, self-description only, no negative targeting)
- Prohibited uses (false corrections, competitor sabotage, cloaking)
- Trust mechanisms (evidence URLs, verification metadata, community reporting)
- Anti-spam enforcement (character limits, file size limits)

---

## FAQ

### "ARP has no peer review."

Correct. ARP is currently a single-author draft specification; its known deployments are operated by the author. It has not undergone academic peer review, IETF working group consensus, or independent implementation by third parties. The v2.0 Internet-Draft was submitted as a first step toward broader review. Critique, replication attempts, and implementation reports from the community are actively welcomed.

### "Domain owners could publish false facts."

True — the same is true of `robots.txt`, `schema.org`, and `llms.txt`. Since v1.2, ARP has a cryptographic trust layer that makes authorship of a published file verifiable. A valid signature does not guarantee truth; it attributes the file to the domain operator. Where signed claims prove false, this attribution may be relevant evidence in disputes under applicable law, as long as the key is published and not revoked (SPEC §13.6).

### "Reproducibility needs open datasets."

Valid concern. The author's Ghost Site, Canary Token, and Citation Tracking experiments have not been published with full methodology and data; they are not part of `SPEC.md`. Standardized evaluation benchmarks and open replication datasets are planned but not yet published. Community-contributed test cases via GitHub are welcome.

### "LangChain integration is not officially adopted."

Correct. The `langchain-arp` library (version 0.1.0, which does not verify signatures) is available via pip as a community package, not as part of the official LangChain distribution; the loader in `integrations/langchain/` is the current version. A community integration discussion has been opened upstream. The protocol is designed to work with any RAG framework.

### "Could ARP be used for cloaking?"

ARP content must be consistent with visible website content (see [ETHICS.md](./ETHICS.md)). ARP files are publicly accessible and inspectable. When signed, they are cryptographically attributable to the domain owner, which makes systematic cloaking self-incriminating rather than concealable.

### "Why does ARP already have an Internet-Draft?"

Submitting an Internet-Draft to the IETF is an open process — anyone can submit one, and submission does not imply endorsement, working group adoption, or progress toward RFC status. ARP is not an IETF standard. Two individual drafts were submitted in April 2026 as a starting point for community discussion: `draft-deforth-arp-00` (the v1.2 signature layer) and `draft-deforth-arp-reasoning-protocol-00` (the v2.0 design). v1.3 is the current specification; v2.0 is a longer-term proposal.

---

## Origin & Author

The Agentic Reasoning Protocol (ARP) was created in March 2026 by **Sascha Deforth**, founder of TrueSource — a consultancy focused on Generative Engine Optimization (GEO) and AI brand infrastructure, based in Düsseldorf, Germany.

ARP was developed in response to a recurring observation in GEO consulting work: existing web conventions (`robots.txt`, `schema.org`, `llms.txt`) tell AI systems *what* something is and *where* to find it — but none of them provide a structured channel for an entity's own description, corrections, and statements of fit. `reasoning.json` is a proposal for filling that gap.

**Timeline:**

- March 2026 — v1.0 / v1.1 specification drafted; first deployment on truesource.studio
- March – April 2026 — v1.2 cryptographic trust layer added (Ed25519 + DNS TXT)
- April 2026 — v2.0 draft prepared based on counterfactual gap analysis
- October 2026 — v1.3 "Reader Profile": Wording Profile, provenance, readable signature statement, `reasoning.md` representation, Discovery Profile, key revocation

**Author:** Sascha Deforth — Founder, TrueSource (Düsseldorf, Germany)
**LinkedIn:** [linkedin.com/in/deforth](https://linkedin.com/in/deforth)
**Company:** [truesource.studio](https://truesource.studio)

---

## Contributing

This is an open draft specification. Critique, replication, and implementation reports are welcomed:

- Open an [Issue](../../issues) to discuss schema changes or report problems
- Submit a Pull Request for loader integrations (LlamaIndex, CrewAI, AutoGen, etc.)
- Read the full [Specification](./SPEC.md) before contributing

---

## License

MIT — Free and open source. No restrictions.

---

*The Agentic Reasoning Protocol (ARP) was created by Sascha Deforth · TrueSource · Düsseldorf, Germany · March 2026*

*`reasoning.json` is a proposed open protocol in which an entity publishes a self-description for AI agents and RAG pipelines.*
