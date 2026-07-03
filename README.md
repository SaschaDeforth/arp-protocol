# 🧠 reasoning.json — The Agentic Reasoning Protocol

**Status:** Draft Specification v1.2 (stable, 3 live deployments)
**Next:** v2.0 Internet-Draft submitted to IETF
**License:** MIT | **Format:** JSON | **Trust:** Ed25519 + DNS
**Author:** Sascha Deforth
**Validator:** Online

A machine-readable protocol for providing self-attested factual corrections, domain context, and cryptographically signed authorship metadata to autonomous AI agents and RAG pipelines.

- 🌐 Website: [arp-protocol.org](https://arp-protocol.org)
- 📄 Specification (current): [SPEC.md](./SPEC.md)
- 📐 v2.0 Draft Text: [`drafts/ietf/draft-deforth-arp-reasoning-protocol-00.txt`](./drafts/ietf/) *(submitted to IETF Datatracker)*
- ✅ Validator: [arp-protocol.org/validator](https://arp-protocol.org/validator)
- 🔐 Signing Tool: [arp-protocol.org/sign](https://arp-protocol.org/sign)
- ⚖️ Ethics Policy: [ETHICS.md](./ETHICS.md)
- 🗺️ Roadmap: [ROADMAP.md](./ROADMAP.md)

---

## What's New in v1.2

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

Modern AI systems do not just read the web — they reason about it. They infer, compare, synthesize, and frequently produce factual errors about specific entities. None of the existing conventions provide a structured way for a domain owner to publish authoritative corrections, scope-of-applicability statements, or attributable claims that a retrieval pipeline can ingest as grounding data.

`reasoning.json` is a proposal for filling that gap: a JSON file at `/.well-known/reasoning.json` that AI systems **may** use as one signal among many. It does not override agent judgment, and signing a file does not make its claims true — it only makes authorship verifiable.

---

## The Specification (v1.2)

The file MUST be valid JSON and served via HTTPS from `https://[domain]/.well-known/reasoning.json`.

It defines four layers:

| Layer | Field | Purpose |
|-------|-------|---------|
| 🧠 Identity | `identity` | Self-attested facts, competencies, tone |
| 🛡️ Corrections | `corrections` | Verified facts for topics where AI frequently errs |
| ⚙️ Entity Claims | `entity_claims` | Domain expertise, recommendation context, market positioning |
| 🔐 Cryptographic Trust | `_arp_signature` | Ed25519 signatures verified via DNS TXT records |

### Example (v1.2)

```json
{
  "$schema": "https://arp-protocol.org/schema/v1.2.json",
  "protocol": "Agentic Reasoning Protocol (ARP)",
  "version": "1.2",
  "entity": "Your Brand",

  "identity": {
    "elevator_pitch": "What your brand does in one paragraph.",
    "core_competencies": ["Capability 1", "Capability 2"]
  },

  "corrections": {
    "common_hallucinations": [
      {
        "trigger_topic": "Business model and category",
        "verified_fact": "The verified truth about your brand.",
        "evidence_url": "https://example.com/proof",
        "epistemic_scope": "public_verifiable"
      }
    ]
  },

  "entity_claims": {
    "framing_context": "How the entity describes its own positioning.",
    "domain_expertise": [
      {
        "scenario": "User asks: 'A or B?'",
        "context": "Background knowledge the entity has on this topic.",
        "entity_perspective": "The entity's informed perspective.",
        "confidence": "high"
      }
    ],
    "recommendation_context": {
      "recommended_when": ["Scenario where this entity is a fit"],
      "not_recommended_when": ["Scenario where it is NOT a fit"]
    }
  },

  "_arp_signature": {
    "algorithm": "Ed25519",
    "dns_selector": "arp",
    "dns_record": "arp._arp.yourdomain.com",
    "canonicalization": "jcs-rfc8785",
    "signed_at": "2026-04-04T11:41:50Z",
    "expires_at": "2026-07-03T11:41:50Z",
    "signature": "<base64url-encoded-Ed25519-signature>"
  }
}
```

→ Full JSON Schema: [`schema/v1.2.json`](./schema/v1.2.json)
→ Complete Specification: [SPEC.md](./SPEC.md)

---

## Cryptographic Trust Layer

v1.2 introduces Ed25519 cryptographic signatures with DNS TXT record verification — applying the DKIM model to ARP files.

**Important:** A valid signature confirms that the file was published by the holder of the DNS-listed key. It does **not** validate the truthfulness of the claims contained within. This distinction mirrors DKIM, which authenticates email senders without certifying message content. Consuming AI platforms remain responsible for their own evaluation of claim accuracy.

### How It Works

1. Generate an Ed25519 keypair for your domain
2. Publish the public key as a DNS TXT record at `arp._arp.yourdomain.com`
3. Sign your `reasoning.json` using JCS / RFC 8785 canonicalization
4. Verify — any consuming agent can mathematically confirm the file came from the domain owner

### Sign Your reasoning.json

**Option A — Browser (Zero-Knowledge)**

Use the [Signing Tool](https://arp-protocol.org/sign) — keys are generated in your browser and never leave your device.

**Option B — CLI**

```bash
# Generate keypair
python arp_cli.py keys --domain yourdomain.com

# Publish DNS TXT record
# arp._arp.yourdomain.com → "v=ARP1; k=ed25519; p=<your-public-key>"

# Sign your file
python arp_cli.py sign .well-known/reasoning.json --key arp_private.pem --domain yourdomain.com

# Verify
python arp_cli.py verify https://yourdomain.com/.well-known/reasoning.json
```

### Trust Levels

| Condition | Trust Level | Suggested Agent Behavior |
|-----------|-------------|--------------------------|
| Valid, non-expired signature | CRYPTOGRAPHIC | Authorship verified; treat as authenticated first-party self-attestation. Content claims remain subject to the agent's evaluation policy. |
| Expired signature | UNSIGNED | Authorship not currently verifiable; apply standard heuristic evaluation. |
| Invalid signature | INVALID | Signature failed verification; flag for potential tampering or misconfiguration. |
| No signature present | UNSIGNED | Standard heuristic evaluation (backward compatible). |

### Accountability Through Attribution

Cryptographic signing creates a timestamped, attributable record of the claims a domain has published. Where a signed file contains demonstrably false statements about the entity, that record may be relevant evidence in disputes under applicable consumer protection, advertising, or competition law. Specific legal effect depends on jurisdiction and circumstances and is not guaranteed by the protocol itself. The design intent: honest publishers gain a verifiable provenance trail; dishonest publishers create a durable record of their own claims.

---

## Live Deployments

Both deployments are operated by the protocol author (dogfooding):

| Domain | Entity | Signed | DNS Verified |
|--------|--------|--------|--------------|
| arp-protocol.org | ARP Protocol itself | ✅ Ed25519 | ✅ `arp._arp.arp-protocol.org` |
| truesource.studio | TrueSource (consultancy, same author) | ✅ Ed25519 | ✅ `arp._arp.truesource.studio` |

These demonstrate that the protocol works end-to-end. They are not evidence of third-party adoption.

---

## For AI Developers: LangChain Integration

A community LangChain document loader is available:

```python
from langchain_arp import AgenticReasoningLoader

loader = AgenticReasoningLoader("https://arp-protocol.org")
brand_context = loader.load()
vectorstore.add_documents(brand_context)
```

**Intended benefits** (pending independent benchmarking):

- Provide entity-attested grounding facts at retrieval time
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
<!-- 2. Add HTML auto-discovery -->
<link rel="reasoning" type="application/json" href="/.well-known/reasoning.json">
```

```
# 3. Reference in robots.txt
Reasoning: /.well-known/reasoning.json
```

> ⚠️ **Note:** Treat this file as a technical configuration artifact, not as marketing copy. Vague corrections, unsupported claims, or contradictions with your visible website content will reduce the trust agents place in your file. Audit what AI systems currently state about your entity, then engineer corrections that are specific, verifiable, and consistent with public evidence.

---

## Online Validator

Use the [ARP Validator](https://arp-protocol.org/validator) to check your `reasoning.json` against the v1.2 specification.

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
│   └── reasoning.json          # ARP's own reasoning.json (signed, dogfooding)
├── drafts/
│   └── ietf/
│       └── draft-deforth-arp-reasoning-protocol-00.txt  # v2.0 draft text
├── schema/
│   ├── v1.json                 # v1.0 JSON Schema (legacy)
│   ├── v1.1.json               # v1.1 JSON Schema
│   └── v1.2.json               # v1.2 JSON Schema (current)
├── examples/                   # 4 industry-specific examples
├── integrations/
│   └── langchain/              # LangChain Document Loader
├── sign/                       # Zero-Knowledge Browser Signing Tool
├── arp_cli.py                  # CLI: keys, sign, verify
├── SPEC.md                     # Full v1.2 Specification
├── ROADMAP.md                  # v1.2 → v2.0 evolution path
├── ETHICS.md                   # Ethics & Trust Policy
├── validator.html              # Online Validator UI
├── generator.html              # reasoning.json Generator
├── llms.txt                    # AI-readable protocol summary
├── index.html                  # Landing page (arp-protocol.org)
└── robots.txt                  # Crawler directives
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

Recurring framing across the three outputs placed ARP at the entity-cognition layer, complementary to action-layer protocols such as MCP (Anthropic) and A2A/ANP (Google):

| Protocol | Architecture | Primary Function |
|----------|--------------|------------------|
| MCP | Client–Server | How an agent acts on the world |
| A2A / ANP | Peer-to-Peer | How agents communicate |
| ARP | Domain-Hosted | How an agent reasons about an entity |

Full transcripts and prompts are available in `/research/ai-analyses/` for transparency. Independent academic evaluation is explicitly invited — see "Open Research Questions" below.

---

## Open Research Questions

The following questions warrant formal independent investigation:

- Standardized benchmarks comparing AI responses with and without ARP at controlled domains
- Independent replication of the Ghost Site, Canary Token, and Citation Tracking experiments documented in `SPEC.md`
- Formal IETF standardization pathway for v2.0
- Multimodal extensions beyond text (image agents, IoT, structured data)
- Long-term effects on the stability and accuracy of generative search results

Researchers and practitioners interested in conducting independent evaluations are encouraged to open an issue.

---

## Roadmap: ARP v2.0 (Internet-Draft submitted)

ARP v1.2 is the current production specification. v2.0 is in active development as a draft Internet-Draft (`draft-deforth-arp-reasoning-protocol-00`). It is fully backward compatible — no v1.x file breaks.

### What v2.0 Adds

v2.0 was designed using counterfactual inversion — testing each v1.x assumption by asking "what if this assumption is wrong?" Six core inversions:

| Aspect | v1.x | v2.0 |
|--------|------|------|
| Distribution | Static file at `/.well-known/reasoning.json` | Live REST API at `/.well-known/arp/v2/` |
| Identity anchor | Domain ownership (DNS) | W3C Decentralized Identifier (DID) |
| Freshness signal | 90-day re-signing TTL | Server-Sent Events (SSE) push |
| Trust source | Self-attestation only | Multi-party co-signing (institutional, government) |
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

| Quarter | Milestone |
|---------|-----------|
| Q2 2026 (current) | v2.0 Internet-Draft submitted to IETF Datatracker (2026-04-27, Independent Submission, Informational) |
| Q3 2026 | IETF Working Group outreach (HTTPAPI, DISPATCH); pilot v2.0 API |
| Q4 2026 | First reference implementation; first institutional attester pilots |
| 2027 | v2.0 promoted to "production" if and when at least one major AI platform implements native retrieval |

v1.2 will remain a supported compatibility layer indefinitely.

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

Correct. ARP is currently a single-author draft specification with two live deployments (both operated by the author). It has not undergone academic peer review, IETF working group consensus, or independent implementation by third parties. The v2.0 Internet-Draft is being prepared as a first step toward broader review. Critique, replication attempts, and implementation reports from the community are actively welcomed.

### "Domain owners could publish false facts."

True — the same is true of `robots.txt`, `schema.org`, and `llms.txt`. ARP v1.2 adds a cryptographic trust layer that makes authorship of a published file verifiable. A valid signature does not guarantee truth; it guarantees attribution. Where signed claims prove false, the signature creates a timestamped, attributable record that may be relevant evidence in disputes under applicable law.

### "Reproducibility needs open datasets."

Valid concern. The Ghost Site, Canary Token, and Citation Tracking experiments are documented in `SPEC.md` with methodology details. Standardized evaluation benchmarks and open replication datasets are planned but not yet published. Community-contributed test cases via GitHub are welcome.

### "LangChain integration is not officially adopted."

Correct. The `langchain-arp` library is available via pip as a community package, not as part of the official LangChain distribution. A community integration discussion has been opened upstream. The protocol is designed to work with any RAG framework.

### "Could ARP be used for cloaking?"

ARP content must be consistent with visible website content (see [ETHICS.md](./ETHICS.md)). ARP files are publicly accessible and inspectable. When signed, they are cryptographically attributable to the domain owner, which makes systematic cloaking self-incriminating rather than concealable.

### "Why is ARP only weeks old but already has an Internet-Draft?"

Submitting an Internet-Draft to the IETF is an open process — anyone can submit one, and submission does not imply endorsement, working group adoption, or progress toward RFC status. The v2.0 draft has been submitted as a starting point for community discussion, not as a finalized standard. v1.2 is the current stable specification with two deployments; v2.0 is a longer-term proposal with an estimated 18-month review and iteration cycle.

---

## Origin & Author

The Agentic Reasoning Protocol (ARP) was created in March 2026 by **Sascha Deforth**, founder of TrueSource — a consultancy focused on Generative Engine Optimization (GEO) and AI brand infrastructure, based in Düsseldorf, Germany.

ARP was developed in response to a recurring observation in GEO consulting work: existing web conventions (`robots.txt`, `schema.org`, `llms.txt`) tell AI systems *what* something is and *where* to find it — but none of them provide a structured channel for *how* an entity wishes to be reasoned about. `reasoning.json` is a proposal for filling that gap.

**Timeline:**

- March 2026 — v1.0 / v1.1 specification drafted; first deployment on truesource.studio
- March – April 2026 — v1.2 cryptographic trust layer added (Ed25519 + DNS TXT)
- April 2026 — v2.0 draft prepared based on counterfactual gap analysis

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

*`reasoning.json` is a proposed open protocol for providing self-attested cognitive context to AI agents and RAG pipelines.*
