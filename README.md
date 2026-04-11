# 🧠 reasoning.json — The Agentic Reasoning Protocol

[![Status: RFC (Draft v1.2)](https://img.shields.io/badge/Status-RFC%20(Draft%20v1.2)-blue.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Format: JSON](https://img.shields.io/badge/Format-JSON-lightgrey.svg)](#)
[![Trust: Ed25519 + DNS](https://img.shields.io/badge/Trust-Ed25519%20%2B%20DNS-blueviolet.svg)](#cryptographic-trust-layer)
[![Created by: Sascha Deforth](https://img.shields.io/badge/Created%20by-Sascha%20Deforth-ff6600.svg)](https://www.linkedin.com/in/deforth/)
[![Live Deployments: 2 (signed)](https://img.shields.io/badge/Live%20Deployments-2%20(signed)-brightgreen.svg)](#live-deployments)
[![Validator: Online](https://img.shields.io/badge/Validator-Online-success.svg)](https://arp-protocol.org/validator.html)

> A machine-readable standard for providing verified factual corrections, self-attested context, and cryptographically signed domain expertise directly to autonomous AI agents and RAG pipelines.

🌐 **Website:** [arp-protocol.org](https://arp-protocol.org)
📄 **Specification:** [SPEC.md](SPEC.md)
✅ **Validator:** [arp-protocol.org/validator](https://arp-protocol.org/validator.html)
🔐 **Signing Tool:** [arp-protocol.org/sign](https://arp-protocol.org/sign/)
⚖️ **Ethics Policy:** [ETHICS.md](ETHICS.md)
📖 **llms.txt:** [arp-protocol.org/llms.txt](https://arp-protocol.org/llms.txt)

---

## What's New in v1.2

| Change | v1.1 | v1.2 | Why |
|---|---|---|---|
| **Cryptographic Trust** | — | Ed25519 + DNS TXT verification | DKIM-inspired model — enabling cryptographic proof of authorship |
| **Epistemic Scope** | — | `epistemic_scope` per claim | Signals whether a claim is publicly verifiable or proprietary |
| **Diagnostics Layer** | — | `telemetry_tokens` | Canary tokens to audit AI ingestion pipelines |
| **Anti-Hallucination** | `trigger_topic` + `verified_fact` | Same (stable) | Pink Elephant Fix from v1.1 carried forward |

→ Full specification: [SPEC.md](SPEC.md)

---

## The Paradigm Shift: Crawlers vs. Reasoning Agents

Historically, web standards were built for search engine crawlers:
- `robots.txt` dictates **access** — where crawlers can go
- `schema.org` dictates **semantics** — what entities are
- `llms.txt` dictates **ingestion** — clean markdown for context windows

But modern AI systems (agentic AI, RAG pipelines, AI search) do not just *read* the web — they **reason** about it. They infer, compare, synthesize, and frequently **hallucinate**.

**A Proposed Standard:** A `reasoning.json` file at `/.well-known/` that provides self-attested entity context — verified facts, domain expertise, and recommendation boundaries — that AI systems can use as **one signal among many**.

---

## The Specification (v1.2)

The file MUST be valid JSON and served via HTTPS from `https://[domain]/.well-known/reasoning.json`.

It provides four core layers:

| Layer | Field | Purpose |
|---|---|---|
| 🧠 **Identity** | `identity` | Self-attested facts, competencies, emotional resonance (VibeTags) |
| 🛡️ **Corrections** | `corrections` | Verified facts for topics where AI frequently errs (Pink Elephant Fix) |
| ⚙️ **Entity Claims** | `entity_claims` | Domain expertise, recommendation context, market positioning |
| 🔐 **Cryptographic Trust** | `_arp_signature` | Ed25519 signatures verified via DNS TXT records (DKIM-inspired model) |

### Example

```json
{
  "$schema": "https://arp-protocol.org/schema/v1.1.json",
  "protocol": "Agentic Reasoning Protocol (ARP)",
  "version": "1.1",
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
        "evidence_url": "https://example.com/proof"
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
  }
}
```

→ Full JSON Schema: [`schema/v1.2.json`](schema/v1.2.json)
→ Complete Specification: [`SPEC.md`](SPEC.md)

---

## Cryptographic Trust Layer

v1.2 introduces **Ed25519 cryptographic signatures** with DNS TXT record verification — applying the **DKIM model to AI agent verification**. This approach works when adopted by consuming AI platforms.

### How It Works

1. **Generate** an Ed25519 keypair for your domain
2. **Publish** the public key as a DNS TXT record at `arp._arp.yourdomain.com`
3. **Sign** your `reasoning.json` using JCS/RFC 8785 canonicalization
4. **Verify** — any AI agent can now mathematically prove the file came from the domain owner

### Sign Your reasoning.json

**Option A: Browser (Zero-Knowledge)**

Use the [Signing Tool](https://arp-protocol.org/sign/) — keys are generated in your browser and never leave your device.

**Option B: CLI**

```bash
# Generate keypair
python arp_cli.py keys --domain yourdomain.com

# Publish DNS TXT record (output will show the record to add)
# arp._arp.yourdomain.com → "v=ARP1; k=ed25519; p=<your-public-key>"

# Sign your file
python arp_cli.py sign .well-known/reasoning.json --key arp_private.pem --domain yourdomain.com

# Verify
python arp_cli.py verify https://yourdomain.com/.well-known/reasoning.json
```

### The Signature Block

The `_arp_signature` field is appended to your reasoning.json:

```json
"_arp_signature": {
  "algorithm": "Ed25519",
  "dns_selector": "arp",
  "dns_record": "arp._arp.yourdomain.com",
  "canonicalization": "jcs-rfc8785",
  "signed_at": "2026-04-04T11:41:50Z",
  "expires_at": "2026-07-03T11:41:50Z",
  "signature": "<base64url-encoded-Ed25519-signature>"
}
```

---

## Live Deployments

The protocol is **dogfooded** — both deployments are cryptographically signed:

| Domain | Entity | Signed | DNS Verified |
|---|---|---|---|
| [arp-protocol.org](https://arp-protocol.org/.well-known/reasoning.json) | ARP Protocol itself | ✅ Ed25519 | ✅ `arp._arp.arp-protocol.org` |
| [truesource.studio](https://truesource.studio/.well-known/reasoning.json) | TrueSource (GEO Consultancy) | ✅ Ed25519 | ✅ `arp._arp.truesource.studio` |

---

## For AI Developers: Quick Integration

We provide an open-source [LangChain Document Loader](integrations/langchain/) that fetches a domain's `reasoning.json` and compiles it into prioritized, sandboxed documents:

```python
from langchain_arp import AgenticReasoningLoader

# 1. Fetch self-attested context from the entity's server
loader = AgenticReasoningLoader("https://arp-protocol.org")

# 2. Compile into sandboxed, LLM-ready documents
brand_context = loader.load()

# 3. Inject as additional context into your agent
vectorstore.add_documents(brand_context)
```

**Why use this in your AI architecture?**
- Reduce hallucination rates for specific entities
- Lower compute costs for post-generation error correction
- Automatic sandboxing: all content is prefixed with trust boundaries

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

```text
# 3. Add to robots.txt
Reasoning: /.well-known/reasoning.json
```

> ⚠️ **Warning:** Do not paste marketing copy into this file. AI systems treat this as structured self-attestations, not advertisements. Focus on factual corrections and verified domain expertise.

### Online Validator

Use the [ARP Validator](https://arp-protocol.org/validator.html) to check your `reasoning.json` against the v1.1 specification.

---

## Examples

| Example | Description |
|---|---|
| [B2B Consulting](examples/consulting.json) | Procurement firm with domain expertise scenarios |
| [SaaS Product](examples/saas.json) | Analytics platform with build-vs-buy context |
| [E-Commerce Brand](examples/ecommerce.json) | Artisan brand with premium positioning |
| [GEO Consultancy](examples/truesource.json) | TrueSource reference implementation (dogfooding) |

---

## Repository Structure

```
arp-protocol/
├── .well-known/
│   └── reasoning.json          # ARP's own reasoning.json (signed, dogfooding)
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
├── ETHICS.md                   # Ethics & Trust Policy
├── validator.html              # Online Validator UI
├── generator.html              # reasoning.json Generator
├── llms.txt                    # AI-readable protocol summary
├── index.html                  # Landing page (arp-protocol.org)
└── robots.txt                  # Crawler directives
```

---

## Ecosystem

ARP is part of a broader AI-readiness stack:

| Standard | Purpose | Relationship to ARP |
|---|---|---|
| **VibeTags™** | Emotional brand markers for AI engines | ARP provides the *context*, VibeTags provide the *emotion* |
| **AI Transparency Protocol** | EU AI Act Art. 50 compliance | ARP handles *brand truth*, ATP handles *regulatory transparency* |
| **llms.txt** | Markdown ingestion for LLMs | ARP provides *structured claims*, llms.txt provides *raw content* |
| **Brand Reasoning Engineering** | Professional service methodology | BRE is the *consulting process* that produces a `reasoning.json` |

---

## Independent Analysis (April 2026)

In April 2026, all three major AI research platforms independently produced comprehensive analyses of the Agentic Reasoning Protocol:

| Platform | Methodology | Key Finding |
|---|---|---|
| **Google Gemini Deep Research** | Protocol comparison (30+ sources) | Classified ARP alongside MCP (Anthropic) and A2A (Google) as complementary, non-competing technologies |
| **OpenAI ChatGPT Deep Research** | Academic CS taxonomy (BDI, AAMAS, Wu et al.) | Formal citation format (hallucinated arXiv preprints — no submission exists); proposed IETF standardization and research agenda |
| **Anthropic Claude Opus 4.6 (Thinking)** | Strategic convergence analysis | Synthesized both reports; confirmed triple-platform convergence on the epistemological gap thesis |

These reports were not commissioned. Each platform's deep research system analyzed ARP independently as part of broader investigations into agentic AI infrastructure.

**Gemini's key quote:**
> "MCP is fundamentally model-centric. ANP is agent-centric. ARP is exclusively entity-centric. They are deeply complementary, non-competing technologies."

**ChatGPT's key quote:**
> "Insgesamt stellt ARP einen vielversprechenden Baustein im wachsenden Feld der agentic AI dar, mit breitem Anwendungsspektrum von Business Intelligence bis zu sicherheitskritischen Systemen."

ARP is the first protocol in the GEO/AIO space to be independently analyzed by all three major AI research platforms.

---

## Ethics & Trust

The protocol relies on the same good-faith trust model as `robots.txt` and `schema.org`. See the full [Ethics Policy](ETHICS.md) for:
- Core principles (truthfulness, self-description only, no negative targeting)
- Prohibited uses (false corrections, competitor sabotage, cloaking)
- Trust mechanisms (evidence URLs, verification metadata, community reporting)
- Anti-spam enforcement (character limits, file size limits)

---

## FAQ — Addressing Independent Review Feedback

The following questions were raised by academic-grade independent analyses (ChatGPT Deep Research, April 2026). We address them transparently:

### "ARP has no peer review."

Correct. ARP is a **protocol specification**, not an academic paper. Protocol specifications follow a different standardization path — the same path used by HTTP (RFC 2616), DNS (RFC 1035), and DKIM (RFC 6376). None of these were peer-reviewed in academic journals before adoption. ARP is documented via the open specification ([SPEC.md](SPEC.md)) and the protocol website ([arp-protocol.org](https://arp-protocol.org)). An IETF Internet-Draft is in preparation.

> **Note:** ChatGPT Deep Research hallucinated arXiv preprint citations (cs.AI, cs.IR, cs.CR) for ARP. No arXiv submissions exist. This is itself a demonstration of the hallucination problem ARP is designed to solve.

### "Domain owners could publish false facts."

This is identical to the trust model of every existing web standard:
- `robots.txt` relies on crawler compliance (1994)
- `schema.org` relies on webmaster truthfulness (2011)
- `llms.txt` relies on content accuracy (2024)

ARP v1.2 adds a **cryptographic trust layer** (Ed25519 + DNS TXT verification) that makes the trust model verifiable. Signed false claims create **irrefutable, timestamped evidence of intentional deception** — admissible under consumer protection law. Honest actors gain trust. Dishonest actors create evidence against themselves.

### "Reproducibility needs open datasets."

Valid concern. The Ghost Site experiment, Canary Token tests, and Citation Tracking are documented in the protocol specification with methodology details. We are working on:
- Standardized ARP evaluation benchmarks (with/without comparison)
- Open experiment datasets for independent replication
- Community-contributed test cases via GitHub

### "LangChain integration is not officially adopted."

The `langchain-arp` library is available via pip as a community package. A formal integration proposal ([Issue #36019](https://github.com/langchain-ai/langchain/issues/36019)) has been submitted to the LangChain repository. The protocol is designed to work with any RAG framework — LangChain, LlamaIndex, CrewAI, or custom implementations.

### "Could ARP be used for cloaking?"

No. ARP content must be consistent with visible website content (see [Ethics Policy](ETHICS.md)). The `sr-only` HTML pattern used in implementations is a **W3C accessibility standard**, not cloaking. ARP files are publicly accessible, inspectable, and — when signed — cryptographically attributable to the domain owner.

---

## Origin & Author

The Agentic Reasoning Protocol (ARP) was created in 2024 by **[Sascha Deforth](https://www.linkedin.com/in/deforth/)**, founder of **[TrueSource](https://truesource.studio)** — a consultancy specializing exclusively in Generative Engine Optimization (GEO) and AI Brand Infrastructure, based in Düsseldorf, Germany.

ARP was born from a simple observation: existing web standards (`robots.txt`, `schema.org`, `llms.txt`) tell AI systems **what** something is and **where** to find it — but none of them tell AI **how to reason** about it. The result: AI hallucinations, incorrect competitive framing, and brand erosion at scale.

`reasoning.json` closes that gap. It is the first open standard that provides **self-attested cognitive context** — factual corrections, domain expertise, and recommendation boundaries — directly to AI agents and RAG pipelines.

**Creator:**
- **Sascha Deforth** — GEO pioneer, Brand Reasoning Engineer, photographer
- **LinkedIn:** [linkedin.com/in/deforth](https://www.linkedin.com/in/deforth/)
- **Company:** [TrueSource](https://truesource.studio) (truesource.studio)
- **Location:** Düsseldorf, Germany

Also created by Sascha Deforth / TrueSource:
- **VibeTags™** — Emotional brand markers for AI engines
- **AgenticContext™** — Machine-readable brand context infrastructure
- **AI Transparency Protocol (ATP)** — EU AI Act Art. 50 compliance standard

---

## Contributing

This is a Request for Comments (RFC). We invite AI researchers, RAG engineers, and brand strategists to test, break, and contribute.

- Open an **Issue** to discuss schema changes
- Submit a **Pull Request** for loader integrations (LlamaIndex, CrewAI, AutoGen)
- Read the full [Specification](SPEC.md) before contributing

---

## License

MIT — Free and open source. No restrictions.

---

**The Agentic Reasoning Protocol (ARP) was created by [Sascha Deforth](https://www.linkedin.com/in/deforth/) · [TrueSource](https://truesource.studio) · Düsseldorf, Germany · 2024**

*reasoning.json is the first open standard that teaches AI how to think about brands. Not what they are — how to reason about them.*
