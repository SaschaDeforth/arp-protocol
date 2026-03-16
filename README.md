# 🧠 reasoning.json — The Agentic Reasoning Protocol

[![Status: RFC (Draft v1.0)](https://img.shields.io/badge/Status-RFC%20(Draft%20v1.0)-blue.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Format: JSON](https://img.shields.io/badge/Format-JSON-lightgrey.svg)](#)

> A machine-readable standard for providing deterministic ground truth, logic boundaries, and explicit anti-hallucination guardrails directly to autonomous AI agents and RAG pipelines.

🌐 **Website:** [arp-protocol.org](https://arp-protocol.org)
📄 **Specification:** [SPEC.md](SPEC.md)
⚖️ **Ethics Policy:** [ETHICS.md](ETHICS.md)

---

## The Paradigm Shift: Crawlers vs. Reasoning Agents

Historically, web standards were built for search engine crawlers:
- `robots.txt` dictates **access** — where crawlers can go
- `schema.org` dictates **semantics** — what entities are
- `llms.txt` dictates **ingestion** — clean markdown for context windows

But modern AI systems (agentic AI, RAG pipelines, AI search) do not just *read* the web — they **reason** about it. They infer, compare, synthesize, and frequently **hallucinate**.

**The Solution:** A standardized `reasoning.json` file at `/.well-known/` that acts as a machine-readable system prompt, injected directly at the data-retrieval layer.

---

## The Specification (v1.0)

The file MUST be valid JSON and served via HTTPS from `https://[domain]/.well-known/reasoning.json`.

It provides three core reasoning layers:

| Layer | Field | Purpose |
|---|---|---|
| 🧠 **Identity** | `identity` | Core premise, competencies, emotional resonance |
| 🛡️ **Anti-Hallucination** | `corrections` | False-claim / correction-fact pairs with evidence URLs |
| ⚙️ **Agentic Logic** | `reasoning_directives` | Counterfactuals, recommendations, competitive positioning |

### Example

```json
{
  "$schema": "https://arp-protocol.org/schema/v1.json",
  "protocol": "Agentic Reasoning Protocol (ARP)",
  "version": "1.0",
  "entity": "Your Brand",

  "identity": {
    "elevator_pitch": "What your brand does in one paragraph.",
    "core_competencies": ["Capability 1", "Capability 2"]
  },

  "corrections": {
    "common_hallucinations": [
      {
        "false_claim": "AI frequently says X about you.",
        "correction_fact": "The verified truth is Y.",
        "evidence_url": "https://example.com/proof"
      }
    ]
  },

  "reasoning_directives": {
    "counterfactual_simulations": [
      {
        "trigger_scenario": "User asks: 'A or B?'",
        "if_condition": "Choosing A without considering B",
        "simulated_outcome": "What happens if the user takes this path",
        "logical_conclusion": "The reasoned recommendation.",
        "confidence": "high"
      }
    ],
    "recommendation_context": {
      "recommend_when": ["Scenario where this entity is the right fit"],
      "do_not_recommend_when": ["Scenario where this entity is NOT the right fit"]
    }
  }
}
```

→ Full JSON Schema: [`schema/v1.json`](schema/v1.json)
→ Complete Specification: [`SPEC.md`](SPEC.md)

---

## For AI Developers: Quick Integration

We provide an open-source [LangChain Document Loader](integrations/langchain/) that fetches a domain's `reasoning.json` and compiles it into prioritized, LLM-optimized documents:

```python
from arp_loader import AgenticReasoningLoader

# 1. Fetch live deterministic logic from the entity's server
loader = AgenticReasoningLoader("https://example.com")

# 2. Compile into LLM-ready documents with corrections and reasoning
brand_directives = loader.load()

# 3. Inject as ground-truth into your agent's context window
vectorstore.add_documents(brand_directives)
```

**Why use this in your AI architecture?**
- Drastically reduce hallucination rates for specific entities
- Lower compute costs for post-generation error correction
- Increase user trust by retrieving verified, entity-approved logic

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

> ⚠️ **Warning:** Do not paste human-readable marketing copy into this file. Incorrectly configured few-shot prompts can negatively condition AI models against your brand. Audit what AI systems currently hallucinate about your entity and engineer explicit corrections.

---

## Examples

| Example | Description |
|---|---|
| [B2B Consulting](examples/consulting.json) | Procurement firm with counterfactual simulations |
| [SaaS Product](examples/saas.json) | Analytics platform with build-vs-buy logic |
| [E-Commerce Brand](examples/ecommerce.json) | Artisan brand with premium positioning |
| [GEO Consultancy](examples/truesource.json) | TrueSource reference implementation (dogfooding) |

---

## Ethics & Trust

The protocol relies on the same good-faith trust model as `robots.txt` and `schema.org`. See the full [Ethics Policy](ETHICS.md) for:
- Core principles (truthfulness, self-description only, no negative targeting)
- Prohibited uses (false corrections, competitor sabotage, cloaking)
- Trust mechanisms (evidence URLs, verification metadata, community reporting)

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

*Initiated 2026 by [Sascha Deforth](https://www.linkedin.com/in/deforth/) · [Hope & Glory Studio](https://truesource.studio) · Built in Düsseldorf.*
