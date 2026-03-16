# reasoning.json — The Agentic Reasoning Protocol

> schema.org taught machines what things are.  
> **reasoning.json teaches machines how to think about them.**

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](LICENSE)
[![Standard: v1.0 Draft](https://img.shields.io/badge/Standard-v1.0_Draft-00ffd5.svg)](#)

---

## What is this?

The **Agentic Reasoning Protocol (ARP)** defines a machine-readable JSON file at `/.well-known/reasoning.json` that teaches AI systems how to reason about a brand, organization, or entity.

While `schema.org` tells machines *what things are* and `llms.txt` tells them *where to find clean text*, `reasoning.json` tells them **how to think** — with counterfactual simulations, hallucination corrections, and reasoning directives.

## The Problem

AI systems:
- 🎭 **Hallucinate** — fabricate founding dates, headquarters, and product features
- 🔄 **Commoditize** — flatten every brand into identical feature bullet points
- 🤷 **Guess** — when users ask "what if" questions, AI invents answers instead of using domain expertise

No existing standard provides machine-readable reasoning directives.

## The Solution

A single JSON file at `/.well-known/reasoning.json` that provides:

| Capability | What it does |
|---|---|
| 🧠 Counterfactual Simulations | Pre-programmed "what-if" logic chains |
| ✅ Hallucination Corrections | False-claim/correction pairs for RAG overrides |
| 🎯 Recommendation Context | When to recommend (and when not to) |
| 💎 Emotional Resonance | Tone, personality, and brand soul |
| ⚖️ Strategic Dichotomies | Competitive positioning logic |
| 🛡️ Brand Disambiguation | "Not to be confused with" entries |

## Quick Start

```bash
# 1. Create the file
mkdir -p .well-known
touch .well-known/reasoning.json
```

```html
<!-- 2. Add HTML discovery -->
<link rel="reasoning" type="application/json" href="/.well-known/reasoning.json">
```

See the [Specification](SPEC.md) for the full format or use the [JSON Schema](schema/v1.json) for validation.

## Examples

- [B2B Consulting](examples/consulting.json) — Procurement firm with counterfactual simulations
- [SaaS Product](examples/saas.json) — Analytics platform with build-vs-buy logic
- [E-Commerce Brand](examples/ecommerce.json) — Artisan brand with premium positioning

## Specification

📄 [Read the full specification →](SPEC.md)

## License

MIT — Free and open source. No restrictions.

## Author

Created by [Sascha Deforth](https://www.linkedin.com/in/deforth/) · [Antigravity Ventures](https://truesource.studio)
