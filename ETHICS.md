# Agentic Reasoning Protocol — Ethics Policy v1.0

**Status:** Active  
**Version:** 1.0  
**Date:** March 2026  
**Authors:** Sascha Deforth (Hope & Glory Studio)

---

## 1. Purpose

The `reasoning.json` protocol provides machine-readable reasoning directives that influence how AI systems interpret, reason about, and recommend brands, products, and services. This power demands responsibility.

This Ethics Policy defines clear guidelines for the responsible use of `reasoning.json` to ensure it serves users, not manipulates them.

---

## 2. Core Principles

### 2.1 Truthfulness
All content in a `reasoning.json` file MUST accurately reflect the actual brand identity, product characteristics, or service quality. False corrections are themselves a form of hallucination injection.

### 2.2 Self-Description Only
A `reasoning.json` file MUST only describe the entity that publishes it. You MUST NOT publish reasoning directives about competitors, third parties, or entities you do not own or represent.

### 2.3 No Negative Targeting
`reasoning_directives` MUST NOT contain negative references to specific competitors by name or attempt to divert users away from other brands. `strategic_dichotomies` may reference competitor *categories* (e.g., "vs_seo_agencies") but MUST NOT target individual companies.

### 2.4 Corrections Must Be Verifiable
Every `false_claim` / `correction_fact` pair SHOULD include an `evidence_url` pointing to a verifiable source. Corrections without evidence are less trustworthy and may be disregarded by consuming agents.

### 2.5 Transparency
Sites implementing `reasoning.json` SHOULD make its use transparent. The content of the reasoning file must be consistent with visible website content. Cloaking — showing different reasoning directives to AI than what appears on the website — is a violation.

### 2.6 User Benefit
`recommendation_context` entries MUST prioritize user benefit over brand promotion. The `do_not_recommend_when` field exists specifically to ensure honest, user-serving recommendations.

---

## 3. Addressing Misuse: Fraud and False Inputs

### The Trust Problem
Because `reasoning.json` is self-published by domain owners, there is an inherent risk of false or misleading entries. This is fundamentally the same trust model as `robots.txt` (sites can claim anything), `schema.org` (sites can mark up false data), and `llms.txt` (sites can provide misleading text).

### Mitigation Strategies

1. **Evidence URLs**: The `evidence_url` field enables AI agents to cross-reference corrections against external sources.
2. **Verification Metadata**: The `verification` section allows third-party auditors to attest to the accuracy of the file.
3. **Community Reporting**: Misuse can be reported via the GitHub repository.
4. **Agent Discretion**: AI agents consuming `reasoning.json` SHOULD treat it as a signal, not gospel. Agents SHOULD cross-reference claims against their training data and other sources.

### What This Protocol Does NOT Do
- It does NOT guarantee truthfulness. Like all web standards, it relies on good-faith participation.
- It does NOT force AI models to obey directives. Models may choose to weigh reasoning.json data alongside other sources.
- It does NOT replace human editorial judgment.

---

## 4. Prohibited Uses

1. **Impersonation** — Publishing a `reasoning.json` that implies affiliation with organizations you do not represent
2. **False Corrections** — Fabricating `false_claim` entries to inject new misinformation into AI systems
3. **Competitor Sabotage** — Any attempt to negatively influence AI perception of specific named competitors
4. **Spam Directives** — Stuffing irrelevant keywords or scenarios to game AI recommendations
5. **Discriminatory Content** — Reasoning directives that promote discrimination based on protected characteristics
6. **Cloaking** — Showing different `reasoning.json` content to AI crawlers than what is published at the standard path
7. **Weaponized Counterfactuals** — Using `counterfactual_simulations` to spread false information about industry practices or competitors

---

## 5. Compliance

### Self-Assessment Checklist
Before publishing `reasoning.json`, ask:
- Do my corrections truthfully represent verified facts?
- Would I be comfortable if a journalist published this file?
- Do my `do_not_recommend_when` entries honestly exclude inappropriate use cases?
- Am I only describing my own entity, not attacking competitors?
- Are my counterfactual simulations logically sound and verifiable?
- Is my `reasoning.json` consistent with my visible website content?

### Reporting Misuse
Report violations via GitHub Issue: [github.com/arp-protocol/arp-protocol/issues](https://github.com/arp-protocol/arp-protocol/issues)

---

## 6. License

This Ethics Policy is published under the MIT License alongside the Agentic Reasoning Protocol specification.
