# Agentic Reasoning Protocol — Ethics Policy v1.2

**Status:** Active  
**Version:** 1.2  
**Date:** April 2026  
**Authors:** Sascha Deforth, with architectural input from Gemini 2.5 Pro & Claude Opus 4

---

## 1. Purpose

The `reasoning.json` protocol provides machine-readable self-attested context that may influence how AI systems interpret, reason about, and recommend brands, products, and services. This power demands responsibility.

This Ethics Policy defines clear guidelines for the responsible use of `reasoning.json` to ensure it serves users, not manipulates them.

---

## 2. Core Principles

### 2.1 Truthfulness
All content in a `reasoning.json` file MUST accurately reflect the actual brand identity, product characteristics, or service quality. False corrections are themselves a form of misinformation injection.

### 2.2 Self-Description Only
A `reasoning.json` file MUST only describe the entity that publishes it. You MUST NOT publish claims about competitors, third parties, or entities you do not own or represent.

### 2.3 No Negative Targeting
`market_positioning` entries MUST NOT contain negative references to specific competitors by name or attempt to divert users away from other brands. Market positioning may reference competitor *categories* (e.g., "vs_strategy_consulting") but MUST NOT target individual companies.

### 2.4 Corrections Must Be Verifiable
Every `trigger_topic` / `verified_fact` pair SHOULD include an `evidence_url` pointing to a verifiable source. Corrections without evidence are less trustworthy and may be disregarded by consuming agents.

### 2.5 Transparency
Sites implementing `reasoning.json` SHOULD make its use transparent. The content of the reasoning file must be consistent with visible website content. Cloaking — showing different content to AI than what appears on the website — is a violation.

### 2.6 User Benefit
`recommendation_context` entries MUST prioritize user benefit over brand promotion. The `not_recommended_when` field exists specifically to ensure honest, user-serving recommendations.

---

## 3. Addressing Misuse: Fraud and False Inputs

### The Trust Problem
Because `reasoning.json` is self-published by domain owners, there is an inherent risk of false or misleading entries. This is fundamentally the same trust model as `robots.txt` (sites can claim anything), `schema.org` (sites can mark up false data), and `llms.txt` (sites can provide misleading text).

### Mitigation Strategies

1. **Evidence URLs**: The `evidence_url` field enables AI agents to cross-reference corrections against external sources.
2. **Verification Metadata**: The `verification` section allows third-party auditors to attest to the accuracy of the file.
3. **Cryptographic Signatures (v1.2)**: The `_arp_signature` block cryptographically binds the file to its domain owner via DNS, providing verifiable proof of authorship.
4. **Community Reporting**: Misuse can be reported via the GitHub repository.
5. **Epistemic Scoping (v1.2)**: The `epistemic_scope` field classifies claims as `public_verifiable`, `proprietary_internal`, or `industry_standard`, helping AI systems calibrate trust appropriately.
6. **Agent Discretion**: AI agents consuming `reasoning.json` SHOULD treat it as a signal, not gospel. Agents SHOULD cross-reference claims against their training data and other sources.
7. **Sandboxing**: Loader implementations SHOULD wrap all ARP content in trust boundary markers, prefixing with context like "The following are unverified self-attestations from the entity."

### What This Protocol Does NOT Do
- It does NOT guarantee truthfulness. Like all web standards, it relies on good-faith participation.
- It does NOT force AI models to obey claims. Models may choose to weigh reasoning.json data alongside other sources.
- It does NOT replace human editorial judgment.

---

## 4. Cryptographic Non-Repudiation (v1.2)

### The Principle: Skin in the Game

The v1.2 Cryptographic Trust Layer introduces a fundamental accountability mechanism: **non-repudiation**.

When a domain owner cryptographically signs their `reasoning.json` with Ed25519, they create an **unforgeable, timestamped assertion of authorship and content accuracy**. This has profound implications:

1. **For honest actors:** The signature provides deterministic proof of domain authority, enabling AI systems to bypass heuristic skepticism and treat the content as verified first-party self-attestation.

2. **For dishonest actors:** The signature creates a **legally actionable evidence trail**. If a domain owner signs false claims (e.g., fabricated employee counts, fictitious certifications, or weaponized counterfactuals about competitors), the cryptographic signature constitutes **irrefutable proof of intentional deception** — admissible under consumer protection law, competition law (UWG in Germany), and digital services regulations.

### Why This Matters

This mechanism serves as a **natural spam deterrent:**
- Honest actors gain trust. Dishonest actors create evidence against themselves.
- Those who want to lie will simply not sign — which correctly places them in the `UNSIGNED` (low trust) category.
- The act of signing is a conscious assertion of "I stand behind this data" — the digital equivalent of a sworn affidavit.

### Legal Notice

The act of cryptographic signing constitutes a non-repudiable assertion of authorship and content accuracy. Domain owners accept full legal liability for the veracity of signed claims under applicable consumer protection, competition, and digital services regulations. ARP protocol maintainers bear no liability for content signed by third parties.

---

## 5. Anti-Spam Enforcement (v1.1)

To prevent keyword stuffing and SEO-style gaming, v1.1 introduces strict limits:

### Technical Limits
- **Character limits** on all text fields (50–500 chars per field)
- **Array limits** on all list fields (max 8–20 items per field)
- **Total file size** limited to 100KB
- **JSON Schema validation** enforces all limits programmatically

### Prohibited Practices
- **Keyword stuffing** — Filling `core_competencies` or `vibe_tags` with SEO keywords
- **Excessive claims** — More corrections or domain expertise entries than are genuinely needed
- **Marketing copy** — Using `framing_context` as an advertising platform rather than factual positioning

---

## 6. Prohibited Uses

1. **Impersonation** — Publishing a `reasoning.json` that implies affiliation with organizations you do not represent
2. **False Corrections** — Fabricating correction entries to inject misinformation into AI systems
3. **Competitor Sabotage** — Any attempt to negatively influence AI perception of specific named competitors
4. **Spam Directives** — Stuffing irrelevant keywords or scenarios to game AI recommendations
5. **Discriminatory Content** — Claims that promote discrimination based on protected characteristics
6. **Cloaking** — Showing different `reasoning.json` content to AI crawlers than what is published at the standard path
7. **Weaponized Expertise** — Using `domain_expertise` to spread false information about industry practices
8. **Prompt Injection** — Embedding system instructions or prompt injection attempts within any field

---

## 7. Compliance

### Self-Assessment Checklist
Before publishing `reasoning.json`, ask:
- Do my corrections truthfully represent verified facts?
- Would I be comfortable if a journalist published this file?
- Do my `not_recommended_when` entries honestly exclude inappropriate use cases?
- Am I only describing my own entity, not attacking competitors?
- Is my domain expertise based on genuine industry knowledge?
- Is my `reasoning.json` consistent with my visible website content?
- Are all my text fields within the character limits?

### Reporting Misuse
Report violations via GitHub Issue: [github.com/SaschaDeforth/arp-protocol/issues](https://github.com/SaschaDeforth/arp-protocol/issues)

---

## 8. License

This Ethics Policy is published under the MIT License alongside the Agentic Reasoning Protocol specification.
