# Agentic Reasoning Protocol — Ethics Policy v1.2

**Status:** Active
**Version:** 1.2
**Date:** April 2026
**Author:** Sascha Deforth

---

## 1. Purpose

The `reasoning.json` protocol provides machine-readable self-attested context that may influence how AI systems interpret, reason about, and recommend brands, products, and services. Because the publisher controls what enters this channel, the protocol depends on responsible use to be useful at all.

This Ethics Policy defines guidelines for the responsible use of `reasoning.json` so that it serves users rather than manipulates them.

---

## 2. Core Principles

### 2.1 Truthfulness
All content in a `reasoning.json` file MUST accurately reflect the actual brand identity, product characteristics, or service quality. False corrections are themselves a form of misinformation injection.

### 2.2 Self-Description Only
A `reasoning.json` file MUST only describe the entity that publishes it. You MUST NOT publish claims about competitors, third parties, or entities you do not own or represent.

### 2.3 No Negative Targeting
`market_positioning` entries MUST NOT contain negative references to specific competitors by name or attempt to divert users away from other brands. Market positioning may reference competitor *categories* (e.g., `vs_strategy_consulting`) but MUST NOT target individual companies.

### 2.4 Corrections Must Be Verifiable
Every `trigger_topic` / `verified_fact` pair SHOULD include an `evidence_url` pointing to a verifiable source. Corrections without evidence are weaker signals and may be disregarded by consuming agents.

### 2.5 Transparency
Sites implementing `reasoning.json` SHOULD make its use transparent. The content of the reasoning file must be consistent with visible website content. Cloaking — showing different content to AI than what appears on the website — is a violation of this policy.

### 2.6 User Benefit
`recommendation_context` entries MUST prioritize user benefit over brand promotion. The `not_recommended_when` field exists specifically to make honest, user-serving recommendations possible.

---

## 3. Addressing Misuse: Fraud and False Inputs

### The Trust Problem

Because `reasoning.json` is self-published by domain owners, there is an inherent risk of false or misleading entries. This is fundamentally the same trust model as `robots.txt` (sites can claim anything), `schema.org` (sites can mark up false data), and `llms.txt` (sites can provide misleading text). ARP does not, and cannot, eliminate this risk.

### Mitigation Strategies

1. **Evidence URLs.** The `evidence_url` field enables consuming agents to cross-reference corrections against external sources.
2. **Verification Metadata.** The `verification` section allows third-party auditors to attest to the accuracy of the file.
3. **Cryptographic Signatures (v1.2).** The `_arp_signature` block cryptographically binds the file to its domain owner via DNS, providing verifiable proof of authorship (not of truth — see §4).
4. **Community Reporting.** Misuse can be reported via the GitHub repository.
5. **Epistemic Scoping (v1.2).** The `epistemic_scope` field classifies claims as `public_verifiable`, `proprietary_internal`, or `industry_standard`, helping consuming systems calibrate trust appropriately.
6. **Agent Discretion.** AI agents consuming `reasoning.json` SHOULD treat it as one signal, not as authoritative truth, and SHOULD cross-reference claims against their training data and other sources.
7. **Sandboxing.** Loader implementations SHOULD wrap all ARP content in trust boundary annotations, prefixing with context such as "The following are unverified self-attestations from the entity."

### What This Protocol Does NOT Do

- It does NOT guarantee truthfulness. Like all web standards, it relies on good-faith participation.
- It does NOT force AI models to obey claims. Models may weigh `reasoning.json` data alongside other sources, or ignore it entirely.
- It does NOT replace human editorial judgment.
- A valid cryptographic signature does NOT certify content accuracy. It certifies authorship only.

---

## 4. Cryptographic Authorship and Accountability (v1.2)

### What Signing Does

The v1.2 Cryptographic Trust Layer enables a domain owner to produce an Ed25519 signature over their `reasoning.json` that is verifiable against a public key published in DNS. A valid signature confirms that the file was published by the holder of the DNS-listed key. It does **not** confirm that the contents are true. This is the same property DKIM provides for email and HTTPS provides for web servers: verified identity, not verified content.

### Why It Matters Anyway

Even though signing does not certify truth, it changes the publisher's incentives in a useful way:

1. **For honest publishers.** A signature provides cryptographic evidence that a specific entity stood behind a specific version of a file at a specific time. Consuming systems and downstream observers can verify this independently.

2. **For dishonest publishers.** A signature creates a timestamped, attributable record of exactly what was published. If signed claims later prove false, the signature makes it difficult for the publisher to disclaim authorship.

The act of signing is therefore a deliberate assertion: "I, the holder of this key, published this content on this date." Publishers who would prefer not to make that assertion can simply leave their files unsigned, which correctly places the file in a lower-trust category.

### Legal Considerations

Where a signed `reasoning.json` contains demonstrably false claims, the signature creates an attributable record that may be relevant evidence in disputes under applicable consumer protection, advertising, or competition law (including, in Germany, the *Gesetz gegen den unlauteren Wettbewerb* / UWG). The specific legal effect depends on jurisdiction, the nature of the claim, the harm caused, and other circumstances. Nothing in this Ethics Policy or the ARP specification should be construed as legal advice or as a guarantee of any particular legal outcome.

ARP protocol maintainers bear no liability for content published or signed by third parties.

---

## 5. Anti-Spam Enforcement (v1.1)

To prevent keyword stuffing and SEO-style gaming, v1.1 introduces strict limits:

### Technical Limits
- **Character limits** on all text fields (50–500 chars per field)
- **Array limits** on all list fields (max 8–20 items per field)
- **Total file size** limited to 100 KB
- **JSON Schema validation** enforces all limits programmatically

### Prohibited Practices
- **Keyword stuffing** — Filling `core_competencies` or `vibe_tags` with SEO keywords
- **Excessive claims** — More corrections or domain expertise entries than are genuinely needed
- **Marketing copy** — Using `framing_context` as an advertising platform rather than for factual positioning

---

## 6. Prohibited Uses

1. **Impersonation** — Publishing a `reasoning.json` that implies affiliation with organizations you do not represent
2. **False Corrections** — Fabricating `corrections` entries to inject misinformation into AI systems
3. **Competitor Sabotage** — Any attempt to negatively influence AI perception of specific named competitors
4. **Spam Directives** — Stuffing irrelevant keywords or scenarios to game AI recommendations
5. **Discriminatory Content** — Claims that promote discrimination based on protected characteristics
6. **Cloaking** — Publishing a `reasoning.json` whose content materially contradicts the visible website
7. **Weaponized Expertise** — Using `domain_expertise` to spread false information about industry practices
8. **Prompt Injection** — Embedding system instructions or prompt injection attempts within any field
9. **Diagnostic Token Misuse** — Using `telemetry_tokens` (§12 of the specification) for anything other than benign ingestion auditing — in particular, MUST NOT be used to attempt to deanonymize users, fingerprint sessions, or carry hidden instructions

---

## 7. Compliance

### Self-Assessment Checklist

Before publishing `reasoning.json`, ask:

- Do my corrections truthfully represent verified facts?
- Would I be comfortable if a journalist published this file alongside an analysis of my actual practices?
- Do my `not_recommended_when` entries honestly exclude inappropriate use cases?
- Am I describing only my own entity, not making claims about competitors?
- Is my domain expertise based on genuine knowledge, not invented authority?
- Is my `reasoning.json` consistent with my visible website content?
- Are all my text fields within the character limits?
- If I have signed the file, am I prepared to stand behind every claim it contains?

### Reporting Misuse

Report violations via GitHub Issue: [github.com/SaschaDeforth/arp-protocol/issues](https://github.com/SaschaDeforth/arp-protocol/issues)

---

## 8. License

This Ethics Policy is published under the MIT License alongside the Agentic Reasoning Protocol specification.
