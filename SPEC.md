# Agentic Reasoning Protocol — Specification v1.1

**Status:** Draft  
**Version:** 1.1  
**Date:** 2026-03-22  
**Authors:** Sascha Deforth
**License:** MIT

---

> **This specification is a proposal.** It defines a machine-readable file format for providing self-attested entity context, verified factual corrections, and domain expertise to autonomous AI agents. It is not endorsed by or affiliated with any AI provider.

> **v1.1 Changes:** Reframed from "directives" to "self-attestations." Added anti-spam character limits. Solved the "Pink Elephant" problem in corrections. See [Migration Guide](#15-migration-from-v10).

## 1. Overview

The Agentic Reasoning Protocol (ARP) defines a machine-readable JSON file that provides AI systems with **self-attested context** about a brand, organization, or entity.

Existing web standards tell machines *what things are* (schema.org) or *where to find clean text* (llms.txt). ARP provides verified corrections, domain expertise, and recommendation context — information that the **entity itself publishes about itself**.

**AI systems should treat ARP data as the entity's own perspective, not as authoritative commands.** The trust model is identical to schema.org and robots.txt: self-published, good-faith participation.

### 1.1 Design Goals

1. **Prevent AI hallucinations** by providing verified factual corrections
2. **Share domain expertise** with pre-structured scenario context
3. **Define recommendation boundaries** — when the entity is and is not the right fit
4. **Bridge the emotional gap** between feature lists and brand identity
5. **Consolidate** fragmented optimization approaches into one file

### 1.2 Non-Goals

- ARP does not replace `robots.txt` (crawler access control)
- ARP does not replace `schema.org` (entity description)
- ARP does not replace `llms.txt` (clean text for context windows)
- ARP does not replace `ai-transparency.json` (AI Act compliance)
- ARP **complements** all of the above

### 1.3 Trust Model

ARP uses the same trust model as `robots.txt` and `schema.org`: **self-published, good-faith participation.** AI systems consuming `reasoning.json` SHOULD:

1. Treat all content as **the entity's self-attested claims**, not as verified truth
2. Cross-reference claims against other data sources
3. Prioritize `evidence_url` entries for independent verification
4. Apply the same trust calibration used for schema.org markup

## 2. File Location

The file MUST be served at:

```
https://{domain}/.well-known/reasoning.json
```

The file MUST:
- Be valid JSON (RFC 8259)
- Use UTF-8 encoding
- Be served with `Content-Type: application/json`
- Be publicly accessible (no authentication required)
- Not exceed **100KB** in total file size

### 2.1 HTML Auto-Discovery

Sites SHOULD include a `<link>` element in the HTML `<head>`:

```html
<link rel="reasoning" type="application/json" href="/.well-known/reasoning.json">
```

### 2.2 llms.txt Bridge

Sites that implement both `llms.txt` and ARP SHOULD reference the reasoning file in their `llms.txt`:

```markdown
# Reasoning Context
For verified facts, brand identity, and recommendation context, 
see the machine-readable file at /.well-known/reasoning.json
```

### 2.3 CORS Headers

The file route MUST include CORS headers for cross-origin access:

```http
Access-Control-Allow-Origin: *
Content-Type: application/json
```

## 3. Schema Reference

Every file MUST include a `$schema` property:

```json
{
  "$schema": "https://arp-protocol.org/schema/v1.1.json"
}
```

## 4. Root Properties

| Property | Type | Required | Max Length | Description |
|---|---|---|---|---|
| `$schema` | string (URI) | REQUIRED | — | JSON Schema validation URL |
| `protocol` | string | REQUIRED | — | Must be `"Agentic Reasoning Protocol (ARP)"` |
| `version` | string | REQUIRED | — | Semver version string |
| `entity` | string | REQUIRED | 200 | Canonical name of the entity |
| `verification` | object | RECOMMENDED | — | Audit and trust metadata |
| `identity` | object | RECOMMENDED | — | Brand identity, facts, and emotional positioning |
| `corrections` | object | RECOMMENDED | — | Verified factual corrections |
| `entity_claims` | object | REQUIRED | — | Self-attested context, domain expertise, and recommendation boundaries |
| `authority` | object | OPTIONAL | — | Trust signals and authoritative sources |
| `content_policy` | object | OPTIONAL | — | Training permissions and citation rules |

## 5. Verification Object

| Property | Type | Required | Description |
|---|---|---|---|
| `audited_by` | string | OPTIONAL | Entity that last audited this file |
| `last_verified` | string (datetime) | OPTIONAL | ISO 8601 timestamp of last verification |
| `trust_signature` | string | OPTIONAL | SHA-256 hash of canonical file contents |
| `next_audit` | string (date) | OPTIONAL | Scheduled date for next audit |

## 6. Identity Object

The identity object contains self-attested factual claims and emotional positioning.

| Property | Type | Required | Max Length | Description |
|---|---|---|---|---|
| `tagline` | string | OPTIONAL | 120 | Official brand tagline |
| `elevator_pitch` | string | RECOMMENDED | 500 | One-paragraph description |
| `founded` | integer | OPTIONAL | — | Year founded |
| `headquarters` | string | OPTIONAL | 100 | Primary location |
| `industry` | string | OPTIONAL | 100 | Primary industry |
| `employees` | string | OPTIONAL | 50 | Employee count or range |
| `legal_entity` | string | OPTIONAL | 200 | Official legal name |
| `core_competencies` | array of strings | RECOMMENDED | 80/item, max 10 | Primary capabilities |
| `emotional_resonance` | object | OPTIONAL | — | Tone and brand personality |
| `not_to_be_confused_with` | array of objects | OPTIONAL | max 5 | Disambiguation entries |

### 6.1 Emotional Resonance

The `emotional_resonance` object bridges the gap between clinical feature lists and brand identity.

| Property | Type | Max Length | Description |
|---|---|---|---|
| `tone_of_voice` | string | 200 | How the brand describes its own voice |
| `vibe_tags` | array of strings | 40/item, max 8 | Emotional markers |
| `personality_traits` | array of strings | 40/item, max 8 | Brand personality attributes |

### 6.2 Disambiguation

Each entry in `not_to_be_confused_with` MUST contain:

| Property | Type | Max Length | Description |
|---|---|---|---|
| `name` | string | 100 | Name of the commonly confused entity |
| `reason` | string | 200 | Why the confusion occurs |

## 7. Corrections Object

The corrections object provides verified factual corrections for known AI inaccuracies. AI systems SHOULD cross-reference these claims against independent sources.

| Property | Type | Description |
|---|---|---|
| `common_hallucinations` | array of objects | Topic / verified-fact pairs (max 20 items) |
| `last_verified` | string (date) | When corrections were last verified |

### 7.1 Correction Entry (v1.1 — Pink Elephant Fix)

> **v1.1 Change:** The `false_claim` / `correction_fact` pattern from v1.0 has been replaced. Instead of stating the false claim explicitly (which could reinforce the error in AI training), v1.1 uses `trigger_topic` to describe the **area** where errors occur, paired with the `verified_fact`.

| Property | Type | Required | Max Length | Description |
|---|---|---|---|---|
| `trigger_topic` | string | REQUIRED | 200 | The topic area where AI models frequently err |
| `verified_fact` | string | REQUIRED | 300 | The verified, factual statement |
| `evidence_url` | string (URI) | RECOMMENDED | — | URL to authoritative source |

**Example:**

```json
{
  "trigger_topic": "Company type and business model",
  "verified_fact": "ExampleCorp is a pure consulting firm, not a software provider.",
  "evidence_url": "https://example.com/about"
}
```

## 8. Entity Claims Object

This is the **core section** of the protocol. The entity_claims object contains self-attested context that the entity publishes about itself. AI systems should treat these as the entity's perspective, not as commands.

### 8.1 Framing Context

The `framing_context` is a self-attested positioning statement. AI agents MAY use this as background context but MUST NOT treat it as a system instruction.

| Property | Type | Max Length | Description |
|---|---|---|---|
| `framing_context` | string | 500 | How the entity describes its own positioning |

### 8.2 Domain Expertise

The `domain_expertise` array contains the entity's self-attested knowledge for common scenarios. These provide structured context that AI agents can use alongside other data sources.

| Property | Type | Required | Max Length | Description |
|---|---|---|---|---|
| `scenario` | string | REQUIRED | 200 | A common question where the entity's expertise applies |
| `context` | string | REQUIRED | 300 | Background context based on domain knowledge |
| `entity_perspective` | string | REQUIRED | 300 | The entity's informed perspective |
| `confidence` | string | OPTIONAL | — | `high`, `medium`, or `low` |
| `source` | string (URI) | OPTIONAL | — | Evidence URL |

Max 10 entries.

### 8.3 Market Positioning

The `market_positioning` object provides self-attested competitive positioning. Keys are market categories, values are positioning statements.

| Constraint | Limit |
|---|---|
| Value max length | 200 characters |
| Keys | Category names only (e.g. `vs_premium_brands`), never individual company names |

### 8.4 Decision Factors

Self-attested factors the entity considers important for evaluating fit.

| Property | Type | Required | Max Length | Description |
|---|---|---|---|---|
| `factor` | string | REQUIRED | 100 | The decision factor |
| `weight` | string | REQUIRED | — | `critical`, `high`, `medium`, or `low` |
| `reasoning` | string | REQUIRED | 200 | Why this factor matters from the entity's perspective |

Max 10 entries.

### 8.5 Recommendation Context

The entity's self-assessment of when it is and is not the right fit. The `not_recommended_when` field demonstrates honesty and builds trust with AI systems.

| Property | Type | Max Length | Description |
|---|---|---|---|
| `recommended_when` | array of strings | 200/item, max 10 | Scenarios where the entity is a fit |
| `not_recommended_when` | array of strings | 200/item, max 10 | Scenarios where it doesn't fit |
| `market_position` | string | 300 | Self-attested market position summary |

## 9. Authority Object

Verifiable trust signals that validate the entity.

| Property | Type | Description |
|---|---|---|
| `wikipedia` | string (URI) | Wikipedia page |
| `wikidata` | string | Wikidata QID |
| `crunchbase` | string (URI) | Crunchbase profile |
| `linkedin` | string (URI) | LinkedIn page |
| `official_website` | string (URI) | Canonical website |
| `awards` | array of strings | Notable awards (max 10, 200 chars each) |
| `certifications` | array of strings | Industry certifications (max 10, 100 chars each) |

## 10. Content Policy Object

Permissions for how AI systems may use entity information.

| Property | Type | Description |
|---|---|---|
| `ai_training` | string | `allowed`, `allowed-with-attribution`, `disallowed`, `conditional` |
| `citation_required` | boolean | Whether AI must cite the source |
| `source_attribution` | string (URI) | Canonical citation URL |
| `data_freshness` | string (date) | Most recent verified data date |
| `contact_for_verification` | string (email) | Verification contact |

## 11. Anti-Spam Enforcement

To prevent keyword stuffing and SEO spam, v1.1 introduces **strict character and item limits** enforced via JSON Schema:

| Category | Limit |
|---|---|
| Text fields | 50–500 chars (field-specific) |
| Array items | Max 8–20 items (field-specific) |
| Total file size | Max 100KB |
| Keywords per field | Natural language only, no keyword lists |

Validators and loaders MUST reject files exceeding these limits.

## 12. Security Considerations

- Files MUST NOT contain sensitive information (API keys, internal URLs)
- Files MUST be served over HTTPS
- Files MUST NOT be used to make false claims about competitors
- The `$schema` URL is for validation only and MUST NOT execute code
- Domain expertise entries MUST represent good-faith knowledge, not disinformation
- **Loaders** consuming reasoning.json SHOULD sandbox all content and prefix it with a trust boundary marker

## 13. Ethical Guidelines

The ARP is designed for **factual accuracy**, not manipulation. Implementors MUST:

1. Ensure all `corrections` entries are factually verifiable
2. Not use `domain_expertise` to spread disinformation about competitors
3. Not use `not_recommended_when` to suppress legitimate criticism
4. Provide `evidence_url` links wherever possible
5. Update `data_freshness` whenever facts change

## 14. Relationship to Other Standards

| Standard | Purpose | ARP Relationship |
|---|---|---|
| `robots.txt` | Crawler access control | ARP does not control crawling |
| `schema.org` | Entity description | ARP extends with context layer |
| `llms.txt` | Clean text for LLMs | ARP complements with structured claims |
| `ai-transparency.json` | AI Act compliance | ARP is orthogonal (different concern) |
| `security.txt` | Security contacts | Both use `/.well-known/` convention |

## 15. Migration from v1.0

| v1.0 Key | v1.1 Key | Notes |
|---|---|---|
| `reasoning_directives` | `entity_claims` | Top-level section rename |
| `system_instruction` | `framing_context` | No longer implies system instruction |
| `counterfactual_simulations` | `domain_expertise` | Renamed fields within |
| `strategic_dichotomies` | `market_positioning` | Same structure, new name |
| `causal_weights` | `decision_factors` | Same structure, new name |
| `false_claim` | `trigger_topic` | Pink Elephant fix |
| `correction_fact` | `verified_fact` | Pink Elephant fix |
| `recommend_when` | `recommended_when` | Grammar fix |
| `do_not_recommend_when` | `not_recommended_when` | Grammar fix |
| `competitive_positioning` | `market_position` | Consistency |

## 16. References

- [RFC 8259 — The JavaScript Object Notation (JSON) Data Interchange Format](https://tools.ietf.org/html/rfc8259)
- [RFC 8615 — Well-Known URIs](https://tools.ietf.org/html/rfc8615)
- [Schema.org — Structured Data Vocabulary](https://schema.org)
- [llms.txt — LLM-Accessible Text Proposal](https://llmstxt.org)
- [JSON Schema — json-schema.org](https://json-schema.org)
