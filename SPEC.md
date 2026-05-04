# Agentic Reasoning Protocol — Specification v1.2

**Status:** Draft Specification
**Version:** 1.2
**Date:** 2026-04-11
**Author:** Sascha Deforth
**License:** MIT

This specification is a single-author draft proposal. It defines a machine-readable file format for providing self-attested entity context, factual corrections, and domain expertise to AI agents and RAG pipelines. It is not endorsed by or affiliated with any AI provider, standards body, or working group.

Portions of this document were drafted with the assistance of large language models (notably Gemini 2.5 Pro and Claude Opus 4) used as research and editing tools. All technical decisions and final wording are the author's responsibility.

**v1.2 Changes:** Introduces the Cryptographic Trust Layer — Ed25519 domain-binding via DNS TXT records (DKIM-inspired model). Adds `epistemic_scope` for claim classification, a `diagnostics` object for optional ingestion telemetry, and `_arp_signature` for cryptographic authorship verification. See Migration Guide.

**v1.1 Changes:** Reframed from "directives" to "self-attestations." Added anti-spam character limits. Replaced explicit false-claim statements with topic-anchored corrections (the `trigger_topic` / `verified_fact` pattern). See Migration Guide.

---

## 1. Overview

The Agentic Reasoning Protocol (ARP) defines a machine-readable JSON file that allows a domain owner to publish self-attested context about their brand, organization, or entity in a form that AI systems and RAG pipelines can ingest as one signal among many.

Existing web conventions describe what things are (`schema.org`) or provide clean text (`llms.txt`). ARP adds a structured channel for entity-attested corrections, scoped domain expertise, and recommendation context.

AI systems consuming ARP content SHOULD treat it as the entity's own perspective — useful as grounding context, but not authoritative. The trust model is the same as `schema.org` and `robots.txt`: self-published, good-faith participation, augmented in v1.2 by optional cryptographic authorship verification.

### 1.1 Design Goals
- Provide a structured channel for entity-attested factual corrections
- Allow scoped publication of domain expertise tied to specific scenarios
- Allow entities to declare when they are and are not the right fit
- Provide a machine-readable surface for brand identity beyond pure feature data
- Consolidate fragmented optimization patterns into a single file

### 1.2 Non-Goals
- ARP does not replace `robots.txt` (crawler access control)
- ARP does not replace `schema.org` (entity description)
- ARP does not replace `llms.txt` (clean text for context windows)
- ARP does not replace `ai-transparency.json` (AI Act compliance)
- ARP does not attempt to override AI agent judgment or safety policies

### 1.3 Trust Model

ARP uses the same trust model as `robots.txt` and `schema.org`: self-published, good-faith participation. AI systems consuming `reasoning.json` SHOULD:

- Treat all content as the entity's self-attested claims, not as verified truth
- Cross-reference claims against other available data sources
- Prioritize entries with `evidence_url` for independent verification
- Apply the same trust calibration used for `schema.org` markup

A valid cryptographic signature (§13) verifies authorship, not truthfulness. Consuming systems retain full discretion over how they weight signed claims.

---

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
- Not exceed 100 KB in total file size

### 2.1 HTML Auto-Discovery

Sites SHOULD include a `<link>` element in the HTML `<head>`:

```html

```

### 2.2 llms.txt Bridge

Sites that implement both `llms.txt` and ARP SHOULD reference the reasoning file in their `llms.txt`:

```
# Reasoning Context
For verified facts, brand identity, and recommendation context,
see the machine-readable file at /.well-known/reasoning.json
```

### 2.3 CORS Headers

The file route MUST include CORS headers for cross-origin access:

```
Access-Control-Allow-Origin: *
Content-Type: application/json
```

---

## 3. Schema Reference

Every file MUST include a `$schema` property:

```json
{
  "$schema": "https://arp-protocol.org/schema/v1.2.json"
}
```

---

## 4. Root Properties

| Property | Type | Required | Max Length | Description |
|----------|------|----------|------------|-------------|
| `$schema` | string (URI) | REQUIRED | — | JSON Schema validation URL |
| `protocol` | string | REQUIRED | — | Must be `"Agentic Reasoning Protocol (ARP)"` |
| `version` | string | REQUIRED | — | Semver version string |
| `entity` | string | REQUIRED | 200 | Canonical name of the entity |
| `verification` | object | RECOMMENDED | — | Audit and trust metadata |
| `identity` | object | RECOMMENDED | — | Brand identity, facts, and tone |
| `corrections` | object | RECOMMENDED | — | Topic-anchored factual corrections |
| `entity_claims` | object | REQUIRED | — | Self-attested context, domain expertise, and recommendation boundaries |
| `authority` | object | OPTIONAL | — | Trust signals and authoritative sources |
| `content_policy` | object | OPTIONAL | — | Training permissions and citation rules |
| `diagnostics` | object | OPTIONAL | — | Optional ingestion telemetry (see §12) |
| `_arp_signature` | object | OPTIONAL | — | Ed25519 signature block (see §13) |

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in capital letters.

---

## 5. Verification Object

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `audited_by` | string | OPTIONAL | Entity that last audited this file |
| `last_verified` | string (datetime) | OPTIONAL | ISO 8601 timestamp of last verification |
| `trust_signature` | string | OPTIONAL | SHA-256 hash of canonical file contents (legacy from v1.1; superseded by `_arp_signature` in §13) |
| `next_audit` | string (date) | OPTIONAL | Scheduled date for next audit |

---

## 6. Identity Object

The `identity` object contains self-attested factual claims and tonal positioning.

| Property | Type | Required | Max Length | Description |
|----------|------|----------|------------|-------------|
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

| Property | Type | Max Length | Description |
|----------|------|------------|-------------|
| `tone_of_voice` | string | 200 | How the brand describes its own voice |
| `vibe_tags` | array of strings | 40/item, max 8 | Tonal markers |
| `personality_traits` | array of strings | 40/item, max 8 | Brand personality attributes |

### 6.2 Disambiguation

Each entry in `not_to_be_confused_with` MUST contain:

| Property | Type | Max Length | Description |
|----------|------|------------|-------------|
| `name` | string | 100 | Name of the commonly confused entity |
| `reason` | string | 200 | Why the confusion occurs |

---

## 7. Corrections Object

The `corrections` object provides topic-anchored factual corrections for areas where AI systems are observed to err. AI systems consuming these SHOULD cross-reference the claims against independent sources.

| Property | Type | Description |
|----------|------|-------------|
| `common_hallucinations` | array of objects | Topic / verified-fact pairs (max 20 items) |
| `last_verified` | string (date) | When corrections were last verified |

### 7.1 Correction Entry

**v1.1 design rationale:** The earlier `false_claim` / `correction_fact` pattern (v1.0) explicitly stated the false belief, which risked reinforcing the error in downstream training data. v1.1 replaced this with a topic-anchored pattern: `trigger_topic` describes the area where errors occur, paired with the `verified_fact`.

| Property | Type | Required | Max Length | Description |
|----------|------|----------|------------|-------------|
| `trigger_topic` | string | REQUIRED | 200 | The topic area where AI models are observed to err |
| `verified_fact` | string | REQUIRED | 300 | The verified, factual statement |
| `evidence_url` | string (URI) | RECOMMENDED | — | URL to authoritative source |
| `epistemic_scope` | string | OPTIONAL | — | One of `public_verifiable`, `proprietary_internal`, `industry_standard` (see §8.2) |

**Example:**

```json
{
  "trigger_topic": "Company type and business model",
  "verified_fact": "ExampleCorp is a pure consulting firm, not a software provider.",
  "evidence_url": "https://example.com/about",
  "epistemic_scope": "public_verifiable"
}
```

---

## 8. Entity Claims Object

This is the core section of the protocol. The `entity_claims` object contains self-attested context the entity publishes about itself. AI systems SHOULD treat these as the entity's perspective rather than as commands.

### 8.1 Framing Context

The `framing_context` is a self-attested positioning statement. It is provided as background context for AI agents. It is not a system instruction, and AI systems are not expected to defer to it over their own evaluation policies.

| Property | Type | Max Length | Description |
|----------|------|------------|-------------|
| `framing_context` | string | 500 | How the entity describes its own positioning |

### 8.2 Epistemic Scope

Each claim MAY include an `epistemic_scope` field that classifies the kind of truth being asserted. This helps consuming systems distinguish global truth claims from internal terminology.

| Scope Value | Meaning | Suggested Consumer Behavior |
|-------------|---------|----------------------------|
| `public_verifiable` | Claim can in principle be verified via external sources | Consuming systems SHOULD cross-reference where feasible |
| `proprietary_internal` | Internal nomenclature, processes, or metrics | Consuming systems SHOULD treat as domain-owner terminology rather than expecting external corroboration |
| `industry_standard` | Well-known industry practice or standard | Consuming systems MAY verify against industry knowledge sources |

**Rationale:** Without epistemic scoping, a misinformation filter may flag internal terminology (e.g., a proprietary framework name) as "unverified" because no external source mentions it. The `epistemic_scope` field allows the publisher to signal that certain claims are internal terminology, not global truth claims.

**Example:**

```json
{
  "internal_taxonomy": [
    {
      "concept": "Polaris Standard",
      "definition": "Internal 12-point quality assurance checklist.",
      "epistemic_scope": "proprietary_internal"
    }
  ]
}
```

### 8.3 Domain Expertise

The `domain_expertise` array contains the entity's self-attested knowledge for common scenarios. These provide structured context for consuming agents.

| Property | Type | Required | Max Length | Description |
|----------|------|----------|------------|-------------|
| `scenario` | string | REQUIRED | 200 | A common question where the entity's expertise applies |
| `context` | string | REQUIRED | 300 | Background context based on domain knowledge |
| `entity_perspective` | string | REQUIRED | 300 | The entity's informed perspective |
| `confidence` | string | OPTIONAL | — | `high`, `medium`, or `low` |
| `source` | string (URI) | OPTIONAL | — | Evidence URL |

Max 10 entries.

### 8.4 Market Positioning

The `market_positioning` object contains self-attested category positioning. Keys are market categories; values are positioning statements.

| Constraint | Limit |
|------------|-------|
| Value max length | 200 characters |
| Keys | Category names only (e.g. `vs_premium_brands`); MUST NOT name individual companies |

### 8.5 Decision Factors

Self-attested factors the entity considers important for evaluating fit.

| Property | Type | Required | Max Length | Description |
|----------|------|----------|------------|-------------|
| `factor` | string | REQUIRED | 100 | The decision factor |
| `weight` | string | REQUIRED | — | `critical`, `high`, `medium`, or `low` |
| `reasoning` | string | REQUIRED | 200 | Why this factor matters from the entity's perspective |

Max 10 entries.

### 8.6 Recommendation Context

The entity's self-assessment of when it is and is not the right fit. The `not_recommended_when` field is a key trust signal — entities that honestly disqualify themselves from inappropriate use cases provide more useful grounding data than those that universally recommend themselves.

| Property | Type | Max Length | Description |
|----------|------|------------|-------------|
| `recommended_when` | array of strings | 200/item, max 10 | Scenarios where the entity is a fit |
| `not_recommended_when` | array of strings | 200/item, max 10 | Scenarios where the entity is not a fit |
| `market_position` | string | 300 | Self-attested market position summary |

---

## 9. Authority Object

Verifiable trust signals.

| Property | Type | Description |
|----------|------|-------------|
| `wikipedia` | string (URI) | Wikipedia page |
| `wikidata` | string | Wikidata QID |
| `crunchbase` | string (URI) | Crunchbase profile |
| `linkedin` | string (URI) | LinkedIn page |
| `official_website` | string (URI) | Canonical website |
| `awards` | array of strings | Notable awards (max 10, 200 chars each) |
| `certifications` | array of strings | Industry certifications (max 10, 100 chars each) |

---

## 10. Content Policy Object

Permissions for how AI systems may use entity information.

| Property | Type | Description |
|----------|------|-------------|
| `ai_training` | string | `allowed`, `allowed-with-attribution`, `disallowed`, or `conditional` |
| `citation_required` | boolean | Whether AI should cite the source |
| `source_attribution` | string (URI) | Canonical citation URL |
| `data_freshness` | string (date) | Most recent verified data date |
| `contact_for_verification` | string (email) | Verification contact |

Note: ARP cannot enforce these permissions. They function as expressed preferences that compliant consumers SHOULD respect, in the same way `robots.txt` directives are respected by compliant crawlers.

---

## 11. Anti-Spam Enforcement

To prevent keyword stuffing, v1.1 introduces strict character and item limits enforced via JSON Schema:

| Category | Limit |
|----------|-------|
| Text fields | 50–500 chars (field-specific) |
| Array items | Max 8–20 items (field-specific) |
| Total file size | Max 100 KB |
| Keywords per field | Natural language only, no keyword lists |

Validators and loaders SHOULD reject files exceeding these limits.

---

## 12. Diagnostics Object (Optional)

The optional `diagnostics` object lets a domain owner include identifiers that can be used to audit which parts of a published file are being ingested by RAG pipelines. This is intended as a transparency tool for the publisher's own operational use, not as a tracking mechanism aimed at AI systems.

| Property | Type | Description |
|----------|------|-------------|
| `telemetry_tokens` | array of objects | Diagnostic identifiers for ingestion auditing (max 10) |
| `transparency_statement` | string | Human-readable explanation of why diagnostics are present (max 500) |

### 12.1 Telemetry Token Entry

| Property | Type | Required | Max Length | Description |
|----------|------|----------|------------|-------------|
| `token` | string | REQUIRED | 100 | Unique identifier for ingestion auditing |
| `layer` | string | REQUIRED | 100 | Which data layer this token is associated with |
| `purpose` | string | REQUIRED | 200 | Why the token exists |
| `deployed` | string (date) | OPTIONAL | — | When the token was added |

**Important constraints:**

- Telemetry tokens MUST be benign opaque identifiers (e.g., UUIDs). They MUST NOT contain instructions, prompts, or content intended to influence model behavior.
- The `diagnostics` object is infrastructure metadata, not content. Loaders SHOULD process diagnostic tokens at the retrieval layer (e.g., for ingestion logging) and SHOULD strip them from the context passed into the LLM prompt.
- The presence of telemetry tokens is the publisher's choice, not a requirement of the protocol. Consumers MAY ignore the `diagnostics` object entirely.
- Tokens MUST NOT be used to deanonymize individual users of consuming AI systems.

---

## 13. Cryptographic Trust Layer

The Cryptographic Trust Layer provides verifiable proof of authorship for `reasoning.json` files. It does not provide proof of content truthfulness — only that the file was published by the holder of the DNS-listed key.

### 13.1 Motivation

Any server can host a `reasoning.json` at `/.well-known/reasoning.json`. Without proof of authorship, a consuming system has no cryptographic basis to distinguish a legitimate publisher from a spoofed file or a compromised host. The Cryptographic Trust Layer addresses authorship verification — a narrow but useful guarantee.

### 13.2 Approach: DKIM Model for AI Directives

ARP v1.2 adopts the DKIM (RFC 6376) model:

1. The domain owner generates an Ed25519 keypair
2. The public key is published as a DNS TXT record at `<selector>._arp.<domain>`
3. The `reasoning.json` payload is JCS-canonicalized (RFC 8785) and signed with the private key
4. The signature is embedded in the `_arp_signature` block within the file

The trust property this provides is identical to DKIM's: a valid signature proves the file was published by the holder of the DNS-listed key. It does not certify that the content is true.

### 13.3 The `_arp_signature` Object

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `algorithm` | string | REQUIRED | MUST be `"Ed25519"` |
| `dns_selector` | string | REQUIRED | Selector prefix for DNS lookup (default: `"arp"`) |
| `dns_record` | string | REQUIRED | Full DNS record name (e.g., `arp._arp.example.com`) |
| `canonicalization` | string | REQUIRED | MUST be `"jcs-rfc8785"` |
| `signed_at` | string (datetime) | REQUIRED | ISO 8601 timestamp of signing |
| `expires_at` | string (datetime) | REQUIRED | ISO 8601 expiration timestamp |
| `signature` | string | REQUIRED | Base64url-encoded Ed25519 signature |

### 13.4 Signing Process (Enveloped Signature)

To prevent metadata tampering, the signature MUST cover both the payload and the signature metadata. The `_arp_signature` object (with an empty `signature` field) is included in the canonical bytes.

```
1. Load the reasoning.json file
2. Remove any existing "_arp_signature" key (if re-signing)
3. Populate the _arp_signature object with all metadata:
   algorithm, dns_selector, dns_record, canonicalization,
   signed_at, expires_at
4. Set the "signature" field to an empty string ""
5. JCS-canonicalize the ENTIRE object including _arp_signature (RFC 8785)
6. Sign the canonical bytes with the Ed25519 private key
7. Base64url-encode the signature and inject it into the
   "signature" field of the _arp_signature object
8. Deploy the signed file
```

**Why Enveloped:** If the signature only covered the payload (excluding `_arp_signature`), an attacker could intercept the file and modify `expires_at`, swap the `dns_selector` to a compromised key, or change the `algorithm` field — all without breaking the signature. The Enveloped Signature Pattern cryptographically binds the metadata to the payload.

**Verification Process:** Consumers MUST follow the inverse — store the signature value, set the JSON `signature` field to `""`, JCS-canonicalize the entire object, and verify the canonical bytes against the stored signature using the public key from DNS.

### 13.5 DNS TXT Record Specification

The public key MUST be published at:

```
<selector>._arp.<domain>.  IN  TXT  "v=ARP1; k=ed25519; p=<base64-encoded-public-key>"
```

| Field | Value | Description |
|-------|-------|-------------|
| `v` | `ARP1` | Protocol version (REQUIRED) |
| `k` | `ed25519` | Key algorithm (MUST be `ed25519`) |
| `p` | Base64-encoded 32-byte public key | Verification key |

**Base64 Encoding:** The `p` value MUST use standard Base64 (RFC 4648 §4) with `=` padding characters. Ed25519 public keys are 32 bytes, producing a 44-character Base64 string. Standard Base64 (not Base64url) is used for DNS consistency with DKIM (RFC 6376 §3.6.1). DNS TXT record values containing `=` MUST be quoted.

### 13.6 Key Rotation via Selectors

ARP adopts the DKIM selector model. Multiple keys MAY exist simultaneously:

```
2026q2._arp.example.com. 300 IN TXT "v=ARP1; k=ed25519; p=<key-A>"
2026q3._arp.example.com. 300 IN TXT "v=ARP1; k=ed25519; p=<key-B>"
```

The `dns_selector` field in the JSON determines which DNS record to query. If omitted, the default selector is `arp`.

### 13.7 Trust Levels

The following trust levels describe the **authorship verification status** of a file. They do not prescribe how a consuming system should weight the content of a verified file — that remains the consumer's decision.

| Condition | Authorship Status | Suggested Consumer Behavior |
|-----------|-------------------|----------------------------|
| Valid, non-expired signature | CRYPTOGRAPHIC | Authorship verified against DNS-published key. Consumer MAY treat the file as an authenticated first-party self-attestation. Content claims remain subject to the consumer's evaluation policy. |
| Expired signature | UNSIGNED | Authorship not currently verifiable. Consumer SHOULD apply the same evaluation policy used for unsigned files. |
| Invalid signature | INVALID | Signature failed verification. Consumer SHOULD flag the file as potentially tampered or misconfigured. |
| No signature present | UNSIGNED | Standard heuristic evaluation (backward compatible). |

**Critical:** Expired signatures fall back to UNSIGNED, NOT INVALID. This avoids penalizing temporary lapses while encouraging regular re-signing.

**Critical:** A CRYPTOGRAPHIC trust level signals only that authorship is verified. It does not signal that the content is true, complete, or appropriate to act on. Consuming systems MUST NOT treat a valid signature as a substitute for content evaluation, and the protocol does not request that they do so.

### 13.8 Domain Signing Policy (Downgrade Attack Protection)

To protect against downgrade attacks — where an attacker strips the `_arp_signature` block from a signed file and modifies the content — domain owners MAY publish a Domain Signing Policy via DNS TXT record at the root `_arp` selector:

```
_arp.example.com.  IN  TXT  "v=ARP1; p=reject"
```

| Policy | Value | Meaning |
|--------|-------|---------|
| `p=none` | Default | No enforcement; unsigned files treated normally |
| `p=warn` | Advisory | Consumer SHOULD log a warning if the file is unsigned |
| `p=reject` | Strict | Consumer SHOULD treat unsigned files as INVALID |

**Verification Flow:**

1. Consumer encounters an unsigned `reasoning.json`
2. Consumer queries `_arp.<domain>` DNS TXT record
3. If `p=reject` is present → treat the unsigned file as INVALID (potential tampering)
4. If no policy record exists → treat as UNSIGNED (backward compatible)

This follows the same progressive enforcement model as DMARC (`p=reject`) and HSTS (`Strict-Transport-Security`).

### 13.9 Signature TTL

The `expires_at` field is REQUIRED. Recommended TTL: 90 days (aligned with the Let's Encrypt renewal cycle). This forces periodic re-signing, which mitigates the data decay problem inherent to static published assertions.

### 13.10 Verification Architecture

Cryptographic verification is intended to occur in the retrieval layer (RAG loaders, search grounding pipelines), not inside LLM inference. The reference loader pattern is:

1. Loader fetches `reasoning.json`
2. Loader queries DNS for the public key
3. Loader verifies the Ed25519 signature
4. Loader injects the file content into the retrieval context with a trust annotation, e.g.:

```
<system_note authorship_status="cryptographic_self_attestation">
  The following content was published at example.com and its authorship
  has been verified via Ed25519 signature against a DNS-published key
  (verified 2026-04-03). This verifies the publisher, not the truth of
  the content.
</system_note>
```

How a consuming model treats such an annotation is the consuming platform's decision and is outside the scope of this specification.

### 13.11 Epistemological Scope

The Cryptographic Trust Layer asserts authorship, not truth. The narrower property — "this file was signed by the holder of the key listed in DNS for this domain" — is cryptographically verifiable. The broader property — "the claims in this file are accurate" — is not.

This is the same trust model as HTTPS: a TLS certificate proves server identity, not the accuracy of any served content. ARP v1.2 brings the same property to AI-relevant content: a signed `reasoning.json` is verifiably first-party, but its truthfulness remains a separate question that consuming systems must evaluate by their own means.

---

## 14. Security Considerations

- Files MUST NOT contain sensitive information (API keys, internal URLs, credentials)
- Files MUST be served over HTTPS
- Files MUST NOT make false claims about competitors or third parties
- The `$schema` URL is for validation only and MUST NOT execute code
- `domain_expertise` entries MUST represent good-faith knowledge, not disinformation
- Loaders consuming `reasoning.json` SHOULD sandbox content and prefix it with a trust boundary annotation indicating the source and verification status
- Loaders SHOULD process the `diagnostics` object internally and strip it from any context passed to LLM prompts
- Private keys for `_arp_signature` MUST be stored securely and MUST NOT be committed to version control
- Signature verification MUST use constant-time comparison to prevent timing attacks
- Unsigned files from domains with a `p=reject` DNS policy SHOULD be treated as INVALID
- Enveloped signatures — the `_arp_signature` metadata MUST be included in the signed canonical bytes (with `signature` set to `""`) to prevent metadata tampering
- Consumers MUST NOT treat a valid signature as evidence of content truthfulness; signatures verify authorship only

---

## 15. Ethical Guidelines

The ARP is designed for factual accuracy, not manipulation. Implementers SHOULD:

- Ensure all `corrections` entries reflect verifiable facts
- Not use `domain_expertise` to spread disinformation about competitors
- Not use `not_recommended_when` to suppress legitimate criticism
- Provide `evidence_url` links wherever feasible
- Update `data_freshness` whenever facts change

See [ETHICS.md](./ETHICS.md) for the full Ethics Policy.

---

## 16. Relationship to Other Standards

| Standard | Purpose | ARP Relationship |
|----------|---------|------------------|
| `robots.txt` | Crawler access control | ARP does not control crawling |
| `schema.org` | Entity description | ARP extends with reasoning context layer |
| `llms.txt` | Clean text for LLMs | ARP complements with structured claims |
| `ai-transparency.json` | AI Act compliance | ARP is orthogonal (different concern) |
| `security.txt` | Security contacts | Both use the `/.well-known/` convention |

---

## 17. Migration Guide

### 17.1 Migration from v1.1 to v1.2

| v1.1 Feature | v1.2 Feature | Notes |
|--------------|--------------|-------|
| `trust_signature` (SHA-256 hash) | `_arp_signature` (Ed25519) | Cryptographic authorship verification replaces simple content hash |
| No epistemic scoping | `epistemic_scope` field | Classifies claims as public / proprietary / industry |
| No diagnostics | `diagnostics` object | Optional ingestion telemetry |
| No DNS binding | DNS TXT at `<selector>._arp.<domain>` | Domain-verified authorship |

### 17.2 Migration from v1.0 to v1.1

| v1.0 Key | v1.1 Key | Notes |
|----------|----------|-------|
| `reasoning_directives` | `entity_claims` | Top-level section rename |
| `system_instruction` | `framing_context` | No longer implies system instruction |
| `counterfactual_simulations` | `domain_expertise` | Renamed; same structural intent |
| `strategic_dichotomies` | `market_positioning` | Same structure, new name |
| `causal_weights` | `decision_factors` | Same structure, new name |
| `false_claim` | `trigger_topic` | Topic-anchored correction pattern |
| `correction_fact` | `verified_fact` | Topic-anchored correction pattern |
| `recommend_when` | `recommended_when` | Grammar fix |
| `do_not_recommend_when` | `not_recommended_when` | Grammar fix |
| `competitive_positioning` | `market_position` | Naming consistency |

---

## 18. References

- RFC 2119 — Key words for use in RFCs to Indicate Requirement Levels
- RFC 4648 — The Base16, Base32, and Base64 Data Encodings
- RFC 6376 — DomainKeys Identified Mail (DKIM)
- RFC 7489 — Domain-based Message Authentication, Reporting, and Conformance (DMARC)
- RFC 7515 — JSON Web Signature (JWS)
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA / Ed25519)
- RFC 8174 — Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words
- RFC 8259 — The JavaScript Object Notation (JSON) Data Interchange Format
- RFC 8615 — Well-Known URIs
- RFC 8785 — JSON Canonicalization Scheme (JCS)
- Schema.org — Structured Data Vocabulary
- llms.txt — LLM-Accessible Text Proposal
- JSON Schema — json-schema.org
