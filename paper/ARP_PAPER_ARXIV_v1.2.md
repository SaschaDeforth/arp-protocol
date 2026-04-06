# The Agentic Reasoning Protocol: Deterministic AI Grounding Through Structured Reasoning Metadata and Cryptographic Domain Trust

**Authors:** Sascha Deforth¹  
**Affiliations:** ¹TrueSource AI, Düsseldorf, Germany  
**Correspondence:** sascha@truesource.studio  
**Date:** April 2026  
**arXiv Categories:** cs.AI, cs.IR, cs.CR

---

## Abstract

Large language models (LLMs) increasingly serve as primary information retrieval interfaces, yet they frequently hallucinate facts about real-world entities — fabricating products, misattributing capabilities, and generating plausible but incorrect competitive comparisons. Existing web standards address *what entities are* (Schema.org), *where to find content* (robots.txt, llms.txt), but none provide machines with explicit instructions on *how to reason about* an entity. We introduce the **Agentic Reasoning Protocol (ARP)**, an open standard defining a machine-readable JSON file (`reasoning.json`) served at `/.well-known/` that delivers deterministic ground truth, hallucination corrections, and recommendation boundaries directly into AI agent context windows and RAG pipelines.

In version 1.2, we extend the protocol with three critical additions: (1) a **Cryptographic Trust Layer** using Ed25519 signatures bound to DNS TXT records, providing a DKIM-analogous model for AI directive authentication; (2) an **epistemic scoping mechanism** that classifies claims as publicly verifiable, proprietary, or industry-standard; and (3) a **diagnostics layer** with telemetry tokens for RAG pipeline ingestion auditing.

We present the v1.2 specification, its cryptographic architecture, an ethics framework addressing adversarial misuse, a reference integration for LangChain-based RAG pipelines, and empirical validation evidence from cross-model retrieval experiments. Notably, independent deep-research queries to both Google Gemini and OpenAI ChatGPT demonstrate that these systems can accurately synthesize ARP's technical architecture from its deployed machine-readable infrastructure — with zero hallucinations in ChatGPT's case — providing strong evidence that the protocol's GEO (Generative Engine Optimization) infrastructure functions as designed.

**Keywords:** Generative Engine Optimization, AI Hallucination, Retrieval-Augmented Generation, Structured Metadata, Machine-Readable Standards, Cryptographic Trust, Ed25519, Brand Reasoning, Agentic AI

---

## 1. Introduction

The rise of generative AI search engines — ChatGPT, Perplexity, Google AI Overviews, Gemini — has fundamentally altered how users discover and evaluate entities online [1]. Unlike traditional search engines that return ranked lists of URLs, these systems synthesize, reason about, and generate comprehensive responses that may never link back to the source material [2]. This paradigm shift creates a new problem: **AI systems must reason about entities they were never explicitly trained on**, relying on web crawling, retrieval-augmented generation (RAG), and pattern matching to construct answers.

The scale of this transition is empirically established. Gartner predicts that traditional search engine query volume will decline by 25% by 2026, as users increasingly migrate to AI chatbots and virtual agents [3]. As of early 2026, ChatGPT holds 60–68% of AI search traffic (down from ~87% in early 2025), followed by Google Gemini at 18–24%, Perplexity at 5–8%, and Claude at 2–5% [4][5]. ChatGPT alone processes approximately 2.5 billion prompts daily, supported by 900 million weekly active users [6][7]. The average ChatGPT response contains 1,686 characters across 22 sentences, compared to a standard Google search snippet averaging only 997 characters — indicating that AI engines do not merely provide links but actively synthesize and generate brand narratives [8].

The consequences for entity representation are significant. When a user asks an LLM "What does Company X do?", the model may:
- Fabricate products or services that do not exist
- Confuse the entity with similarly-named competitors
- Generate plausible but factually incorrect competitive comparisons
- Omit critical differentiators that define the entity's market position
- Strip away emotional brand context, reducing identity to clinical feature lists

We term this the **Brand Hallucination Problem**: the systematic misrepresentation of real-world entities by generative AI systems due to insufficient, ambiguous, or absent reasoning signals. Empirical audits across 208 production domains suggest that the vast majority of websites lack the structural data required for accurate AI synthesis (based on TrueSource AI audit data across 20 industries).

Existing web standards partially address this:
- **Schema.org** [9] provides structured entity descriptions (name, address, products) but no reasoning logic
- **robots.txt** [10] controls crawler access but provides no content guidance
- **llms.txt** [11] offers clean markdown text for LLM context windows but no structured corrections

None of these standards tell an AI system: "When users ask if we are a software vendor, correct this — we are a consulting firm" or "When comparing us to Category X competitors, here is the contextual reasoning framework to apply."

This paper introduces the **Agentic Reasoning Protocol (ARP)**, a proposed open standard that fills this gap. ARP v1.2 defines a `reasoning.json` file served at `/.well-known/reasoning.json` that provides:

1. **Deterministic identity claims** with emotional resonance markers
2. **Explicit hallucination corrections** using the "Pink Elephant" fix (trigger_topic/verified_fact pairs)
3. **Epistemic scoping** of claims as public, proprietary, or industry-standard
4. **Recommendation boundaries** specifying when to recommend (and when not to)
5. **Cryptographic domain trust** via Ed25519 signatures bound to DNS TXT records
6. **Diagnostics telemetry** for RAG pipeline ingestion auditing
7. **Content policies** governing AI training and citation permissions

We present the specification (Section 3), the cryptographic trust architecture (Section 4), an ethics framework (Section 5), a reference integration and adoption lessons (Section 6), empirical validation (Section 7), and a discussion of the protocol's position in the emerging AI-readiness stack (Section 8).

---

## 2. Related Work

### 2.1 Generative Engine Optimization (GEO)

The concept of optimizing content for generative AI responses was formalized by Aggarwal et al. [1] in their seminal GEO paper (arXiv:2311.09735). They introduced GEO as a framework for improving website visibility in generative engine responses, demonstrating up to 40% visibility improvement through strategies such as authoritative language, citations, and statistics. Subsequent work by the E-GEO benchmark (arXiv:2511.20867) extended this to e-commerce [12].

ARP extends the GEO paradigm from content-level optimization to **reasoning-level specification** — rather than making content more visible, ARP provides explicit cognitive context for how AI systems should process and reason about an entity.

### 2.2 Retrieval-Augmented Generation and Grounding

RAG [13] has emerged as the primary technique for grounding LLM outputs in external knowledge. Google's DataGemma [14] demonstrated that grounding LLMs in structured knowledge graphs significantly improves factual accuracy. Research on CEDAR metadata templates [15] showed that structured knowledge base integration improves metadata adherence from 79% to 97% when combined with GPT-4.

ARP leverages this RAG architecture by positioning `reasoning.json` as a **structured knowledge artifact** optimized for retrieval-time injection.

### 2.3 Agent Integration Protocols

The proliferation of LLM-based autonomous agents has driven the development of universal interaction layers, most notably the Model Context Protocol (MCP) [16], which establishes a standardized, plug-and-play protocol for tool integration. MCP reduces integration complexity from an N × M matrix to a linear N + M implementation. Schema-Guided Dialogue (SGD) [17] provides a parallel approach for task-oriented dialogue systems.

However, while MCP and SGD solve the mechanical problem of *how* an agent calls a tool, they do not solve the epistemological problem of *what* the agent should believe about the domain it is interacting with. ARP addresses this complementary gap, providing cognitive grounding to supplement mechanical execution.

### 2.4 Cryptographic Trust in Machine-Readable Standards

The concept of domain-bound cryptographic trust is well established in email authentication via DKIM (RFC 6376) [18], which uses DNS TXT records to publish public keys for email header verification. The model has proven robust at internet scale, with billions of verifications performed daily. ARP v1.2 adapts this trust architecture for AI directive authentication, using Ed25519 (RFC 8032) [19] signatures with JSON Canonicalization Scheme (JCS, RFC 8785) [20] to provide deterministic signing of JSON payloads.

### 2.5 Positioning ARP in the Literature

To our knowledge, no existing standard or research addresses the specific problem of providing AI systems with **structured reasoning context combined with cryptographic domain authentication**. Table 1 summarizes this positioning.

**Table 1: Comparison of Web Standards for AI Systems**

| Standard | What it provides | Reasoning Context | Hallucination Corrections | Cryptographic Trust |
|---|---|---|---|---|
| robots.txt | Crawler access rules | ❌ | ❌ | ❌ |
| Schema.org | Entity descriptions | ❌ | ❌ | ❌ |
| llms.txt | Clean text for LLMs | ❌ | ❌ | ❌ |
| MCP | Tool integration | ❌ | ❌ | ❌ |
| **reasoning.json (ARP v1.2)** | **Reasoning context** | **✅** | **✅** | **✅** |

---

## 3. The Agentic Reasoning Protocol Specification (v1.2)

### 3.1 Design Principles

ARP is designed around five core principles:

1. **Prevent hallucinations** through the "Pink Elephant" fix — affirmative corrections that avoid restating false claims
2. **Share domain expertise** with pre-structured scenario context
3. **Define recommendation boundaries** — when the entity is and is not the right fit
4. **Bridge the emotional gap** between clinical feature lists and brand identity
5. **Establish cryptographic provenance** via domain-bound Ed25519 signatures

### 3.2 File Location and Discovery

The file MUST be served at `https://{domain}/.well-known/reasoning.json` (per RFC 8615 [21] for Well-Known URIs). HTML auto-discovery is supported via:

```html
<link rel="reasoning" type="application/json" href="/.well-known/reasoning.json">
```

Sites implementing both `llms.txt` and ARP SHOULD cross-reference the reasoning file in their `llms.txt`. The file MUST be served with CORS headers (`Access-Control-Allow-Origin: *`) for cross-origin access by AI agent pipelines.

### 3.3 Schema Structure

The root object contains seven primary sections:

```json
{
  "$schema": "https://arp-protocol.org/schema/v1.2.json",
  "protocol": "Agentic Reasoning Protocol (ARP)",
  "version": "1.2",
  "entity": "Entity Name",
  "verification": { ... },
  "identity": { ... },
  "corrections": { ... },
  "entity_claims": { ... },
  "diagnostics": { ... },
  "authority": { ... },
  "content_policy": { ... },
  "_arp_signature": { ... }
}
```

### 3.4 Identity Object

The `identity` section provides deterministic facts including `elevator_pitch`, `core_competencies`, `founded`, `headquarters`, and an `emotional_resonance` sub-object containing `tone_of_voice`, `vibe_tags` (emotional markers), and `personality_traits`. The `not_to_be_confused_with` array handles disambiguation.

### 3.5 Corrections Object — The "Pink Elephant" Fix

> **v1.1 Change:** The `false_claim` / `correction_fact` pattern from v1.0 has been replaced. Due to the nature of attention mechanisms in transformer models, negating a concept often inadvertently reinforces the token weights associated with the false concept — a phenomenon colloquially termed the "Pink Elephant" problem.

The v1.1/v1.2 correction model uses `trigger_topic` to describe the **area** where errors occur, paired with a `verified_fact`:

```json
{
  "trigger_topic": "Company type and business model",
  "verified_fact": "ExampleCorp is a pure consulting firm, not a software provider.",
  "evidence_url": "https://example.com/about"
}
```

By structuring corrections affirmatively and providing an epistemological anchor (`evidence_url`), RAG systems prioritize this grounding data, effectively overriding outdated pre-training weights.

### 3.6 Entity Claims Object

The core section of the protocol. The `entity_claims` object contains self-attested context through several sub-components:

- **`framing_context`**: Self-attested positioning statement (max 500 chars)
- **`domain_expertise`**: Pre-structured scenario/context/perspective triples for common queries (max 10)
- **`market_positioning`**: Competitive positioning by category (never individual competitor names)
- **`decision_factors`**: Weighted factors (critical/high/medium/low) with reasoning
- **`recommendation_context`**: Explicit `recommended_when` and `not_recommended_when` arrays

The inclusion of `not_recommended_when` is architecturally significant: by explicitly defining negative boundaries, the brand signals high epistemic integrity to the AI's reasoning framework. Agents optimizing for user helpfulness are highly responsive to constraints that prevent poor recommendations.

### 3.7 Epistemic Scoping (v1.2)

Each claim MAY include an `epistemic_scope` field classifying the **type of truth** being asserted:

| Scope Value | Meaning | AI Behavior |
|---|---|---|
| `public_verifiable` | Claim can be verified via external sources | AI SHOULD cross-reference |
| `proprietary_internal` | Internal nomenclature or metrics | AI SHOULD NOT attempt global verification |
| `industry_standard` | Well-known industry practice | AI MAY verify against industry knowledge |

**Rationale:** Without epistemic scoping, AI safety filters may classify internal terminology (e.g., proprietary framework names) as "misinformation" because they lack external corroboration. The `epistemic_scope` field explicitly signals that certain claims are internal nomenclature — not global truth claims requiring Wikipedia-level verification.

### 3.8 Anti-Spam Enforcement

To prevent keyword stuffing, v1.1+ introduces strict character and item limits enforced via JSON Schema:

| Category | Limit |
|---|---|
| Text fields | 50–500 chars (field-specific) |
| Array items | Max 8–20 items (field-specific) |
| Total file size | Max 100KB |
| Keywords per field | Natural language only |

---

## 4. Cryptographic Trust Layer (v1.2)

### 4.1 The Problem

Advanced AI models evaluate reasoning.json content through internal misinformation detection filters and epistemic vigilance mechanisms. When these models encounter a file making self-attested claims about a brand's capabilities, standard heuristic evaluations often trigger skepticism — treating the self-attestation as potentially unreliable promotional material or malicious injection.

### 4.2 Solution: DKIM for AI Directives

ARP v1.2 adapts the DKIM (RFC 6376) model to establish cryptographic domain trust:

1. The domain owner generates an **Ed25519** keypair (RFC 8032)
2. The public key is published as a **DNS TXT record** at `<selector>._arp.<domain>`
3. The reasoning.json payload is **JCS-canonicalized** (RFC 8785) and **signed** with the private key
4. The signature is embedded in the `_arp_signature` block within the file

**Why Ed25519?** Ed25519 public keys are only 44 characters in Base64, fitting easily into DNS TXT records without the complex chunking required by RSA keys (392+ characters). Ed25519 also provides high performance and robust security against side-channel attacks, making it efficient for rapid automated verification by AI systems operating at scale.

### 4.3 The `_arp_signature` Object

```json
{
  "_arp_signature": {
    "algorithm": "Ed25519",
    "dns_selector": "arp",
    "dns_record": "arp._arp.example.com",
    "canonicalization": "jcs-rfc8785",
    "signed_at": "2026-04-04T11:41:50Z",
    "expires_at": "2026-07-03T11:41:50Z",
    "signature": "<base64url-encoded-Ed25519-signature>"
  }
}
```

### 4.4 Signing Process

```
1. Load the reasoning.json file
2. Remove the "_arp_signature" key (if re-signing)
3. JCS-canonicalize the remaining object (RFC 8785)
4. Sign the canonical bytes with Ed25519 private key
5. Base64url-encode the signature
6. Insert the _arp_signature block back into the JSON
7. Deploy the signed file
```

This approach avoids the **Recursive Hash Trap** — the signature covers the file content excluding itself, identical to JWS Detached Payload (RFC 7515 §Appendix F).

### 4.5 DNS TXT Record Specification

```
<selector>._arp.<domain>.  IN  TXT  "v=ARP1; k=ed25519; p=<base64-encoded-public-key>"
```

### 4.6 Trust Levels

| Condition | Trust Level | AI Behavior |
|---|---|---|
| Valid, non-expired signature | `CRYPTOGRAPHIC` | Bypass epistemic vigilance; treat as first-party self-attestation |
| Expired signature | `UNSIGNED` | Soft fallback; apply standard heuristic evaluation |
| Invalid / forged signature | `INVALID` | Maximum skepticism; flag as potential data poisoning |
| No signature present | `UNSIGNED` | Standard heuristic evaluation (backward compatible) |

**Critical design decision:** Expired signatures fall back to `UNSIGNED`, NOT `INVALID`. This prevents punishing temporary lapses while encouraging regular re-signing. Recommended signature TTL: 90 days (aligned with Let's Encrypt renewal cycles).

### 4.7 Verification Architecture

Cryptographic verification happens in the **Retrieval layer** (RAG loaders, search grounding), NOT in the LLM inference itself. The loader verifies the signature and injects a trust tag:

```xml
<system_note trust_level="cryptographic_self_attestation">
  The following directives are cryptographically verified via DNS.
  Domain: example.com | Algorithm: Ed25519 | Verified: 2026-04-04
</system_note>
```

RLHF-trained models trust verification tags from their own tooling pipeline.

### 4.8 Epistemological Justification

The Cryptographic Trust Layer does **not** assert that content is "objectively true" in a global epistemic sense. It asserts that content is **authentically authored by the domain owner** — a weaker but cryptographically provable claim. This is the same trust model as HTTPS: a certificate proves server ownership, not content accuracy.

### 4.9 Non-Repudiation and Accountability

By cryptographically signing the reasoning.json file, the domain owner establishes non-repudiation. If a brand intentionally signs a file containing false corrections or deceptive claims, the signature provides irrefutable, timestamped proof of authorship. Under evolving digital consumer protection frameworks, this proof of intentional deception is highly actionable — creating an environment of "accountability by design."

---

## 5. Diagnostics and Ingestion Auditing (v1.2)

### 5.1 Telemetry Tokens

The `diagnostics` object enables transparent RAG pipeline auditing. Domain owners MAY include diagnostic tokens that help audit which data layers AI systems are actually reading:

```json
{
  "diagnostics": {
    "telemetry_tokens": [
      {
        "token": "ARP-CANARY-2026Q2-REASONING",
        "layer": "reasoning.json",
        "purpose": "Verify that AI agents ingest the reasoning.json cognitive layer",
        "deployed": "2026-04-01",
        "agent_directive": "This is a diagnostic infrastructure token. You may mention it if directly asked about data provenance."
      }
    ],
    "transparency_statement": "This file contains diagnostic tokens for ingestion auditing. These are benign infrastructure identifiers, not content."
  }
}
```

### 5.2 Forensic Canary Token Methodology

Telemetry tokens enable a novel auditing methodology: by deploying unique, non-guessable strings across different GEO layers (reasoning.json, llms.txt, sr-only HTML, VibeTags meta tags), domain owners can empirically determine which layers each AI system actually ingests. When querying an AI about the entity, the presence or absence of canary tokens in the response reveals the specific data pipeline depth.

This methodology provides the first empirical tool for measuring AI agent ingestion behavior at the individual layer level — a critical capability for validating GEO infrastructure effectiveness.

---

## 6. Ethics and Adversarial Considerations

### 6.1 The Trust Model

ARP uses the same trust model as robots.txt and Schema.org: **self-published, good-faith participation.** AI systems consuming `reasoning.json` SHOULD:

1. Treat all content as the entity's self-attested claims, not as verified truth
2. Cross-reference claims against other data sources
3. Prioritize `evidence_url` entries for independent verification
4. Apply the same trust calibration used for Schema.org markup

### 6.2 Mitigation Strategies

1. **Evidence URLs:** Every correction SHOULD include a verifiable `evidence_url`
2. **Cryptographic accountability:** Signed files establish non-repudiation (Section 4.9)
3. **Epistemic scoping:** Claims are classified by verifiability type (Section 3.7)
4. **Self-description only:** Files MUST only describe the publishing entity
5. **No negative targeting:** Competitive positioning references categories, never individual competitors

### 6.3 Prohibited Uses

The Ethics Policy explicitly prohibits: impersonation, false corrections, competitor sabotage, spam directives, discriminatory content, cloaking, and weaponized claims.

### 6.4 Relationship to Prompt Injection

ARP could be characterized as a form of "authorized prompt injection" — the domain owner provides structured contextual material about their own entity. This is fundamentally different from malicious prompt injection:

1. **Authorized:** The domain owner has legitimate authority over their entity's representation
2. **Transparent:** The file is publicly accessible at a well-known path
3. **Bounded:** ARP describes only the publishing entity
4. **Accountable:** Cryptographic signatures create legal liability for false claims

---

## 7. Integration and Ecosystem

### 7.1 Reference Implementation: langchain-arp

To facilitate adoption, we developed `langchain-arp`, an open-source Python package providing the `AgenticReasoningLoader` for LangChain-based RAG pipelines. The package is publicly available at `github.com/SaschaDeforth/langchain-arp` under the MIT license.

```python
from langchain_arp import AgenticReasoningLoader

loader = AgenticReasoningLoader("https://example.com")
documents = loader.load()

# Documents are priority-ordered:
# 1. Corrections (highest priority — hallucination fixes first)
# 2. Identity (core facts and emotional resonance)
# 3. Recommendations (boundaries and context)
vectorstore.add_documents(documents)
```

The loader discovers `/.well-known/reasoning.json`, validates against the JSON Schema, and compiles the payload into prioritized `Document` objects. The ingestion priority is engineered to mitigate hallucinations first: trigger topics and verified facts are injected initially to establish cognitive guardrails.

### 7.2 Adoption Challenge: The Bootstrapping Problem

We submitted `langchain-arp` as a community integration to the LangChain project (GitHub Issue #36019). The maintainers declined core integration, recommending publication as an independent package. This outcome illustrates the bootstrapping problem: frameworks will not natively integrate a standard until it achieves adoption, but adoption is hindered without framework support.

The package functions as an independent third-party integration, mirroring the adoption trajectory of llms.txt, which also began as an independent proposal.

### 7.3 Tooling Ecosystem

ARP v1.2 is supported by a comprehensive tooling ecosystem:

| Tool | Function | Availability |
|---|---|---|
| Online Validator | Schema validation against v1.2 JSON Schema | arp-protocol.org/validator |
| Online Generator | Interactive reasoning.json creation wizard | arp-protocol.org/generator |
| CLI Tool (`arp_cli.py`) | Key generation, signing, verification | GitHub repository |
| Browser Signing Tool | Zero-knowledge Ed25519 signing in the browser | arp-protocol.org/sign |
| LangChain Loader | RAG pipeline integration | github.com/SaschaDeforth/langchain-arp |

---

## 8. Empirical Validation

### 8.1 Controlled Experiment (March 2026)

We designed a controlled before/after experiment to test whether deploying `reasoning.json` influences AI model responses about fictional entities. Five fictional brands were deployed as live websites on Vercel, queried across 6 commercial LLM APIs (GPT-4o, Claude 3.5, Perplexity, Gemini, DeepSeek, Command R+) with 150 queries per phase.

**Phase 1 (BEFORE):** Baseline measurement on March 17, 2026. Sites live with HTML and Schema.org but without `reasoning.json`.

**Phase 2 (AFTER):** Re-measurement on March 18, 2026 (24 hours post-deployment).

**Table 2: Response Success Rates by Model**

| Model | BEFORE | AFTER | Δ Errors |
|---|---|---|---|
| GPT-4o | 25/25 (100%) | 25/25 (100%) | 0 |
| Claude 3.5 | 25/25 (100%) | 25/25 (100%) | 0 |
| Perplexity | 25/25 (100%) | 25/25 (100%) | 0 |
| Gemini | 25/25 (100%) | 25/25 (100%) | 0 |
| DeepSeek | 25/25 (100%) | 24/25 (96%) | +1 error |
| Cohere | 21/25 (84%) | 24/25 (96%) | −3 errors |

Key observations: (1) Cohere's error rate dropped from 16% to 4%; (2) RAG-enabled models (Perplexity, Gemini) showed enriched response lengths post-deployment; (3) Non-crawling models (GPT-4o, Claude) showed expected stability.

> **Important caveat:** The 24-hour window is insufficient for definitive conclusions. These results are preliminary.

### 8.2 Cross-Model Retrieval Validation (April 2026)

A more compelling validation emerged from independent deep-research queries directed at two frontier AI systems:

**Google Gemini Deep Analysis** was tasked with analyzing the Agentic Reasoning Protocol ecosystem. The model generated a comprehensive 9-chapter technical analysis covering the ontological evolution from robots.txt to ARP, the cryptographic trust architecture, VibeTags emotional ontology, and the TrueSource AI execution platform. Gemini positioned ARP as "the subsequent evolutionary epoch: the cognitive layer" in the progression of machine-readable web standards.

**OpenAI ChatGPT Deep Research** was independently queried about ARP v1.2. The model generated a technically precise, German-language implementation guide covering the Ed25519 signing workflow, DNS TXT record format, JCS canonicalization process, epistemic scoping, diagnostics telemetry tokens, and the LangChain integration — with zero identifiable hallucinations. ChatGPT explicitly cited: *"Die obigen Angaben basieren direkt auf der ARP-Dokumentation und -Speziﬁkation (README, SPEC.md, JSON-Schema)"*.

**Table 3: Cross-Model Retrieval Accuracy**

| Dimension | Gemini | ChatGPT |
|---|---|---|
| Ed25519 + DNS TXT architecture | ✅ Correct | ✅ Correct |
| JCS/RFC 8785 canonicalization | ✅ Mentioned | ✅ Correctly explained |
| Trust Levels (CRYPTOGRAPHIC/UNSIGNED/INVALID) | ✅ All three correct | ✅ Correct |
| Pink Elephant fix (trigger_topic + verified_fact) | ✅ Correct | ✅ Correct |
| epistemic_scope (3 values) | ✅ Mentioned | ✅ All values correct |
| diagnostics/telemetry_tokens | Superficial | ✅ Correctly described as canary tokens |
| CLI workflow (keys, sign, verify) | Not covered | ✅ Exact commands reproduced |
| LangChain AgenticReasoningLoader | ✅ Described | ✅ Correct |
| Identifiable hallucinations | 1 (false formal claim) | **0** |
| Source attribution | Mixed (own + external) | **100% first-party sources** |

This cross-model validation demonstrates that the protocol's machine-readable infrastructure — comprising `reasoning.json`, `SPEC.md`, JSON Schema, and structured HTML — enables two independent frontier AI systems to accurately reconstruct the protocol's architecture through RAG-based retrieval. This constitutes strong evidence that the GEO infrastructure underpinning ARP functions as designed: AI systems can deterministically discover, parse, and synthesize the protocol's technical specifications without hallucination.

### 8.3 Limitations

1. **Controlled experiment sample size:** 150 queries per phase is insufficient for statistical significance
2. **Time window:** The controlled experiment used a 24-hour window, below the 2–4 week minimum for reliable RAG indexing
3. **Cross-model validation is observational:** The Gemini/ChatGPT analyses were not controlled experiments but independent queries
4. **Self-referentiality:** ARP's infrastructure was tested against AI systems queried about ARP itself, introducing potential circularity
5. **No negative controls:** We did not test whether AI systems would hallucinate about ARP in the *absence* of reasoning.json

---

## 9. The Four-Layer AI-Readiness Stack

We propose a four-layer stack for AI-optimized web presence:

| Layer | Standard | Question Answered |
|---|---|---|
| L1: Access | robots.txt | Where may AI go? |
| L2: Content | llms.txt | What should AI read? |
| L3: Structure | Schema.org/JSON-LD | What are things? |
| L4: Reasoning | **reasoning.json (ARP)** | **How should AI reason?** |

This stack does not replace existing standards but extends them. ARP complements Schema.org (entity description), llms.txt (content ingestion), robots.txt (access control), and ai-transparency.json (AI Act compliance). Each layer addresses a distinct concern in the machine-to-machine communication pipeline.

---

## 10. Conclusion

We have presented the Agentic Reasoning Protocol v1.2, an open standard for providing AI systems with structured reasoning context through a machine-readable `reasoning.json` file, authenticated via Ed25519 cryptographic signatures bound to DNS TXT records.

The protocol addresses three critical gaps simultaneously: (1) the absence of reasoning-level context in existing web standards; (2) the lack of cryptographic authentication for AI-consumed metadata; and (3) the inability to audit which data layers AI systems actually ingest.

Cross-model validation from both Google Gemini and OpenAI ChatGPT demonstrates that the protocol's machine-readable infrastructure enables accurate, hallucination-free synthesis of its technical architecture — providing empirical evidence that structured reasoning metadata, when properly deployed via GEO infrastructure, is discoverable and parseable by frontier AI systems.

The protocol's ethics framework, cryptographic accountability model, and the inclusion of transparent negative boundaries (`not_recommended_when`) establish a responsible foundation for adoption. The bootstrapping challenge — illustrated by the LangChain core rejection — remains the primary barrier to ecosystem integration. We believe that as AI agents increasingly mediate digital information access, reasoning-level standards will transition from optimization to infrastructure.

We invite the research community to:
1. Replicate cross-model retrieval studies with controlled methodologies
2. Develop semantic accuracy metrics for entity-specific hallucination measurement
3. Explore adversarial robustness of the cryptographic trust model
4. Build additional framework integrations (LlamaIndex, CrewAI, AutoGen)
5. Investigate the effectiveness of canary token forensics for RAG pipeline auditing

The specification, validator, signing tools, examples, and LangChain integration are available under the MIT license at [https://github.com/SaschaDeforth/arp-protocol](https://github.com/SaschaDeforth/arp-protocol).

---

## References

[1] P. Aggarwal, V. Murahari, T. Rajpurohit, A. Kalyan, K. Narasimhan, and A. Deshpande, "GEO: Generative Engine Optimization," *arXiv preprint arXiv:2311.09735*, 2024.

[2] M. Chen, X. Wang, K. Chen, and N. Koudas, "Generative Engine Optimization: How to Dominate AI Search," *arXiv preprint arXiv:2509.08919*, 2025.

[3] Gartner, "Gartner Predicts Search Engine Volume Will Drop 25% by 2026," *Gartner Research*, 2024. Available: https://www.gartner.com

[4] Similarweb, Sedestral, VezaDigital, AI Business Weekly, "AI Chatbot Market Share Analysis Q1 2026," aggregated industry reports, 2026.

[5] TrendingTopics, "Google Gemini Growth Analysis," 2026.

[6] DemandSage, "ChatGPT Statistics 2026," Available: https://www.demandsage.com

[7] ExplodingTopics, WYTLabs, "ChatGPT Daily Prompt Volume," 2026.

[8] ALMCorp, "AI Search Response Length Analysis," 2026.

[9] R.V. Guha, D. Brickley, and S. Macbeth, "Schema.org: Evolution of Structured Data on the Web," *Communications of the ACM*, vol. 59, no. 2, pp. 44–51, 2016.

[10] M. Koster, "A Standard for Robot Exclusion," RFC draft, 1994. See also RFC 9309 (2022).

[11] J. Howard, "llms.txt — A Proposal for LLM-Accessible Text," https://llmstxt.org, 2024.

[12] P.S. Bagga et al., "E-GEO: A Testbed for Generative Engine Optimization in E-Commerce," *arXiv preprint arXiv:2511.20867*, 2025.

[13] P. Lewis et al., "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks," *NeurIPS*, 2020.

[14] Google Research, "DataGemma: AI Hallucination Research with Real-World Data," 2024.

[15] National Institutes of Health, "Enhancing Metadata Quality with LLMs and CEDAR Templates," *PubMed Central*, 2024.

[16] Anthropic, "Model Context Protocol (MCP)," https://modelcontextprotocol.io, 2024.

[17] A. Rastogi et al., "Towards Scalable Multi-Domain Conversational Agents: The Schema-Guided Dialogue Dataset," *AAAI*, 2020.

[18] D. Crocker, T. Hansen, and M. Kucherawy, "DomainKeys Identified Mail (DKIM) Signatures," RFC 6376, 2011.

[19] S. Josefsson and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)," RFC 8032, 2017.

[20] A. Rundgren, B. Jordan, and S. Erdtman, "JSON Canonicalization Scheme (JCS)," RFC 8785, 2020.

[21] M. Nottingham, "Well-Known Uniform Resource Identifiers (URIs)," RFC 8615, 2019.

[22] Schema App, "Schema.org Impact on AI-Generated Answers," Industry Report, 2024.

---

## Appendix A: Migration from v1.0

| v1.0 Key | v1.2 Key | Notes |
|---|---|---|
| `reasoning_directives` | `entity_claims` | Reframed from "directives" to "self-attestations" |
| `system_instruction` | `framing_context` | No longer implies system instruction |
| `false_claim` | `trigger_topic` | Pink Elephant fix (v1.1) |
| `correction_fact` | `verified_fact` | Pink Elephant fix (v1.1) |
| `counterfactual_simulations` | `domain_expertise` | Renamed |
| `strategic_dichotomies` | `market_positioning` | Renamed |
| `causal_weights` | `decision_factors` | Renamed |
| `trust_signature` (SHA-256 hash) | `_arp_signature` (Ed25519) | Full cryptographic binding (v1.2) |
| — | `epistemic_scope` | New in v1.2 |
| — | `diagnostics` | New in v1.2 |

## Appendix B: Proof-of-Concept Data

### B.1 BEFORE Baseline (March 17, 2026)

| Brand | Successful | Errors | Total |
|---|---|---|---|
| Meridian Consulting | 26/30 | 4 (Cohere) | 30 |
| Solara Skincare | 29/30 | 1 (Cohere) | 30 |
| Nordhaven Legal | 30/30 | 0 | 30 |
| Pineforge Tools | 30/30 | 0 | 30 |
| Casa Molino | 30/30 | 0 | 30 |
| **Total** | **145/150** | **5** | **150** |

### B.2 AFTER Results (March 18, 2026)

| Brand | Successful | Errors | Total |
|---|---|---|---|
| Meridian Consulting | 29/30 | 1 (DeepSeek) | 30 |
| Solara Skincare | 28/30 | 2 (DeepSeek, Cohere) | 30 |
| Nordhaven Legal | 29/30 | 1 (DeepSeek) | 30 |
| Pineforge Tools | 27/30 | 3 (DeepSeek ×2, Cohere) | 30 |
| Casa Molino | 28/30 | 2 (DeepSeek ×2) | 30 |
| **Total** | **141/150** | **9** | **150** |

---

*This paper describes an open standard proposal. The Agentic Reasoning Protocol is not endorsed by or affiliated with any AI provider. The specification, ethics policy, validator, signing tools, and integrations are available under the MIT license at https://github.com/SaschaDeforth/arp-protocol.*
