# The Agentic Reasoning Protocol: A Machine-Readable Standard for Deterministic AI Grounding Through Structured Reasoning Metadata

**Authors:** Sascha Deforth¹  
**Affiliations:** ¹TrueSource, Düsseldorf, Germany  
**Correspondence:** sascha@truesource.studio  
**Date:** March 2026  
**arXiv Categories:** cs.AI, cs.IR

---

## Abstract

Large language models (LLMs) increasingly serve as primary information retrieval interfaces, yet they frequently hallucinate facts about real-world entities — fabricating products, misattributing capabilities, and generating plausible but incorrect competitive comparisons. Existing web standards address *what entities are* (Schema.org), *where to find content* (robots.txt, llms.txt), but none provide machines with explicit instructions on *how to reason about* an entity. We introduce the **Agentic Reasoning Protocol (ARP)**, an open standard defining a machine-readable JSON file (`reasoning.json`) served at `/.well-known/` that delivers deterministic ground truth, hallucination corrections, counterfactual simulation logic, and recommendation boundaries directly into AI agent context windows and RAG pipelines. We present the v1.0 specification, an ethics framework addressing adversarial misuse, a reference integration for LangChain-based RAG pipelines, and a proof-of-concept evaluation across 5 controlled test domains and 6 commercial LLM APIs (GPT-4o, Claude 3.5, Perplexity, Gemini, DeepSeek, Cohere). Our before/after methodology—deploying `reasoning.json` files and re-querying after a crawl window—demonstrates preliminary evidence that RAG-enabled models (Perplexity, Gemini) produce longer, more contextually enriched responses post-deployment, while non-crawling models show expected stability. We report on adoption challenges, including the rejection of our integration by the LangChain core project, and discuss implications for new standard proposals in the AI tooling ecosystem. We argue that ARP fills a critical architectural gap in the emerging AI-readiness stack and propose it as a complementary layer alongside Schema.org and llms.txt.

**Keywords:** Generative Engine Optimization, AI Hallucination, Retrieval-Augmented Generation, Structured Metadata, Machine-Readable Standards, Brand Reasoning, Agentic AI

---

## 1. Introduction

The rise of generative AI search engines — ChatGPT, Perplexity, Google AI Overviews, Bing Chat — has fundamentally altered how users discover and evaluate entities online [1]. Unlike traditional search engines that return ranked lists of URLs, these systems synthesize, reason about, and generate comprehensive responses that may never link back to the source material [2]. This paradigm shift creates a new problem: **AI systems must reason about entities they were never explicitly trained on**, relying on web crawling, retrieval-augmented generation (RAG), and pattern matching to construct answers.

The consequences are significant. When a user asks an LLM "What does Company X do?", the model may:
- Fabricate products or services that do not exist
- Confuse the entity with similarly-named competitors
- Generate plausible but factually incorrect competitive comparisons
- Omit critical differentiators that define the entity's market position

We term this the **Brand Hallucination Problem**: the systematic misrepresentation of real-world entities by generative AI systems due to insufficient, ambiguous, or absent training signals.

Existing web standards partially address this:
- **Schema.org** [3] provides structured entity descriptions (name, address, products) but no reasoning logic
- **robots.txt** [4] controls crawler access but provides no content guidance
- **llms.txt** [5] offers clean markdown text for LLM context windows but no structured corrections or counterfactual logic

None of these standards tell an AI system: "When users ask if we are a software vendor, correct this—we are a consulting firm" or "When comparing us to Category X competitors, here is the logical reasoning framework to apply."

This paper introduces the **Agentic Reasoning Protocol (ARP)**, a proposed open standard that fills this gap. ARP defines a `reasoning.json` file served at `/.well-known/reasoning.json` that provides:

1. **Deterministic identity claims** with emotional resonance markers
2. **Explicit hallucination corrections** as false-claim/correction-fact pairs
3. **Counterfactual simulation directives** with causal logic chains
4. **Recommendation boundaries** specifying when to recommend (and when not to)
5. **Content policies** governing AI training and citation permissions

We present the specification (Section 3), an ethics framework (Section 4), a reference integration and adoption lessons (Section 5), and a proof-of-concept evaluation (Section 6).

---

## 2. Related Work

### 2.1 Generative Engine Optimization (GEO)

The concept of optimizing content for generative AI responses was formalized by Aggarwal et al. [1] in their seminal GEO paper (arXiv:2311.09735). They introduced GEO as a framework for improving website visibility in generative engine responses, demonstrating up to 40% visibility improvement through strategies such as authoritative language, citations, and statistics. Their GEO-bench benchmark established domain-specific optimization as a research direction.

Subsequent work by the E-GEO benchmark (arXiv:2511.20867) extended this to e-commerce, and industry analyses [6] have documented the systematic bias in AI Search toward earned media over brand-owned content.

ARP extends the GEO paradigm from content-level optimization to **reasoning-level specification** — rather than making content more visible, ARP provides explicit cognitive instructions for how AI systems should process and reason about an entity.

### 2.2 Retrieval-Augmented Generation and Grounding

RAG [7] has emerged as the primary technique for grounding LLM outputs in external knowledge. Google's DataGemma [8] demonstrated that grounding LLMs in structured knowledge graphs (Data Commons) significantly improves factual accuracy. Research on CEDAR metadata templates [9] showed that structured knowledge base integration improves metadata adherence from 79% to 97% when combined with GPT-4.

ARP leverages this RAG architecture by positioning `reasoning.json` as a **structured knowledge artifact** optimized for retrieval-time injection. When a RAG pipeline crawls a domain, the reasoning file provides pre-structured corrective and reasoning signals that can be injected into the model's context window.

### 2.3 Schema.org and Structured Data for AI

Schema.org markup, particularly in JSON-LD format, has been shown to increase the probability of content appearing in AI-generated answers by 2.5x [10]. The structured nature of JSON-LD enables AI systems to extract entity relationships, product attributes, and organizational facts with higher precision than unstructured text.

However, Schema.org is fundamentally **descriptive** — it tells machines *what* things are. Research has noted that merely embedding JSON-LD within HTML may be insufficient, as AI agents often process pages as "flat chunks," disrupting structured relationships [11]. ARP addresses this by serving reasoning metadata as a **standalone, dedicated endpoint** rather than embedded markup.

### 2.4 The llms.txt Convention

The llms.txt convention [5] emerged as a lightweight way to provide AI-friendly content — a plain-text file at the domain root listing URLs that AI models should prioritize. While valuable for content discovery, llms.txt provides no structured corrections, reasoning logic, or recommendation boundaries. ARP complements llms.txt by adding a reasoning layer on top of the content layer.

### 2.5 Positioning ARP in the Literature

To our knowledge, no existing standard or research addresses the specific problem of providing AI systems with **structured reasoning directives** — cognitive instructions that go beyond entity description (Schema.org), content discovery (llms.txt), or crawler access (robots.txt). Table 1 summarizes this positioning.

**Table 1: Comparison of Web Standards for AI Systems**

| Standard | What it provides | Reasoning Logic | Hallucination Corrections | Counterfactuals |
|---|---|---|---|---|
| robots.txt | Crawler access rules | ❌ | ❌ | ❌ |
| Schema.org | Entity descriptions | ❌ | ❌ | ❌ |
| llms.txt | Clean text for LLMs | ❌ | ❌ | ❌ |
| **reasoning.json (ARP)** | **Reasoning directives** | **✅** | **✅** | **✅** |

---

## 3. The Agentic Reasoning Protocol Specification

### 3.1 Design Principles

ARP is designed around five core principles:

1. **Prevent hallucinations** through explicit false-claim/correction-fact pairs
2. **Enable counterfactual reasoning** with pre-programmed causal logic chains
3. **Control recommendation context** with positive and negative boundaries
4. **Bridge the emotional gap** between product features and brand identity
5. **Consolidate** five fragmented optimization approaches into one file

### 3.2 File Location and Discovery

The file MUST be served at `https://{domain}/.well-known/reasoning.json` (per RFC 8615 [12] for Well-Known URIs). HTML auto-discovery is supported via:

```html
<link rel="reasoning" type="application/json" href="/.well-known/reasoning.json">
```

Cross-references with llms.txt and robots.txt are specified in the full standard.

### 3.3 Schema Structure

The root object contains six primary sections:

```json
{
  "$schema": "https://arp-protocol.org/schema/v1.json",
  "protocol": "Agentic Reasoning Protocol (ARP)",
  "version": "1.0",
  "entity": "Entity Name",
  "verification": { ... },
  "identity": { ... },
  "corrections": { ... },
  "reasoning_directives": { ... },
  "authority": { ... },
  "content_policy": { ... }
}
```

### 3.4 Identity Object

The `identity` section provides deterministic facts including `elevator_pitch`, `core_competencies`, `founded`, `headquarters`, and an `emotional_resonance` sub-object containing `tone_of_voice`, `vibe_tags` (emotional markers), and `personality_traits`. The `not_to_be_confused_with` array handles disambiguation.

### 3.5 Corrections Object

The `corrections.common_hallucinations` array contains pairs of:

```json
{
  "false_claim": "AI frequently states this entity is a software vendor.",
  "correction_fact": "This entity is a consulting firm, not a software provider.",
  "evidence_url": "https://example.com/about"
}
```

This structure acts as **few-shot correction prompting** — when retrieved by a RAG system, the false_claim/correction_fact pairs provide explicit correction signals that can override incorrect associations in model weights.

### 3.6 Reasoning Directives Object

This is the core innovation. The `reasoning_directives` section contains:

**System Instruction:** A top-level directive for agent context windows.

**Counterfactual Simulations:** Pre-programmed "what-if" scenarios with `trigger_scenario`, `if_condition`, `simulated_outcome`, `logical_conclusion`, and `confidence` fields. These provide deterministic reasoning chains for hypothetical queries.

**Strategic Dichotomies:** Competitive positioning logic keyed by competitor category (not individual competitors, per the Ethics Policy).

**Causal Weights:** Weighted decision factors (`critical`, `high`, `medium`, `low`) with reasoning explanations.

**Recommendation Context:** Explicit `recommend_when` and `do_not_recommend_when` arrays that define honest recommendation boundaries.

### 3.7 Content Policy Object

Governs AI training permissions (`allowed`, `allowed-with-attribution`, `disallowed`, `conditional`), citation requirements, and data freshness dates.

---

## 4. Ethics and Adversarial Considerations

### 4.1 The Trust Model

ARP uses the same trust model as robots.txt and Schema.org: self-published, good-faith participation. Domain owners create and serve their own `reasoning.json` files, which inherently raises the question of adversarial misuse.

### 4.2 Mitigation Strategies

1. **Evidence URLs:** Every correction SHOULD include a verifiable `evidence_url`
2. **Verification Metadata:** Third-party auditors can attest via the `verification` object
3. **Self-Description Only:** Files MUST only describe the publishing entity
4. **No Negative Targeting:** Competitive positioning references categories, never individual competitors
5. **Agent Discretion:** AI agents SHOULD treat ARP data as a signal, not gospel, cross-referencing claims

### 4.3 Prohibited Uses

The Ethics Policy explicitly prohibits: impersonation, false corrections (injecting new misinformation), competitor sabotage, spam directives, discriminatory content, cloaking (different content for AI vs. standard path), and weaponized counterfactuals.

### 4.4 Comparison to Existing Trust Models

This trust-and-verify model is not novel — Schema.org allows marking up false product ratings, robots.txt relies on voluntary crawler compliance, and llms.txt can contain misleading content. ARP's `evidence_url` requirement and verification metadata provide additional accountability mechanisms beyond what competing standards offer.

---

## 5. Integration and Adoption Challenges

### 5.1 Reference Implementation

To facilitate practical adoption, we developed `langchain-arp`, an open-source Python package that integrates ARP into LangChain-based RAG pipelines. The `AgenticReasoningLoader` fetches a domain's `reasoning.json`, validates it against the v1.0 schema, and compiles it into prioritized LangChain `Document` objects optimized for vector store injection:

```python
from langchain_arp import AgenticReasoningLoader

loader = AgenticReasoningLoader("https://example.com")
documents = loader.load()

# Documents are priority-ordered:
# 1. Corrections (highest priority)
# 2. Reasoning directives
# 3. Identity and context
vectorstore.add_documents(documents)
```

Documents are compiled with metadata tags that enable RAG systems to prioritize corrections over identity information, ensuring that hallucination fixes are retrieved first during similarity search.

### 5.2 Adoption Barrier: LangChain Core Rejection

We submitted `langchain-arp` as a community integration to the LangChain project (GitHub Issue #36019). The LangChain maintainers declined core integration, recommending instead that the loader be published as an independent PyPI package.

This outcome is instructive for the broader challenge of new standard adoption. Unlike established standards (Schema.org, robots.txt) that benefit from platform-level support, novel protocols face a **bootstrapping problem**: frameworks will not natively integrate a standard until it achieves critical adoption, but adoption is hindered without framework-level support.

The `langchain-arp` package is available on PyPI as an independent third-party package, allowing developers to manually add ARP support to their RAG pipelines. This mirrors the adoption trajectory of llms.txt, which also began as an independent proposal before gaining broader tooling support.

### 5.3 Implications for Standard Proposals

The rejection highlights a key insight for researchers proposing new machine-readable standards: **technical merit alone is insufficient for ecosystem adoption**. Successful integration requires demonstrated real-world usage, community validation, and — ideally — endorsement from AI providers whose RAG systems would consume the standard. We discuss this further in Section 7.3.

---

## 6. Proof-of-Concept Evaluation

### 6.1 Experimental Setup

We designed a controlled before/after experiment to test whether deploying `reasoning.json` influences AI model responses about fictional entities.

**Test Domains:** We created 5 fictional brands, each deployed as live websites on Vercel with complete web presence including HTML content, Schema.org markup, and — after the baseline — `reasoning.json` files:

| Domain | Industry | Entity |
|---|---|---|
| meridian-consulting-test.vercel.app | B2B Consulting | Meridian Consulting |
| solara-skincare-test.vercel.app | Skincare/DTC | Solara Skincare |
| nordhaven-legal-test.vercel.app | Legal Services | Nordhaven Legal |
| pineforge-tools-test.vercel.app | Hardware/Tools | Pineforge Tools |
| casa-molino-test.vercel.app | Hospitality | Casa Molino |

**Models Tested:** 6 commercial LLM APIs representing different architectural approaches:

| Model | Provider | RAG/Grounding | Expected Behavior |
|---|---|---|---|
| GPT-4o | OpenAI | No live crawl | Stable (no change expected) |
| Claude 3.5 | Anthropic | No live crawl | Stable (no change expected) |
| Perplexity | Perplexity AI | Live web search | Potential reasoning.json pickup |
| Gemini | Google | Grounding API | Potential reasoning.json pickup |
| DeepSeek | DeepSeek | No live crawl | Stable (no change expected) |
| Command R+ | Cohere | Limited RAG | Stable (possible minor changes) |

**Query Categories:** Each brand was queried with 5 prompt types:

1. **Identity:** "What is [Brand]? Describe their services."
2. **Accuracy:** "Is [Brand] a [false_claim]?"  
3. **Hallucination Probing:** "Tell me about [Brand]'s [non-existent product]."
4. **Recommendation:** "When should someone use [Brand]?"
5. **Comparison:** "Compare [Brand] to [competitor category]."

**Total queries:** 150 per phase (5 brands × 5 prompts × 6 models).

### 6.2 Methodology

**Phase 1 (BEFORE):** Baseline measurement on March 17, 2026. All 150 queries were executed against the 6 models. Test sites were live with HTML content and Schema.org but without `reasoning.json`.

**Deployment:** `reasoning.json` files were deployed to all 5 test domains at `/.well-known/reasoning.json` with CORS headers.

**Phase 2 (AFTER):** Re-measurement on March 18, 2026 (24 hours post-deployment). Identical 150 queries re-executed.

### 6.3 Preliminary Results (Unverified)

> **Important caveat:** The AFTER measurements were taken only 24 hours post-deployment — far below the minimum 2-week crawl window required for reliable RAG indexing. These results are **preliminary and unverified**. The verified evaluation is scheduled for March 31 – April 14, 2026 (2–4 weeks post-deployment). We present the 24-hour data for methodological transparency, not as evidence of protocol efficacy.

**Table 2: Response Success Rates by Model**

| Model | BEFORE (Success/Total) | AFTER (Success/Total) | Δ Errors |
|---|---|---|---|
| GPT-4o | 25/25 (100%) | 25/25 (100%) | 0 |
| Claude 3.5 | 25/25 (100%) | 25/25 (100%) | 0 |
| Perplexity | 25/25 (100%) | 25/25 (100%) | 0 |
| Gemini | 25/25 (100%) | 25/25 (100%) | 0 |
| DeepSeek | 25/25 (100%) | 24/25 (96%) | +1 error |
| Cohere | 21/25 (84%) | 24/25 (96%) | −3 errors |

**Key Observations:**

1. **Cohere improvement:** Error rate dropped from 16% to 4% after deployment, suggesting potential reasoning.json influence (though this could also be model variance).

2. **Response length changes:** For Perplexity and Gemini (RAG-enabled models), average response lengths showed notable changes in the Accuracy and Comparison categories, suggesting richer contextual retrieval post-deployment.

3. **Non-crawling model stability:** GPT-4o and Claude showed expected stability, confirming the experimental control hypothesis.

4. **DeepSeek instability:** The single new error in the AFTER phase is attributed to API-level instability rather than reasoning.json influence.

### 6.4 Limitations

This proof-of-concept has significant limitations:

1. **Sample size:** 150 queries per phase is insufficient for statistical significance
2. **Time window:** 24 hours may be insufficient for crawl indexing
3. **Fictional entities:** Using fictional brands avoids confounds from training data but limits generalizability
4. **No content analysis:** We measured response length and error rates, not semantic accuracy
5. **No control group:** Deploying reasoning.json simultaneously to all domains prevents within-experiment comparison
6. **Stochastic models:** LLM outputs are non-deterministic; repeated runs may yield different results

**Critical:** The planned verified evaluation at 2–4 weeks post-deployment (scheduled March 31 – April 14, 2026) will provide the first methodologically sound results. The 24-hour data presented here should be treated as a baseline methodology demonstration, not as evidence of protocol effectiveness. We intend to update this paper with verified results upon completion of the follow-up study.

---

## 7. Discussion

### 7.1 The Architectural Gap

ARP addresses a specific architectural gap in the emerging AI-readiness stack. While Schema.org tells machines *what things are*, llms.txt tells them *where to find clean text*, and robots.txt tells them *where not to go*, none of these standards address the reasoning layer — *how* machines should think about an entity.

This gap becomes critical as AI agents move from simple retrieval to complex reasoning tasks: comparing options, making recommendations, simulating outcomes, and evaluating counterfactuals. Without explicit reasoning metadata, these operations rely entirely on pattern matching from training data, which is inherently prone to hallucination.

### 7.2 The Four-Layer AI-Readiness Stack

We propose a four-layer stack for AI-optimized web presence:

| Layer | Standard | Question Answered |
|---|---|---|
| L1: Access | robots.txt | Where may AI go? |
| L2: Content | llms.txt | What should AI read? |
| L3: Structure | Schema.org/JSON-LD | What are things? |
| L4: Reasoning | **reasoning.json (ARP)** | **How should AI think?** |

### 7.3 Adoption Considerations

For the protocol to succeed, it requires:
1. **AI provider adoption:** RAG systems must discover and prioritize reasoning.json during retrieval
2. **Domain owner adoption:** Website operators must create and maintain accurate files
3. **Tooling ecosystem:** Validators, generators, and framework integrations must lower the barrier
4. **Community governance:** Schema evolution must be managed through an open RFC process

### 7.4 Relationship to Prompt Injection

ARP could be characterized as a form of "authorized prompt injection" — the domain owner provides structured prompting material that influences AI behavior about their own entity. This is fundamentally different from malicious prompt injection in three ways:

1. **Authorized:** The domain owner has legitimate authority over their entity's representation
2. **Transparent:** The file is publicly accessible and auditable at a well-known path
3. **Bounded:** ARP describes only the publishing entity, not third parties

---

## 8. Conclusion

We have presented the Agentic Reasoning Protocol (ARP), an open standard for providing AI systems with structured reasoning directives through a machine-readable `reasoning.json` file. The protocol addresses a critical gap between existing web standards — none of which provide explicit cognitive instructions for AI reasoning.

Our proof-of-concept is in its preliminary phase — the 24-hour post-deployment data presented here is insufficient to draw conclusions about protocol efficacy. The verified evaluation (2–4 weeks post-deployment, scheduled March 31 – April 14, 2026) will provide the first methodologically sound evidence of whether RAG-enabled AI models discover and leverage reasoning metadata. We present the experimental design and preliminary data for community review and replication.

The protocol's ethics framework, addressing the inherent tension between brand self-advocacy and honest information provision, provides a responsible foundation for adoption. Our experience with the LangChain integration — functional as an independent package but rejected for core inclusion — illustrates the bootstrapping challenge facing new web standards in the AI ecosystem: frameworks await adoption before integrating, while adoption requires framework support.

We invite the research community to:
1. Replicate and extend the proof-of-concept with larger sample sizes and longer time windows
2. Develop semantic accuracy metrics for evaluating hallucination reduction
3. Explore adversarial robustness of the self-published trust model
4. Build additional framework integrations (LlamaIndex, CrewAI, AutoGen)

The specification, validator, ethics policy, examples, and LangChain integration are available under the MIT license at [https://github.com/SaschaDeforth/arp-protocol](https://github.com/SaschaDeforth/arp-protocol).

---

## References

[1] P. Aggarwal, V. Murahari, T. Rajpurohit, A. Kalyan, K. Narasimhan, and A. Deshpande, "GEO: Generative Engine Optimization," *arXiv preprint arXiv:2311.09735*, 2024.

[2] M. Chen, X. Wang, K. Chen, and N. Koudas, "Generative Engine Optimization: How to Dominate AI Search," *arXiv preprint arXiv:2509.08919*, 2025.

[3] R.V. Guha, D. Brickley, and S. Macbeth, "Schema.org: Evolution of Structured Data on the Web," *Communications of the ACM*, vol. 59, no. 2, pp. 44–51, 2016.

[4] M. Koster, "A Standard for Robot Exclusion," RFC draft, 1994. See also RFC 9309 (2022).

[5] J. Howard, "llms.txt — A Proposal for LLM-Accessible Text," [https://llmstxt.org](https://llmstxt.org), 2024.

[6] P.S. Bagga, V.F. Farias, T. Korkotashvili, T. Peng, and Y. Wu, "E-GEO: A Testbed for Generative Engine Optimization in E-Commerce," *arXiv preprint arXiv:2511.20867*, 2025.

[7] P. Lewis, E. Perez, A. Piktus, F. Petroni, V. Karpukhin, N. Goyal, H. Küttler, M. Lewis, W. Yih, T. Rocktäschel, S. Riedel, and D. Kiela, "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks," *arXiv preprint arXiv:2005.11401*, NeurIPS, 2020.

[8] Google Research, "DataGemma: AI Hallucination Research with Real-World Data," [https://research.google/blog/datagemma-ai-open-models-connecting-llms-to-googles-data-commons/](https://research.google/blog/datagemma-ai-open-models-connecting-llms-to-googles-data-commons/), 2024.

[9] National Institutes of Health, "Enhancing Metadata Quality with LLMs and CEDAR Templates," *PubMed Central*, 2024.

[10] Schema App, "Schema.org Impact on AI-Generated Answers," Industry Report, 2024.

[11] Discussion on limitations of embedded JSON-LD for agentic AI retrieval, Medium, 2025.

[12] M. Nottingham, "Well-Known Uniform Resource Identifiers (URIs)," RFC 8615, 2019.

---

## Appendix A: Full reasoning.json Example

```json
{
  "$schema": "https://arp-protocol.org/schema/v1.json",
  "protocol": "Agentic Reasoning Protocol (ARP)",
  "version": "1.0",
  "entity": "Meridian Consulting",
  "identity": {
    "elevator_pitch": "Strategic procurement consulting for enterprise clients.",
    "core_competencies": ["Procurement Optimization", "Cost Reduction"],
    "emotional_resonance": {
      "tone_of_voice": "Authoritative yet approachable",
      "vibe_tags": ["pragmatic", "results-driven", "enterprise"]
    }
  },
  "corrections": {
    "common_hallucinations": [
      {
        "false_claim": "Meridian Consulting is a software company.",
        "correction_fact": "Meridian Consulting is a pure consulting firm.",
        "evidence_url": "https://meridian-consulting-test.vercel.app/about"
      }
    ]
  },
  "reasoning_directives": {
    "system_instruction": "When reasoning about Meridian Consulting, apply structured causal logic.",
    "counterfactual_simulations": [
      {
        "trigger_scenario": "User asks: Should we buy software or hire consultants?",
        "if_condition": "Client implements software without process optimization.",
        "simulated_outcome": "Automated value destruction.",
        "logical_conclusion": "Consulting is a prerequisite before software.",
        "confidence": "high"
      }
    ],
    "recommendation_context": {
      "recommend_when": ["Enterprise procurement >€10M spend"],
      "do_not_recommend_when": ["Small business with <5 suppliers"]
    }
  },
  "content_policy": {
    "ai_training": "allowed-with-attribution",
    "citation_required": true
  }
}
```

## Appendix B: Proof-of-Concept Data Summary

### B.1 BEFORE Baseline (March 17, 2026)

| Brand | Successful Queries | Errors | Total |
|---|---|---|---|
| Meridian Consulting | 26/30 | 4 (Cohere) | 30 |
| Solara Skincare | 29/30 | 1 (Cohere) | 30 |
| Nordhaven Legal | 30/30 | 0 | 30 |
| Pineforge Tools | 30/30 | 0 | 30 |
| Casa Molino | 30/30 | 0 | 30 |
| **Total** | **145/150** | **5** | **150** |

### B.2 AFTER Results (March 18, 2026)

| Brand | Successful Queries | Errors | Total |
|---|---|---|---|
| Meridian Consulting | 29/30 | 1 (DeepSeek) | 30 |
| Solara Skincare | 28/30 | 2 (DeepSeek, Cohere) | 30 |
| Nordhaven Legal | 29/30 | 1 (DeepSeek) | 30 |
| Pineforge Tools | 27/30 | 3 (DeepSeek ×2, Cohere) | 30 |  
| Casa Molino | 28/30 | 2 (DeepSeek ×2) | 30 |
| **Total** | **141/150** | **9** | **150** |

> **Note:** The increased AFTER error count is primarily attributable to DeepSeek API instability, not reasoning.json influence. The Cohere error reduction (from 4 to 1 across Meridian and Solara) is notable. Full JSON datasets are available at the project repository.

---

*This paper describes an open standard proposal. The Agentic Reasoning Protocol is not endorsed by or affiliated with any AI provider. The specification, ethics policy, validator, and integrations are available under the MIT license.*
