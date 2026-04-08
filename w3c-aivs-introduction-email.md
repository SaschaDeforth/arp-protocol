# W3C AIVS Community Group — Introduction Email

**To:** public-aivs@w3.org  
**Subject:** Complementary Work: Content Provenance for AI Agent Inputs (ARP)

---

Hi everyone,

I'm Sascha Deforth, founder of TrueSource (truesource.studio), a consultancy specializing in Generative Engine Optimization. I just joined the group and wanted to introduce myself and share some complementary work that I believe directly intersects with AIVS's mission.

## Context

AIVS addresses a critical gap: cryptographic proof of what an AI agent *did* — its actions, their sequence, and their integrity. This is essential for audit trails and regulatory compliance.

However, there is a symmetric gap on the *input* side: AI agents and RAG pipelines currently have no way to verify that the structured data they *consume* was actually authorized by the domain owner. This enables what we've empirically demonstrated as "Phantom Authority" — the ability for any actor to become the #1 cited source in AI search engines within 24 hours using nothing but well-structured semantic data on a visually empty website.

## The Agentic Reasoning Protocol (ARP)

To address this, we've developed the Agentic Reasoning Protocol (ARP v1.2), a lightweight DNS-anchored verification mechanism for machine-readable entity claims:

- **Signing:** Entity claims (reasoning.json) are signed using Ed25519 (RFC 8032)
- **Canonicalization:** JCS/RFC 8785 for deterministic hashing
- **Verification:** Public key published via DNS TXT record (analogous to DKIM)
- **Scope:** Verifies content provenance — who authorized the structured data an agent reads

The full specification, JSON Schema, and reference implementation (signer + validator) are open source:
→ https://arp-protocol.org
→ Schema: https://arp-protocol.org/schema/v1.2.json

## How ARP complements AIVS

| Dimension | AIVS | ARP |
|-----------|------|-----|
| Verifies | What an agent DID (output integrity) | What an agent READS (input integrity) |
| Crypto | Ed25519 + SHA-256 hash chains | Ed25519 + JCS canonicalization |
| Anchor | Self-contained proof bundle | DNS TXT record (like DKIM) |
| Scope | Session-level audit trail | Domain-level content provenance |
| Together | Full trust chain: verified inputs → verified actions → verified outputs |

I believe these two specifications together could form the foundation of end-to-end integrity for agentic AI systems — which is exactly what the EU AI Act Article 19 and NIST AI RMF will require.

## Empirical Validation

We've conducted a public field experiment ("Phantom Authority") demonstrating the vulnerability that ARP addresses. A completely empty website with only machine-readable structured data became the #1 cited source in Perplexity and was independently validated by ChatGPT and Google Deep Research. This empirically proves that RAG systems currently have zero content provenance verification.

I'd be happy to share the full technical writeup and discuss how ARP and AIVS could be designed to interoperate — for example, an AIVS session bundle could include ARP verification status for each URL the agent accessed during the session.

Looking forward to contributing to the group's work.

Best,
Sascha Deforth
TrueSource | arp-protocol.org
hello@truesource.studio
