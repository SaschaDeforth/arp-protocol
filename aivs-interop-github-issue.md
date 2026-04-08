# GitHub Issue: AIVS ↔ ARP Interoperability Proposal

**Repository:** https://github.com/bkauto3/Conduit  
**Type:** Feature Proposal / Discussion  

---

## Title: Proposal: ARP integration for content provenance verification in AIVS sessions

## Body:

### Summary

I'd like to propose interoperability between AIVS and the [Agentic Reasoning Protocol (ARP)](https://arp-protocol.org) — a DNS-anchored, Ed25519-based verification mechanism for machine-readable entity claims consumed by AI agents.

AIVS and ARP are architecturally complementary and share the same cryptographic primitives:

| Dimension | AIVS | ARP |
|-----------|------|-----|
| **Verifies** | What an agent DID (output/action integrity) | What an agent READS (input/content provenance) |
| **Crypto** | Ed25519 + SHA-256 | Ed25519 + JCS/RFC 8785 |
| **Trust anchor** | Self-contained proof bundle | DNS TXT record (DKIM model) |
| **Scope** | Agent session audit trail | Domain-level content provenance |

Together, they form a complete trust chain: **verified inputs → verified actions → verified outputs**.

### The Gap AIVS Explicitly Identifies

Section 9.2 of the AIVS v1.0 spec ("What AIVS Does NOT Prove") identifies two limitations that ARP directly addresses:

1. **Key authenticity**: *"AIVS does not include a PKI or certificate chain. The public key in the bundle is self-asserted."*
   
   → ARP anchors public keys in DNS TXT records (like DKIM), providing domain-verified key authenticity without requiring PKI infrastructure.

2. **Truthfulness**: *"AIVS does not prove that the recorded inputs/outputs actually occurred."*
   
   → While ARP doesn't prove absolute truth either, it proves **provenance** — that the structured data an agent read was authorized by the domain owner. This is the missing link between "the agent navigated to X" (AIVS proves) and "the content at X was legitimate" (ARP proves).

### Concrete Interop Proposal

#### 1. ARP Verification Status in Audit Rows

When an AIVS session logs a `browser.navigate` or content retrieval action, the `outputs_json` field could include ARP verification status:

```json
{
  "id": 3,
  "action_type": "tool_call",
  "tool_name": "browser.navigate",
  "inputs_json": "{\"url\": \"https://example.com/reasoning.json\"}",
  "outputs_json": "{\"status\": 200, \"content_type\": \"application/json\", \"arp_verification\": {\"status\": \"PASS\", \"dns_record\": \"arp._arp.example.com\", \"algorithm\": \"Ed25519\", \"signed_at\": \"2026-04-01T10:00:00Z\", \"expires_at\": \"2026-07-01T10:00:00Z\"}}",
  "cost_cents": 0,
  "timestamp": 1712412345.123456,
  "prev_hash": "abc123...",
  "row_hash": "def456..."
}
```

This doesn't break the hash chain (since `outputs_json` is intentionally excluded from hash computation per Section 4, Note), but provides an auditable record of whether content provenance was verified.

#### 2. ARP Status Values

| Status | Meaning |
|--------|---------|
| `PASS` | DNS key found, Ed25519 signature valid, not expired |
| `FAIL_NO_ARP` | No `reasoning.json` or `_arp_signature` found at domain |
| `FAIL_NO_DNS` | No DNS TXT record at `<selector>._arp.<domain>` |
| `FAIL_EXPIRED` | Signature expired (`expires_at` < current time) |
| `FAIL_INVALID` | Signature verification failed |
| `SKIP` | ARP check not performed |

#### 3. AIVS-Micro + ARP DNS Alignment

AIVS-Micro (Section 7.1) already lists "DNS TXT record verification" as a use case. ARP's DNS TXT format (`v=ARP1; k=ed25519; p=<base64-key>`) is fully compatible with AIVS-Micro's design constraints (~200 bytes).

A combined verification flow:
1. Agent reads `reasoning.json` at target URL
2. Agent verifies ARP signature via DNS TXT lookup → content provenance confirmed
3. Agent performs actions based on verified content
4. AIVS bundle logs all actions with ARP verification status per URL
5. Verifier can independently confirm both action integrity (AIVS) AND content provenance (ARP)

#### 4. Shared Cryptographic Identity (Optional)

Since both specs use Ed25519, an agent implementation could use a **single keypair** for both AIVS session signing and ARP content verification lookups, simplifying key management.

### Implementation

ARP has a reference implementation with:
- **JSON Schema:** https://arp-protocol.org/schema/v1.2.json
- **Online Validator:** https://arp-protocol.org/validator.html
- **Signer:** https://arp-protocol.org/sign.html
- **Spec:** https://arp-protocol.org/SPEC.md

The protocol is open, not proprietary, and we've submitted an IETF Internet-Draft (`draft-deforth-arp-01`) for formal standardization.

### Empirical Background

ARP was developed in response to the "Phantom Authority" experiment (April 2026), which demonstrated that a completely empty website with only structured data could become the #1 cited source in Perplexity and ChatGPT within 24 hours. This proves that RAG systems currently have zero content provenance verification — exactly the gap ARP fills.

Google's Deep Research independently validated this finding in a 60+ source academic analysis, concluding that ARP represents *"the most advanced technical solution"* for this class of vulnerability.

### Questions for Discussion

1. Should ARP verification status be a standardized field in `outputs_json`, or should it remain implementation-specific metadata?
2. Should AIVS v1.1 consider a formal "content provenance" extension that references ARP or similar protocols?
3. Is there interest in a joint reference implementation demonstrating the AIVS + ARP trust chain?

Looking forward to the discussion.

— Sascha Deforth (@SaschaDeforth)  
TrueSource | arp-protocol.org
