# Gemini Technical Review — Analysis & Fix Plan
## draft-deforth-arp-00 → draft-deforth-arp-01

### Bewertung der Kritikpunkte

| # | Issue | Severity | Valid? | Action |
|---|---|---|---|---|
| 1.1 | Unauthenticated Signature Metadata | 🔴 CRITICAL | ✅ Ja | Fix: Nur `signature` excluden, nicht gesamten Block |
| 1.2 | Cross-Domain Replay (fehlende Domain-Bindung) | 🔴 CRITICAL | ✅ Ja | Fix: Required `domain` field im Payload |
| 2.1 | Section 8 vs 12.6 Widerspruch | 🟡 HIGH | ✅ Ja | Fix: DKIM-CNAME Delegation, `dns_record` entfernen |
| 3.1 | BCP 190 Namespace Pollution | 🟡 HIGH | ✅ Ja | Fix: `/.well-known/reasoning.json` |
| 3.2 | IANA _arp Registration | 🟡 MEDIUM | ✅ Ja | Fix: Formale IANA Registration |
| 3.3 | Custom Crypto Envelope vs JWS | 🟢 LOW | ⚠️ Teilweise | Notieren als Future Work, nicht jetzt umstellen |
| 4.1 | CORS Header fehlt | 🟡 MEDIUM | ✅ Ja | Fix: SHOULD CORS * |
| 4.2 | HTTP Redirect Behavior | 🟡 MEDIUM | ✅ Ja | Fix: Original Domain für DNS |
| 4.3 | DNS Key Caching | 🟢 LOW | ✅ Ja | Fix: Keys bis expires_at behalten |

### Kritische Breaking Changes für -01

1. **Canonicalization:** Bisher: gesamten `_arp_signature` Block excluden → Neu: NUR `signature` Feld excluden
2. **Payload:** Neues REQUIRED Feld `domain` (bindet Payload an Domain)
3. **Discovery:** `/reasoning.json` → `/.well-known/reasoning.json`
4. **Signature Block:** `dns_record` Feld ENTFERNEN (Verifier konstruiert DNS-Name selbst)
5. **Cross-Domain:** Via DNS CNAME, nicht via JSON-Feld
