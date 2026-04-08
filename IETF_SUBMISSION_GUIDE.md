# IETF Internet-Draft Submission Guide
## draft-deforth-arp-00

### Generierte Dateien

| Datei | Format | Größe | Zweck |
|-------|--------|-------|-------|
| `draft-deforth-arp-00.xml` | xml2rfc v3 (RFC 7991) | 32 KB | Quell-Dokument für Submission |
| `draft-deforth-arp-00.txt` | Plain Text (896 Zeilen) | 33 KB | Gerenderte TXT-Version |
| `draft-deforth-arp-00.html` | HTML | 96 KB | Browser-Preview |

### Submission-Schritte

#### 1. IETF Datatracker Account erstellen
→ https://datatracker.ietf.org/accounts/create/

#### 2. Individual Submission einreichen
→ https://datatracker.ietf.org/submit/

- **Submission Type:** Individual (nicht WG)
- **Upload:** `draft-deforth-arp-00.xml` (xml2rfc v3)
- Das System generiert automatisch TXT, HTML und PDF Versionen
- Du bekommst eine Confirmation-Email

#### 3. Bestätigung
- Email bestätigen (innerhalb 48h)
- Draft erscheint dann auf: `https://datatracker.ietf.org/doc/draft-deforth-arp/`
- Automatischer 6-Monats-Expiry (8. Oktober 2026)

### Inhalt des Drafts

**12 Sektionen:**
1. Introduction (+ Design Goals)
2. Terminology (BCP 14 / RFC 2119)
3. Protocol Overview (4-Phasen-Flow)
4. DNS TXT Record Format (Record Name, Value, Multiple Keys, Size)
5. Reasoning Payload (Location, Required Fields, Optional Sections)
6. Canonicalization (JCS/RFC 8785)
7. Signing Procedure (Ed25519 + Base64url)
8. Verification Procedure (14-Step Algorithmus + Result Codes)
9. Signature Block Format (_arp_signature Schema)
10. Key Rotation
11. Relationship to Existing Standards (DKIM, C2PA, W3C VC, AIVS, SCITT, Schema.org)
12. Security Considerations (DNS Security, Key Compromise, Replay, Truthfulness, Narrative Injection, Cross-Domain)

**+ Appendices:**
- A. Complete Example (DNS Record + Payload + Verification Steps)
- B. JSON Schema Reference
- Acknowledgements (W3C AIVS CG)

**Normative References:** RFC 1035, 2119, 4648, 8032, 8174, 8785
**Informative References:** RFC 6376, AIVS v1.0, C2PA v2.2, W3C VC 2.0, EU AI Act, ARP Schema

### Nächste Schritte nach Submission

1. **Announce auf IETF Mailing Lists** (z.B. `ietf-announce`, relevante WG Lists)
2. **Cross-Post** auf W3C AIVS CG Mailing List (`public-aivs@w3.org`)
3. **LinkedIn Announcement** mit Datatracker-Link
4. **Version -01** nach Feedback erstellen (z.B. AIVS Interop Section hinzufügen)
