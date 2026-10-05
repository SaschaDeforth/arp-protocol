# Agentic Reasoning Protocol — LangChain Integration

A LangChain-compatible Document Loader for `reasoning.json` files (ARP v1.3, "Reader Profile").

A `reasoning.json` file is an entity's self-description: identity data, corrections with evidence links and self-described context. The loader turns it into Documents and states in every Document where the content comes from and what was checked.

## Installation

```bash
pip install requests langchain-core
# for the signature check (reference verifier arp_cli.py from this repository):
pip install cryptography rfc8785 dnspython
```

The signature check uses `arp_cli.py` (v1.4 or later). The loader imports it when it is on the Python path or, inside this repository, from `../../arp_cli.py`. Without it, a signed file is marked `NOT_CHECKED`.

## Usage

```python
from arp_loader import AgenticReasoningLoader

loader = AgenticReasoningLoader("https://example.com")
docs = loader.load()

for doc in docs:
    print(doc.metadata["section"], doc.metadata["authorship_status"])
```

## Provenance line

Every Document starts with one neutral line in plain text (SPEC v1.3 §13.10), followed by an empty line and the content:

```
Source: example.com — self-description (ARP). Authorship verified via Ed25519/DNS on 2026-10-05; this verifies the publisher, not the truth of the content.
```

Other results use the same form:

```
Source: example.com — self-description (ARP). Not signed; the publisher is not cryptographically verified.
Source: example.com — self-description (ARP). Signature check failed (key_revoked); the publisher is not verified.
Source: example.com — self-description (ARP). Signature expired on 2026-12-23; the publisher is not currently verified.
Source: example.com — self-description (ARP). Signature present, not checked by this loader; the publisher is not verified.
```

The line describes origin and check result. It contains no instruction to the model and no tags that imitate system markup; the tag-based example of SPEC v1.2 is no longer used. How a model weighs the content remains the decision of the application.

## Documents

The loader fetches `/.well-known/reasoning.json` and yields one Document per section:

1. **Corrections** — topic-anchored statements the entity publishes about itself, with evidence links
2. **Identity** — self-description, provenance statement and positioning (`framing_context`)
3. **Organization** — legal facts from the v1.3 `organization` object
4. **Fit** — situations the entity describes as a typical fit or not a fit (`recommendation_context`)
5. **Domain expertise** — the entity's perspective on scenarios in its field
6. **Market positioning** — the entity's view of its market category

The `diagnostics` object is never passed on (SPEC §12). Members named like instructions (`system_instruction`, `ai_directive`, `agent_directive`, v1.0 `then_directive`) are not passed on either. The v1.0 container `reasoning_directives` is not read; content is taken from `entity_claims` only.

## Input checks

- The file is parsed as I-JSON (RFC 7493). A file with a member name that occurs twice in one object, or with `NaN`/`Infinity`, is rejected with a `ValueError`. With duplicate names, JSON parsers keep the last value while people and language models reading the text see the first; a signature covers only the parsed object. Files nested deeper than 64 levels are rejected as well.
- Fetches are limited to 1 MiB and 30 seconds overall. The 30 seconds also hold while the server sends its status line and headers: the fetch runs in a worker thread, and the loader stops waiting after 30 seconds even if the server sends one byte at a time. Redirects are followed only within the same host and never from https to http. URLs with userinfo (`user@host`) or backslashes are refused.
- `representations` are fetched only when `href` is a plain https URL on the domain of the manifest (no port, query or userinfo).

## Metadata

All metadata values are flat strings, numbers or booleans, so vector stores can index them.

| Key | Meaning |
|-----|---------|
| `authorship_status` | `CRYPTOGRAPHIC`, `UNSIGNED`, `INVALID`, `ERROR` (DNS lookup failed) or `NOT_CHECKED` |
| `authorship_reason` | e.g. `valid`, `unsigned`, `expired`, `key_revoked`, `legacy_payload_only`, `domain_mismatch`, `domain_missing`, `malformed_signature` |
| `authorship_checked_on` | Date of the check (UTC) |
| `source_line` | The provenance line shown at the top of each Document |
| `is_signed` | A signature block is present (says nothing about validity) |
| `signature_dns`, `signature_doh_url` | From `_arp_signature` (`verify.dns_name`, `verify.doh_url`), only if `authorship_status` is `CRYPTOGRAPHIC`; otherwise `none` |
| `signature_statement` | `_arp_signature.statement`, only if `authorship_status` is `CRYPTOGRAPHIC` and the statement matches the fixed wording of SPEC §13.3 for the retrieval domain; otherwise `none`. A template that reads only metadata therefore never shows a signature statement for a file whose check failed |
| `signed_at`, `expires_at` | Signature period |
| `provenance_statement`, `publisher`, `publisher_url`, `published` | From the v1.3 `provenance` object |
| `representation_url`, `representation_sha256` | The `reasoning.md` entry of `representations` |
| `representation_status` | Only with `check_representation=True`: `REPRESENTATION_MATCH`, `REPRESENTATION_MISMATCH` or `REPRESENTATION_UNCHECKED` |

A `CRYPTOGRAPHIC` status means that the operator of the domain published exactly this file. It does not mean that the statements are true.

## Options

```python
AgenticReasoningLoader(
    "https://example.com",
    path="/.well-known/reasoning.json",
    timeout=10,
    verify_signature=True,        # check via arp_cli; False → NOT_CHECKED
    check_representation=False,   # fetch reasoning.md and compare its sha256
)
```

## Use in a RAG Pipeline

```python
from langchain_community.vectorstores import Chroma
from langchain_openai import OpenAIEmbeddings

docs = AgenticReasoningLoader("https://example.com").load()
vectorstore = Chroma.from_documents(docs, OpenAIEmbeddings())
retriever = vectorstore.as_retriever()
```

The provenance line travels with each chunk, so the retrieved text keeps its source and check result.

## Standalone Usage (No LangChain)

```python
from arp_loader import load_reasoning

docs = load_reasoning("https://example.com")
for doc in docs:
    print(doc.page_content)
```

## CLI Usage

```bash
python arp_loader.py https://example.com
```

## Tests

```bash
python3 -m pytest tests/test_arp_loader.py   # from the repository root
```

## License

MIT
