"""
Agentic Reasoning Protocol (ARP) — LangChain Document Loader
============================================================

A LangChain-compatible Document Loader that fetches and parses
reasoning.json files from the /.well-known/ directory of any website.

A reasoning.json file is an entity's self-description: identity data,
corrections with evidence links and self-described context. The loader turns
it into LangChain Documents. Every Document starts with a neutral provenance
line (SPEC §13.10) that says where the content comes from and what was
checked, for example:

    Source: example.com — self-description (ARP). Authorship verified via
    Ed25519/DNS on 2026-10-05; this verifies the publisher, not the truth of
    the content.

v1.3 Changes (ARP v1.3 "Reader Profile"):
- Neutral plain-text provenance line instead of a pseudo-system tag
  (the <system_note> example of SPEC v1.2 §13.10 was removed in v1.3).
- Signature check through arp_cli (reference CLI v1.4) when it is
  importable: authorship_status CRYPTOGRAPHIC / UNSIGNED / INVALID / ERROR,
  or NOT_CHECKED when arp_cli is not available. is_signed keeps its old
  meaning (a signature block is present) and says nothing about validity.
- v1.3 fields passed through as metadata: provenance (statement, publisher,
  publisher_url, published), _arp_signature.statement and verify.doh_url,
  representations (reasoning.md URL and sha256), optional sha256 check of
  reasoning.md (check_representation=True).
- organization section (v1.3) becomes its own Document.
- Loader texts are third-person descriptions; members named like
  instructions (system_instruction, reasoning_directives, *_directive,
  then_directive) are not passed on — including the v1.0 container
  reasoning_directives, which is no longer read as a fallback for
  entity_claims.
- The file is parsed as I-JSON (RFC 7493): duplicate member names, NaN and
  Infinity are rejected (ValueError). With duplicate names, JSON parsers
  keep the last value while readers of the text see the first.
- Fetches are limited: at most 1 MiB, an overall deadline that also holds
  while the server sends its headers (the fetch runs in a worker thread),
  redirects only within the same host and never from https to http, no
  URLs with userinfo or backslashes.
- signature_statement, signature_dns and signature_doh_url are passed on
  only when authorship_status is CRYPTOGRAPHIC and the statement matches
  the fixed SPEC §13.3 template for the retrieval domain; otherwise "none".
- Files nested deeper than 64 levels are rejected (ValueError).
- The fallback import of ../../arp_cli.py registers the module in
  sys.modules before running it; without that, the dataclasses in arp_cli
  failed and every signed file was NOT_CHECKED. An arp_cli older than 1.4.0
  is not used; a signed file that cannot be checked is logged as a warning.
- signature_dns is the key record that was queried ({selector}._arp.{retrieval
  domain}), not dns_record from the file (informational only, SPEC §13.3).

v1.1 Changes:
- Modern langchain_core imports (langchain.docstore.document is deprecated)
- lazy_load() generator for LangChain v0.1+ streaming support
- Cryptographic trust metadata surfaced in Document metadata
- Graceful handling of SPA catch-all routers returning HTML as 200 OK
- Content sanitization (strip HTML/script tags)

Usage:
    from arp_loader import AgenticReasoningLoader

    loader = AgenticReasoningLoader("https://example.com")
    docs = loader.load()

    for doc in docs:
        print(doc.metadata["authorship_status"], doc.metadata["section"])

License: MIT
Author: Sascha Deforth
Spec: https://arp-protocol.org
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:
    requests = None  # type: ignore

# Modern langchain_core imports (v0.1+)
try:
    from langchain_core.documents import Document
    from langchain_core.document_loaders import BaseLoader
except ImportError:
    # Fallback for standalone usage without LangChain
    class Document:  # type: ignore
        def __init__(self, page_content: str, metadata: dict):
            self.page_content = page_content
            self.metadata = metadata

    class BaseLoader:  # type: ignore
        def load(self) -> List["Document"]:
            return list(self.lazy_load())


logger = logging.getLogger(__name__)

LOADER_VERSION = "1.3"

# Regex patterns for content sanitization
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_RE = re.compile(r"<script[^>]*>.*?</script>", re.DOTALL | re.IGNORECASE)

# Authorship states (SPEC §13.7) plus the loader-only state NOT_CHECKED.
NOT_CHECKED = "NOT_CHECKED"

# Reference verifier: arp_cli v1.4.0 or later (Enveloped Pattern only,
# domain binding, v1.3 fields). Inside the repository it sits two levels up.
MIN_ARP_CLI_VERSION = (1, 4, 0)
_MIN_ARP_CLI_TEXT = ".".join(map(str, MIN_ARP_CLI_VERSION))
ARP_CLI_FALLBACK_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "arp_cli.py")
_ARP_CLI_LOCK = threading.Lock()

# Fetch limits (same values as arp_cli v1.4).
MAX_BYTES = 1024 * 1024
TOTAL_TIMEOUT = 30.0
MAX_REDIRECTS = 5
MAX_DEPTH = 64

# Fixed wording of _arp_signature.statement (SPEC §13.3).
SIGNATURE_STATEMENT_TEMPLATE = (
    "Signed with Ed25519 by the operator of {domain}. "
    "Public key: DNS TXT record {selector}._arp.{domain}. "
    "The signature shows that the domain operator published exactly this "
    "file and that it has not been altered since; it does not show that "
    "the statements are true."
)

# Characters never accepted in a fetched URL (controls, space, non-ASCII,
# backslash); "@" in the authority (userinfo) is refused separately.
_UNSAFE_URL_CHAR_RE = re.compile(r"[^\x21-\x7e]|\\")


def _sanitize(text: Any) -> str:
    """Strip HTML tags and script blocks from a value."""
    if not isinstance(text, str):
        return str(text)
    text = _SCRIPT_RE.sub("", text)
    text = _HTML_TAG_RE.sub("", text)
    return text.strip()


def _arp_cli_version_ok(module: Any) -> bool:
    """True if module.__version__ is MIN_ARP_CLI_VERSION or later."""
    try:
        version = tuple(int(part) for part in str(module.__version__).split(".")[:3])
    except (AttributeError, ValueError):
        return False
    return version + (0,) * (3 - len(version)) >= MIN_ARP_CLI_VERSION


def _import_arp_cli():
    """Return the arp_cli module (reference verifier, v1.4.0 or later) or None.

    Tries a normal import first, then the repository layout
    (integrations/langchain/ → ../../arp_cli.py). The file from the
    repository is registered in sys.modules before it runs, as a normal
    import does: the dataclasses in arp_cli look up their module there while
    the class is created. If running the file fails, the entry is removed
    again. An older arp_cli is not used. Both cases are logged as warnings.
    """
    with _ARP_CLI_LOCK:  # no thread may see a module that is still running
        try:
            import arp_cli  # type: ignore
        except Exception:
            arp_cli = None
        # A name already in sys.modules (e.g. set to None to block the
        # import) is left alone.
        if arp_cli is None and "arp_cli" not in sys.modules and os.path.isfile(ARP_CLI_FALLBACK_PATH):
            spec = importlib.util.spec_from_file_location("arp_cli", ARP_CLI_FALLBACK_PATH)
            if spec is None or spec.loader is None:
                return None
            module = importlib.util.module_from_spec(spec)
            sys.modules["arp_cli"] = module
            try:
                spec.loader.exec_module(module)
            except BaseException as e:
                if sys.modules.get("arp_cli") is module:
                    del sys.modules["arp_cli"]
                if not isinstance(e, Exception):
                    raise
                logger.warning(f"arp_cli could not be loaded from {ARP_CLI_FALLBACK_PATH}: "
                               f"{type(e).__name__}: {e}")
                return None
            arp_cli = module
        if arp_cli is None:
            return None
        if not _arp_cli_version_ok(arp_cli):
            logger.warning(f"arp_cli {getattr(arp_cli, '__version__', '(no version)')} from "
                           f"{getattr(arp_cli, '__file__', '?')} is older than {_MIN_ARP_CLI_TEXT} "
                           "and is not used.")
            return None
        return arp_cli


def _depth_exceeds(value: Any, limit: int) -> bool:
    """True if objects/arrays nest deeper than limit (iterative, no recursion)."""
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict):
            children = list(item.values())
        elif isinstance(item, list):
            children = item
        else:
            continue
        if depth > limit:
            return True
        stack.extend((child, depth + 1) for child in children)
    return False


def parse_reasoning_json(raw: bytes) -> Any:
    """Parse reasoning.json bytes as I-JSON (RFC 7493). Raises ValueError.

    Uses arp_cli.parse_manifest_bytes when available (also rejects integers
    outside ±(2^53−1) and unpaired surrogates); otherwise a standalone check
    for duplicate member names, NaN and Infinity. In both cases files nested
    deeper than 64 levels are rejected, also with a ValueError.
    """
    arp_cli = _import_arp_cli()
    if arp_cli is not None and hasattr(arp_cli, "parse_manifest_bytes"):
        try:
            return arp_cli.parse_manifest_bytes(raw)
        except RecursionError:  # older arp_cli without a depth limit
            raise ValueError(f"JSON nested deeper than {MAX_DEPTH} levels (not accepted)")

    def object_pairs(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError(f"duplicate member name {key!r} (I-JSON, RFC 7493 §2.3)")
            obj[key] = value
        return obj

    def reject_constant(name):
        raise ValueError(f"{name} is not a JSON number")

    try:
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=object_pairs,
                          parse_constant=reject_constant)
    except RecursionError:
        raise ValueError(f"JSON nested deeper than {MAX_DEPTH} levels (not accepted)")
    if _depth_exceeds(data, MAX_DEPTH):
        raise ValueError(f"JSON nested deeper than {MAX_DEPTH} levels (not accepted)")
    return data


def _call_with_deadline(work: Callable[[Dict[str, Any]], bytes], seconds: float, url: str) -> bytes:
    """Run work(state) in a daemon thread and return its result within seconds.

    requests applies its timeout to each socket operation, not to the whole
    request: a server that sends its headers one byte at a time could keep a
    fetch open indefinitely. On timeout ValueError is raised, state["cancelled"]
    is set and the response registered in state["close"] is closed; the
    thread stops at its next read or socket timeout.
    """
    state: Dict[str, Any] = {"cancelled": False, "close": None}
    outcome: Dict[str, Any] = {}

    def runner() -> None:
        try:
            outcome["value"] = work(state)
        except BaseException as e:  # passed on to the caller below
            outcome["error"] = e

    thread = threading.Thread(target=runner, name="arp-loader-fetch", daemon=True)
    thread.start()
    thread.join(max(0.0, seconds))
    if thread.is_alive():
        state["cancelled"] = True
        close = state.get("close")
        if close is not None:
            try:
                close()
            except Exception:
                pass
        raise ValueError(f"Fetching {url} took longer than {seconds:.0f} s.")
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]


def _checked_url(url: str) -> str:
    """Return url rebuilt from its parsed parts, or raise ValueError.

    Checking and fetching then see the same host (no userinfo, backslash,
    controls or non-ASCII; http or https only).
    """
    if not isinstance(url, str) or _UNSAFE_URL_CHAR_RE.search(url):
        raise ValueError("URL contains characters that are not allowed")
    parts = urlparse(url)
    if parts.scheme not in ("https", "http") or "@" in parts.netloc or not parts.hostname:
        raise ValueError("URL must be http(s) with a host and without userinfo")
    port = parts.port  # raises ValueError for an invalid port
    host = parts.hostname.lower().rstrip(".")
    netloc = host + (f":{port}" if port is not None else "")
    return f"{parts.scheme}://{netloc}{parts.path or '/'}" + (f"?{parts.query}" if parts.query else "")


def provenance_line(domain: str, status: str, reason: str = "", checked_on: str = "",
                    expires_at: str = "") -> str:
    """Neutral provenance line for loader output (SPEC v1.3 §13.10).

    Plain text, third person, no imperatives, no tags imitating system markup.
    """
    base = f"Source: {domain} — self-description (ARP)."
    if status == "CRYPTOGRAPHIC":
        return (f"{base} Authorship verified via Ed25519/DNS on {checked_on}; "
                "this verifies the publisher, not the truth of the content.")
    if status == "UNSIGNED" and reason == "expired":
        when = f" on {expires_at[:10]}" if expires_at else ""
        return f"{base} Signature expired{when}; the publisher is not currently verified."
    if status == "UNSIGNED":
        return f"{base} Not signed; the publisher is not cryptographically verified."
    if status == "INVALID":
        return f"{base} Signature check failed ({reason or 'invalid'}); the publisher is not verified."
    if status == "ERROR":
        return f"{base} Signature could not be checked ({reason or 'error'}); the publisher is not verified."
    return f"{base} Signature present, not checked by this loader; the publisher is not verified."


class AgenticReasoningLoader(BaseLoader):
    """
    Load and parse a reasoning.json file from any website.

    The loader fetches /.well-known/reasoning.json and converts it
    into LangChain Documents for RAG retrieval.

    Each section of the reasoning file becomes a separate Document with
    metadata (including the authorship state). Every Document starts with
    the neutral provenance line of SPEC §13.10.

    Args:
        url: Base URL of the website (e.g., "https://example.com")
        path: Custom path to reasoning.json (default: "/.well-known/reasoning.json")
        timeout: HTTP request timeout in seconds (default: 10)
        headers: Optional custom HTTP headers
        verify_signature: Check the Ed25519 signature via arp_cli (default: True).
            Without arp_cli the state is NOT_CHECKED.
        check_representation: Fetch the representations (reasoning.md) and
            compare their sha256 (default: False).
        resolver: Optional DNS TXT resolver (name -> list of strings), passed
            to arp_cli; mainly for tests.
    """

    def __init__(
        self,
        url: str,
        path: str = "/.well-known/reasoning.json",
        timeout: int = 10,
        headers: Optional[Dict[str, str]] = None,
        verify_signature: bool = True,
        check_representation: bool = False,
        resolver: Optional[Callable[[str], List[str]]] = None,
    ):
        if requests is None:
            raise ImportError(
                "The 'requests' package is required. Install it with: pip install requests"
            )

        self.url = url.rstrip("/")
        self.path = path
        self.timeout = timeout
        self.verify_signature = verify_signature
        self.check_representation = check_representation
        self.resolver = resolver
        self._trust_metadata: Dict[str, Any] = {}
        self._source_line = ""
        self.headers = headers or {
            "User-Agent": f"AgenticReasoningLoader/{LOADER_VERSION} (LangChain; +https://arp-protocol.org)",
            "Accept": "application/json",
        }

    @property
    def full_url(self) -> str:
        return urljoin(self.url + "/", self.path.lstrip("/"))

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _get_bytes(self, url: str) -> bytes:
        """GET url: at most MAX_BYTES, TOTAL_TIMEOUT seconds overall (also
        while the headers arrive), redirects only within the same host and
        never from https to http."""
        current = _checked_url(url)
        deadline = time.monotonic() + TOTAL_TIMEOUT
        return _call_with_deadline(lambda state: self._get_bytes_worker(url, current, deadline, state),
                                   TOTAL_TIMEOUT, url)

    def _get_bytes_worker(self, url: str, current: str, deadline: float, state: Dict[str, Any]) -> bytes:
        """The fetch loop of _get_bytes (runs in the worker thread)."""
        host = urlparse(current).hostname
        headers = dict(self.headers)
        headers.setdefault("Accept-Encoding", "identity")  # size limit applies to the bytes sent
        for _ in range(MAX_REDIRECTS + 1):
            if time.monotonic() > deadline or state["cancelled"]:
                raise ValueError(f"Fetching {url} took longer than {TOTAL_TIMEOUT:.0f} s.")
            response = requests.get(current, headers=headers, timeout=self.timeout,
                                    stream=True, allow_redirects=False)
            state["close"] = response.close
            try:
                if response.status_code in (301, 302, 303, 307, 308):
                    target = _checked_url(urljoin(current, response.headers.get("Location", "")))
                    if urlparse(target).hostname != host:
                        raise ValueError(f"Redirect from {current} to another host is not followed.")
                    if current.startswith("https://") and not target.startswith("https://"):
                        raise ValueError(f"Redirect from {current} to http is not followed.")
                    current = target
                    continue
                response.raise_for_status()
                body = bytearray()
                raw = getattr(response, "raw", None)
                if raw is not None and hasattr(raw, "read1"):
                    # urllib3 >= 2: one network read per piece, so the deadline
                    # also holds against servers that send one byte at a time.
                    pieces = iter(lambda: raw.read1(65536, decode_content=True), b"")
                else:
                    pieces = response.iter_content(65536)
                for chunk in pieces:
                    body.extend(chunk)
                    if len(body) > MAX_BYTES:
                        raise ValueError(f"Response from {current} is larger than {MAX_BYTES} bytes.")
                    if time.monotonic() > deadline or state["cancelled"]:
                        raise ValueError(f"Fetching {current} took longer than {TOTAL_TIMEOUT:.0f} s.")
                return bytes(body)
            finally:
                state["close"] = None
                response.close()
        raise ValueError(f"Too many redirects for {url}.")

    def _fetch(self) -> Dict[str, Any]:
        """Fetch and parse the reasoning.json file."""
        full_url = self.full_url
        logger.info(f"Fetching reasoning.json from {full_url}")

        raw = self._get_bytes(full_url)

        # Gracefully handle SPA catch-all routers returning HTML as 200 OK.
        # Duplicate member names, NaN and Infinity are rejected (I-JSON).
        try:
            data = parse_reasoning_json(raw)
        except RecursionError:
            raise ValueError(f"reasoning.json at {full_url} is rejected: JSON nested too deeply.")
        except ValueError as e:
            if getattr(e, "reason", None) in ("duplicate_member", "non_ijson") \
                    or "duplicate member" in str(e) or "not a JSON number" in str(e):
                raise ValueError(
                    f"reasoning.json at {full_url} is rejected: {e}. "
                    "It is JSON, but not I-JSON (RFC 7493)."
                )
            raise ValueError(
                f"Failed to parse JSON from {full_url}. "
                "The endpoint returned an invalid format "
                "(possibly an HTML page from an SPA catch-all router)."
            )

        if not isinstance(data, dict):
            raise ValueError(
                f"Invalid reasoning.json format at {full_url}. "
                "Expected a JSON object."
            )

        # Authorship state and v1.3 fields for downstream use
        self._extract_trust_metadata(data)

        logger.info(f"Successfully loaded reasoning.json for entity: {data.get('entity', 'unknown')}")
        return data

    def _check_authorship(self, data: Dict[str, Any], domain: str) -> Dict[str, str]:
        sig = data.get("_arp_signature")
        if not sig:
            return {"status": "UNSIGNED", "reason": "unsigned"}
        if not self.verify_signature:
            return {"status": NOT_CHECKED, "reason": "verification_disabled"}
        arp_cli = _import_arp_cli()
        if arp_cli is None:
            logger.warning(f"Signature of {domain} not checked: arp_cli.py (v{_MIN_ARP_CLI_TEXT} or later) "
                           "is not available; authorship_status is NOT_CHECKED.")
            return {"status": NOT_CHECKED, "reason": "arp_cli_unavailable"}
        try:
            result = arp_cli.verify_manifest(data, domain=domain, resolver=self.resolver, now=self._now())
        except Exception as e:  # missing optional dependency, unexpected input
            logger.warning(f"Signature check not possible: {e}")
            return {"status": NOT_CHECKED, "reason": "verifier_error"}
        # dns_name: the key record that was queried, built from the retrieval
        # domain and dns_selector; dns_record in the file is informational
        # only (SPEC §13.3).
        return {"status": result["status"], "reason": result["reason"] or "",
                "dns_name": result.get("dns_name") or ""}

    def _check_representation(self, data: Dict[str, Any], domain: str) -> str:
        arp_cli = _import_arp_cli()
        if arp_cli is None:
            return "REPRESENTATION_UNCHECKED"

        # check_representations only passes plain https URLs on the retrieval
        # domain to fetch; _get_bytes adds the size and redirect limits.
        results = arp_cli.check_representations(data, retrieval_domain=domain, fetch=self._get_bytes)
        md = [r for r in results if str(r.get("href", "")).endswith("/reasoning.md")] or results
        return md[0]["status"] if md else "none"

    def _extract_trust_metadata(self, data: Dict[str, Any]) -> None:
        """Authorship state, signature fields and v1.3 provenance as flat metadata."""
        domain = (urlparse(self.full_url).hostname or "").lower().rstrip(".")
        sig = data.get("_arp_signature") if isinstance(data.get("_arp_signature"), dict) else {}
        verify = sig.get("verify") if isinstance(sig.get("verify"), dict) else {}
        prov = data.get("provenance") if isinstance(data.get("provenance"), dict) else {}
        reps = data.get("representations") if isinstance(data.get("representations"), list) else []
        md_rep = next((r for r in reps if isinstance(r, dict)
                       and str(r.get("href", "")).endswith("/reasoning.md")), {})

        check = self._check_authorship(data, domain)
        checked_on = self._now().date().isoformat()
        # The statement and the key pointers are passed on only for a valid
        # signature, and the statement only in its fixed wording (SPEC §13.3):
        # templates that read metadata alone must not show a signature
        # statement for a file whose check failed.
        cryptographic = check["status"] == "CRYPTOGRAPHIC"
        statement = sig.get("statement")
        selector = sig.get("dns_selector") or "arp"
        if not cryptographic or statement != SIGNATURE_STATEMENT_TEMPLATE.format(domain=domain, selector=selector):
            statement = "none"
        self._source_line = provenance_line(domain, check["status"], check["reason"], checked_on,
                                            str(sig.get("expires_at", "")))

        self._trust_metadata = {
            # Presence of a signature block only (unchanged meaning since v1.1)
            "is_signed": bool(sig and sig.get("signature")),
            "authorship_status": check["status"],
            "authorship_reason": check["reason"],
            "authorship_checked_on": checked_on,
            "source_line": self._source_line,
            "signature_algorithm": sig.get("algorithm", "none"),
            "signature_dns": (check.get("dns_name") or "none") if cryptographic else "none",
            "signature_doh_url": verify.get("doh_url", "none") if cryptographic else "none",
            "signature_statement": statement,
            "signed_at": sig.get("signed_at", "none"),
            "expires_at": sig.get("expires_at", "none"),
            "provenance_statement": prov.get("statement", "none"),
            "publisher": prov.get("publisher", "none"),
            "publisher_url": prov.get("publisher_url", "none"),
            "published": prov.get("published", "none"),
            "representation_url": md_rep.get("href", "none"),
            "representation_sha256": md_rep.get("sha256", "none"),
        }
        # Metadata stays flat even if the file puts objects where strings belong.
        self._trust_metadata = {k: v if isinstance(v, (str, int, float, bool)) else _sanitize(json.dumps(v))
                                for k, v in self._trust_metadata.items()}
        if self.check_representation:
            self._trust_metadata["representation_status"] = (
                self._check_representation(data, domain) if md_rep else "none")

    @staticmethod
    def _claims(data: Dict[str, Any]) -> Dict[str, Any]:
        """entity_claims (v1.1+). The v1.0 container reasoning_directives carries
        an instruction-style name (SPEC §11.2) and is not used as a fallback."""
        claims = data.get("entity_claims")
        return claims if isinstance(claims, dict) else {}

    def _with_source_line(self, parts: List[str]) -> str:
        return "\n".join([self._source_line, ""] + parts)

    def _base_metadata(self, data: Dict[str, Any], section: str) -> Dict[str, Any]:
        return {
            "source": self.url,
            "entity": data.get("entity", "Unknown"),
            "section": section,
            "protocol": "ARP",
            "version": data.get("version", "unknown"),
            **self._trust_metadata,
        }

    def _build_system_document(self, data: Dict[str, Any]) -> Document:
        """Build the identity document (self-description and positioning)."""
        entity = data.get("entity", "Unknown Entity")
        identity = data.get("identity", {})

        parts = [f"# Self-description of {entity} (ARP)", ""]

        provenance = data.get("provenance")
        if isinstance(provenance, dict) and provenance.get("statement"):
            parts.append(_sanitize(provenance["statement"]))
            parts.append("")

        # Identity
        if identity:
            parts.append("## Identity")
            if "elevator_pitch" in identity:
                parts.append(f"**Summary:** {_sanitize(identity['elevator_pitch'])}")
            if "tagline" in identity:
                parts.append(f"**Tagline:** {_sanitize(identity['tagline'])}")
            for key, label in (("founded", "Founded"), ("headquarters", "Headquarters"),
                               ("industry", "Industry"), ("legal_entity", "Legal entity")):
                if key in identity:
                    parts.append(f"**{label}:** {_sanitize(identity[key])}")
            if "core_competencies" in identity:
                comps = [_sanitize(c) for c in identity["core_competencies"]]
                parts.append(f"**Core Competencies:** {', '.join(comps)}")
            if "emotional_resonance" in identity:
                er = identity["emotional_resonance"]
                if "tone_of_voice" in er:
                    parts.append(f"**Tone of Voice:** {_sanitize(er['tone_of_voice'])}")
                if "vibe_tags" in er:
                    tags = [_sanitize(t) for t in er["vibe_tags"]]
                    parts.append(f"**Vibe Tags:** {', '.join(tags)}")
            for other in identity.get("not_to_be_confused_with", []) or []:
                if isinstance(other, dict) and other.get("name"):
                    line = f"**Not to be confused with:** {_sanitize(other['name'])}"
                    if other.get("reason"):
                        line += f" — {_sanitize(other['reason'])}"
                    parts.append(line)
            parts.append("")

        # Framing context (v1.1+). The v1.0 container reasoning_directives is not read.
        claims = self._claims(data)
        framing = claims.get("framing_context")
        if framing:
            parts.append(f"## Positioning as described by {entity}")
            parts.append(_sanitize(framing))
            parts.append("")

        return Document(page_content=self._with_source_line(parts),
                        metadata=self._base_metadata(data, "identity"))

    def _build_organization_document(self, data: Dict[str, Any]) -> Optional[Document]:
        """Build a document from the v1.3 organization object (legal facts)."""
        org = data.get("organization")
        if not isinstance(org, dict) or not org:
            return None
        entity = data.get("entity", "Unknown")
        parts = [f"# Organization data published by {entity}", ""]

        def flatten(prefix: str, value: Any) -> None:
            if isinstance(value, dict):
                for k, v in value.items():
                    if not str(k).startswith("@"):  # schema.org @type is not content
                        flatten(f"{prefix}.{k}" if prefix else str(k), v)
            elif isinstance(value, list):
                parts.append(f"- {prefix}: {', '.join(_sanitize(v) for v in value)}")
            else:
                parts.append(f"- {prefix}: {_sanitize(value)}")

        flatten("", org)
        return Document(page_content=self._with_source_line(parts),
                        metadata=self._base_metadata(data, "organization"))

    def _build_corrections_documents(self, data: Dict[str, Any]) -> List[Document]:
        """Build documents from topic-anchored corrections."""
        docs = []
        corrections = data.get("corrections", {})
        hallucinations = corrections.get("common_hallucinations", [])

        if not hallucinations:
            return docs

        entity = data.get("entity", "Unknown")
        parts = [f"# Corrections published by {entity} about itself", ""]
        parts.append(
            f"The following statements are corrections that '{entity}' publishes about itself; "
            "evidence links are listed where the file provides them."
        )
        parts.append("")

        for i, h in enumerate(hallucinations, 1):
            # v1.1 keys with v1.0 fallback
            topic = h.get("trigger_topic", h.get("false_claim", ""))
            fact = h.get("verified_fact", h.get("correction_fact", ""))

            parts.append(f"### Correction {i}")
            parts.append(f"**Topic:** {_sanitize(topic)}")
            parts.append(f"**Statement by {entity}:** {_sanitize(fact)}")
            if "evidence_url" in h:
                parts.append(f"**Evidence:** {h['evidence_url']}")
            parts.append("")

        metadata = self._base_metadata(data, "corrections")
        metadata.update(correction_count=len(hallucinations),
                        last_verified=corrections.get("last_verified", "unknown"))
        docs.append(Document(page_content=self._with_source_line(parts), metadata=metadata))
        return docs

    def _build_counterfactual_documents(self, data: Dict[str, Any]) -> List[Document]:
        """Build documents from domain expertise (v1.0/v1.1 counterfactual keys as fallback)."""
        docs = []
        claims = self._claims(data)
        simulations = claims.get(
            "domain_expertise",
            claims.get("counterfactual_simulations",
                       claims.get("counterfactual_logic", []))
        )

        if not simulations:
            return docs

        entity = data.get("entity", "Unknown")
        parts = [f"# Domain knowledge stated by {entity}", ""]
        parts.append(f"The following statements give the perspective of '{entity}' on its field.")
        parts.append("")

        for i, sim in enumerate(simulations, 1):
            scenario = sim.get("scenario", sim.get("trigger_scenario", sim.get("if_scenario", "")))
            context = sim.get("context", sim.get("if_condition", ""))
            perspective = sim.get("entity_perspective", sim.get("simulated_outcome", ""))
            conclusion = sim.get("logical_conclusion", "")

            parts.append(f"### Scenario {i}: {_sanitize(scenario)}")
            if context:
                parts.append(f"**Context:** {_sanitize(context)}")
            if perspective:
                parts.append(f"**Perspective of {entity}:** {_sanitize(perspective)}")
            if conclusion:
                parts.append(f"**Conclusion stated by {entity}:** {_sanitize(conclusion)}")
            if "confidence" in sim:
                parts.append(f"**Confidence stated by {entity}:** {sim['confidence']}")
            parts.append("")

        metadata = self._base_metadata(data, "domain_expertise")
        metadata["scenario_count"] = len(simulations)
        docs.append(Document(page_content=self._with_source_line(parts), metadata=metadata))
        return docs

    def _build_recommendation_document(self, data: Dict[str, Any]) -> Optional[Document]:
        """Build document from recommendation context (described fit)."""
        claims = self._claims(data)
        rec = claims.get("recommendation_context", claims.get("recommendation_boundaries", {}))

        if not rec:
            return None

        entity = data.get("entity", "Unknown")
        parts = [f"# Fit as described by {entity}", ""]

        # v1.1 keys with v1.0 fallback
        fit = rec.get("recommended_when", rec.get("recommend_when", rec.get("recommend_for", [])))
        no_fit = rec.get("not_recommended_when", rec.get("do_not_recommend_when", rec.get("do_not_recommend_for", [])))

        if fit:
            parts.append(f"## Typical fit according to {entity}")
            for r in fit:
                parts.append(f"- {_sanitize(r)}")
            parts.append("")

        if no_fit:
            parts.append(f"## Not a fit according to {entity}")
            for r in no_fit:
                parts.append(f"- {_sanitize(r)}")
            parts.append("")

        position = rec.get("market_position", rec.get("competitive_positioning"))
        if position:
            parts.append(f"**Market position as described by {entity}:** {_sanitize(position)}")

        return Document(page_content=self._with_source_line(parts),
                        metadata=self._base_metadata(data, "recommendations"))

    def _build_dichotomy_document(self, data: Dict[str, Any]) -> Optional[Document]:
        """Build document from market positioning / strategic dichotomies."""
        claims = self._claims(data)
        dichotomies = claims.get("market_positioning", claims.get("strategic_dichotomies", {}))

        if not dichotomies:
            return None

        entity = data.get("entity", "Unknown")
        parts = [f"# Market positioning stated by {entity}", ""]
        parts.append(
            f"The following positioning statements are published by '{entity}' "
            "about how it views its market category."
        )
        parts.append("")

        for key, value in dichotomies.items():
            label = key.replace("vs_", "vs. ").replace("_", " ").title()
            parts.append(f"### {label}")
            parts.append(_sanitize(value))
            parts.append("")

        return Document(page_content=self._with_source_line(parts),
                        metadata=self._base_metadata(data, "market_positioning"))

    # ─── Lazy Load (Modern LangChain v0.1+) ─────────────────────────

    def lazy_load(self) -> Iterator[Document]:
        """
        Lazily yield documents one by one.

        This is the recommended standard for LangChain v0.1+.
        The base class automatically provides load() via list(self.lazy_load()).

        The authorship state (authorship_status, signature_dns, signed_at)
        and the v1.3 provenance fields are in every Document's metadata;
        every page_content starts with the provenance line.

        Documents are yielded in this order:
        1. Corrections
        2. Identity (self-description, positioning)
        3. Organization (v1.3)
        4. Described fit (recommendation context)
        5. Domain expertise
        6. Market positioning
        The diagnostics object is never passed on (SPEC §12).
        """
        data = self._fetch()

        # 1. Corrections
        yield from self._build_corrections_documents(data)

        # 2. Identity
        yield self._build_system_document(data)

        # 3. Organization
        org_doc = self._build_organization_document(data)
        if org_doc:
            yield org_doc

        # 4. Described fit
        rec_doc = self._build_recommendation_document(data)
        if rec_doc:
            yield rec_doc

        # 5. Domain expertise
        yield from self._build_counterfactual_documents(data)

        # 6. Market positioning
        dich_doc = self._build_dichotomy_document(data)
        if dich_doc:
            yield dich_doc

    def load(self) -> List[Document]:
        """
        Load the reasoning.json and return as LangChain Documents.

        Convenience wrapper around lazy_load() for backwards compatibility.
        """
        docs = list(self.lazy_load())
        logger.info(f"Loaded {len(docs)} documents from reasoning.json for {docs[0].metadata.get('entity', 'unknown') if docs else 'unknown'}")
        return docs


# --- Standalone usage (without LangChain) ---

def load_reasoning(url: str, path: str = "/.well-known/reasoning.json") -> List[Document]:
    """
    Convenience function for loading reasoning.json without LangChain.

    Args:
        url: Base URL of the website
        path: Custom path (default: /.well-known/reasoning.json)

    Returns:
        List of Document objects with page_content and metadata
    """
    loader = AgenticReasoningLoader(url, path=path)
    return loader.load()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python arp_loader.py <url>")
        print("Example: python arp_loader.py https://example.com")
        sys.exit(1)

    target_url = sys.argv[1]
    print(f"\n🧠 Loading reasoning.json from {target_url}...\n")

    try:
        docs = load_reasoning(target_url)
        if docs:
            print(docs[0].metadata.get("source_line", ""))
            print()
        for doc in docs:
            section = doc.metadata.get("section", "unknown").upper()
            status = doc.metadata.get("authorship_status", "?")
            print(f"━━━ [{section}] {status} ━━━")
            print(doc.page_content[:500])
            print()
        print(f"✅ Loaded {len(docs)} documents.")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
