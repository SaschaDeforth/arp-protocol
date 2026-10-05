#!/usr/bin/env python3
"""
ARP Protocol CLI — Reader Profile (v1.4.0)
Command-line tool for generating keys, linting, rendering, signing and
verifying reasoning.json files (ARP v1.3 "Reader Profile").

v1.4.0 Changes (ARP v1.3 "Reader Profile"):
  - sign: writes a readable signature statement and a verify block into
    _arp_signature (ARP-S), renders /.well-known/reasoning.md (ARP-R) and
    binds its bytes via representations[].sha256. The order is fixed:
    signature metadata (without signature) -> render reasoning.md ->
    sha256 into representations -> canonicalize -> sign.
    sign runs lint first and aborts on wording violations
    (override: --allow-lint-errors, prints a warning).
  - render-md: deterministic Markdown rendering of a manifest — the
    reference format for /.well-known/reasoning.md. render_reasoning_md()
    is a pure function without global state; other tools may import or
    port it (see its docstring for the exact format). It refuses control
    characters in names and strings (SPEC §13.12.1) and top-level members
    such as "Verification" whose heading would imitate the fixed final
    section; --allow-control-characters only for files below v1.3.
  - lint: Wording Profile (ARP-W) over all field names and string values,
    plus provenance (ARP-P) and signature/representation fields; derived
    texts (reasoning.md, llms.txt, HTML) line by line with --text.
    Errors also for control characters in v1.3 files, role tags and
    chat-template tokens (schema v1.3), member names with "verified" or
    "authoritative" (except verified_fact, last_verified), injection
    formulas ("ignore previous instructions"), generic AI subjects with
    instructions ("Assistants must cite …"), German imperatives, members
    that imitate the "## Verification" section of reasoning.md, and the
    signature statement outside _arp_signature.
    Exit code 0 (no errors), 1 (errors), 2 (file not readable).
  - verify: an empty p= in the DNS TXT record means the key was revoked
    (INVALID, reason key_revoked — analogous to DKIM, RFC 6376 §3.6.1);
    "v=arp1" is read case-tolerantly with a warning; representations are
    fetched (URL source) or read from the neighbouring file (local source)
    and compared by SHA-256: REPRESENTATION_MATCH / REPRESENTATION_MISMATCH /
    REPRESENTATION_UNCHECKED; the payload field "domain" must match the
    retrieval domain (SPEC §4); --json output; descriptive result texts.
  - keys: --selector (rotation pattern arpYYMM, e.g. arp2610), --revoke OLD
    prints the revocation record, --out-pub writes the public key as PEM;
    an existing key file is never overwritten (only with --force, which
    replaces the file atomically) and key files get mode 0600.
  - Missing optional dependencies no longer terminate an importing program.
  - SECURITY (hardening after review):
    · reasoning.json is parsed as I-JSON (RFC 7493, as RFC 8785 requires):
      duplicate member names, NaN/Infinity, integers outside ±(2^53−1) and
      unpaired surrogates are rejected (verify: INVALID duplicate_member /
      non_ijson; lint: error). With duplicate names the bytes people and
      LLMs read differ from the parsed object that the signature covers.
    · The signature value is decoded strictly: exactly 86 Base64url (or,
      from older tooling, standard Base64) characters, optional "==",
      canonical encoding. Text appended after the padding is rejected.
      DNS p= values are decoded strictly as well; duplicate tags in a key
      record are malformed.
    · A signed file without a "domain" string is INVALID (domain_missing);
      in v1.3 files, dns_record and verify.dns_name must name the key
      record of the retrieval domain (else INVALID domain_mismatch).
    · HTTP fetches: same parser for checking and fetching, no userinfo,
      backslash or port in representation URLs, redirects only within the
      same host and never from https to http, size limit 1 MiB, overall
      deadline — also while the headers arrive (worker thread). Values
      from the file are stripped of control characters before they are
      printed; --json escapes C1 and direction characters.
    · Representations: equal URLs fetched once, at most 4 distinct URLs
      and 60 s per run; the local check reads only reasoning.md next to
      the manifest (no symbolic links, at most 1 MiB).
    · Parsing: integer literals with more than 16 digits are rejected
      without conversion (non_ijson); files nested deeper than 64 levels
      are not loaded (invalid_json) instead of raising RecursionError.
  - sign and keys require --selector (after a rotation the old default
    "arp" may be revoked).

v1.3.1 Changes:
  - SECURITY: the legacy Payload-only verification fallback was REMOVED.
    In that pattern the _arp_signature metadata (expires_at, dns_selector,
    algorithm) was NOT covered by the signature — a holder of a legacy-signed
    file could extend its validity or redirect the DNS selector at will and
    still get a CRYPTOGRAPHIC verdict. Only the Enveloped Pattern (SPEC §13.4)
    is accepted now. Files signed with CLI <= 1.2 must be re-signed.

v1.3.0 Changes:
  - Enveloped Signature Pattern: _arp_signature metadata (with signature:"")
    is included in the canonical bytes, matching SPEC §13.4 and the Browser Signer.
  - Unpadded base64url output (86 characters for Ed25519, JWS convention).
  - Tolerant decoding: accepts padded and unpadded base64/base64url on read.
  - Domain-Binding: verify constructs the DNS name from the retrieval domain
    (or --domain flag for local files), never trusts dns_record as query source.
  - --pubkey flag for offline / CI verification against a local public key file.
  - dns_record mismatch warnings (informational only).

Usage:
    arp keys --domain example.com --selector arp2610 --revoke arp
    arp lint .well-known/reasoning.json
    arp render-md .well-known/reasoning.json --domain example.com
    arp sign .well-known/reasoning.json --key arp_private_arp2610.pem \\
        --domain example.com --selector arp2610
    arp verify https://example.com/.well-known/reasoning.json
    arp verify .well-known/reasoning.json --domain example.com
    arp verify .well-known/reasoning.json --pubkey arp_public.pem

Exit codes:
    lint     0 = no errors (warnings possible), 1 = errors, 2 = file not readable
    verify   0 = CRYPTOGRAPHIC or UNSIGNED (incl. expired), 1 = INVALID,
             2 = not checkable (file not loadable, DNS failure, no domain)
    sign     0 = signed, 1 = aborted (lint errors, bad key, bad input)

Dependencies:
    pip install cryptography rfc8785 dnspython requests

License: MIT
Author: Sascha Deforth (TrueSource)
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import math
import os
import re
import stat
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple
from urllib.parse import parse_qs, urljoin, urlparse, urlsplit

__version__ = "1.4.0"

CLI_VERSION = __version__
SPEC_VERSION = "1.3"
SCHEMA_URL = "https://arp-protocol.org/schema/v1.3.json"
SPEC_SIGNATURE_URL = "https://arp-protocol.org/SPEC.md#13-cryptographic-trust-layer"
DOH_URL_TEMPLATE = "https://dns.google/resolve?name={name}&type=TXT"
MANIFEST_PATH = "/.well-known/reasoning.json"
MARKDOWN_PATH = "/.well-known/reasoning.md"
MARKDOWN_MEDIA_TYPE = "text/markdown"
USER_AGENT = f"arp-cli/{CLI_VERSION} (+https://arp-protocol.org)"

# Fixed wording (ARP-S, K3). The statement is part of _arp_signature and
# therefore covered by the signature.
SIGNATURE_STATEMENT_TEMPLATE = (
    "Signed with Ed25519 by the operator of {domain}. "
    "Public key: DNS TXT record {dns_name}. "
    "The signature shows that the domain operator published exactly this "
    "file and that it has not been altered since; it does not show that "
    "the statements are true."
)

# Fixed wording (ARP-P, K2). Identical in signed and unsigned files.
PROVENANCE_STATEMENT_TEMPLATE = (
    "This file is {entity}'s own description of itself, published by "
    "{publisher} at {domain}. The statements are self-attested; where "
    "available, independent evidence is linked in evidence_url."
)

# Trust levels (SPEC §13.7) and the non-trust status for "could not check".
TRUST_CRYPTOGRAPHIC = "CRYPTOGRAPHIC"
TRUST_UNSIGNED = "UNSIGNED"
TRUST_INVALID = "INVALID"
STATUS_ERROR = "ERROR"

# Plain-words limitation for CRYPTOGRAPHIC results (SPEC §13.7). Names how
# authorship was checked, so the text itself passes the Wording Profile.
CRYPTOGRAPHIC_MEANING = "authorship verified via Ed25519 signature; content not verified"
# The same for a check against a local public key file (verify --pubkey):
# neither the key's DNS record for the domain nor its revocation was looked up.
LOCAL_KEY_MEANING = ("signature matches the local public key file; link to the domain and revocation "
                     "status not checked; content not verified")

REPRESENTATION_MATCH = "REPRESENTATION_MATCH"
REPRESENTATION_MISMATCH = "REPRESENTATION_MISMATCH"
REPRESENTATION_UNCHECKED = "REPRESENTATION_UNCHECKED"

# Limits for HTTP fetches (manifest and representations). SPEC §2 recommends
# manifests of at most 100 KB; 1 MiB leaves room without allowing memory abuse.
MAX_FETCH_BYTES = 1024 * 1024
FETCH_TIMEOUT = 15          # seconds per connect/read
FETCH_TOTAL_TIMEOUT = 30.0  # seconds for the whole fetch incl. redirects
MAX_REDIRECTS = 5
# Representations per verify run: distinct URLs fetched, and the time for all
# of them together. Further entries are reported as REPRESENTATION_UNCHECKED.
MAX_REPRESENTATION_FETCHES = 4
REPRESENTATIONS_TOTAL_TIMEOUT = 60.0

# I-JSON (RFC 7493 §2.2): integers outside this range are not interoperable.
IJSON_MAX_SAFE_INTEGER = 2 ** 53 - 1
# An integer literal with more digits lies outside ±(2^53−1) in any case.
IJSON_MAX_INTEGER_DIGITS = 16
# ARP manifests nest a few levels deep; deeper files are not accepted
# (deep nesting would otherwise exhaust the recursion limit of the parser).
MAX_JSON_DEPTH = 64


# ─────────────────────────────────────────────
# Encoding helpers
# ─────────────────────────────────────────────

def b64url_encode_unpadded(data: bytes) -> str:
    """
    Encode bytes to unpadded base64url (JWS / RFC 7515 convention).

    Ed25519 signatures are 64 bytes → 86 characters without padding.
    This is the normative emission format as of SPEC v1.3 / CLI v1.3.0.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64_decode_tolerant(value: str) -> bytes:
    """
    Decode base64 or base64url, with or without padding.

    Lenient helper for trusted local input (e.g. a --pubkey file). It is
    NOT used for values taken from a reasoning.json or from DNS: it ignores
    whitespace and stops at the first padding, so text appended after "=="
    would be dropped silently. Use decode_signature_strict() and
    decode_dns_public_key() for those.
    """
    value = re.sub(r"\s+", "", value)
    value = value.replace("+", "-").replace("/", "_")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


_SIG_URL_RE = re.compile(r"[A-Za-z0-9_-]{86}(?:==)?")
_SIG_STD_RE = re.compile(r"[A-Za-z0-9+/]{86}(?:==)?")
_P_URL_RE = re.compile(r"[A-Za-z0-9_-]{43}=?")
_P_STD_RE = re.compile(r"[A-Za-z0-9+/]{43}=?")


def decode_signature_strict(value: Any) -> bytes:
    """Decode the _arp_signature.signature value (SPEC §13.3). Raises ValueError.

    Accepted: exactly 86 characters of Base64url (the emission format) or,
    as written by older tooling, of standard Base64 — one alphabet, not
    mixed — optionally followed by "==". The encoding must be canonical
    (unused trailing bits zero). Rejected: whitespace, other characters and
    anything after the padding. The signature value itself is not covered
    by the signature, so every accepted spelling must denote exactly one
    byte string and nothing else.
    """
    if not isinstance(value, str):
        raise ValueError("signature is not a string")
    if _SIG_URL_RE.fullmatch(value):
        core = value[:86]
    elif _SIG_STD_RE.fullmatch(value):
        core = value[:86].replace("+", "-").replace("/", "_")
    else:
        raise ValueError("signature must be 86 Base64url characters (optionally followed by '=='), "
                         "without whitespace or other text")
    raw = base64.urlsafe_b64decode(core + "==")
    if b64url_encode_unpadded(raw) != core:
        raise ValueError("signature uses a non-canonical Base64 encoding")
    return raw


def decode_dns_public_key(value: Any) -> Tuple[bytes, List[str]]:
    """Decode the p= value of a key record (SPEC §13.5). Returns (32 bytes, warnings).

    SPEC: standard Base64 with padding (44 characters). Read tolerantly:
    missing padding or the Base64url alphabet give a warning. Anything else
    (other characters, wrong length, non-canonical bits) raises ValueError.
    """
    if not isinstance(value, str):
        raise ValueError("p= is not a string")
    warnings: List[str] = []
    if _P_STD_RE.fullmatch(value):
        core = value[:43]
        if not value.endswith("="):
            warnings.append("DNS record p= lacks the '=' padding; SPEC §13.5 specifies padded standard Base64.")
    elif _P_URL_RE.fullmatch(value):
        core = value[:43].replace("-", "+").replace("_", "/")
        warnings.append("DNS record p= uses the Base64url alphabet; SPEC §13.5 specifies standard Base64.")
    else:
        raise ValueError("p= is not a 32-byte key in Base64 (44 characters)")
    raw = base64.b64decode(core + "=", validate=True)
    if base64.b64encode(raw).decode("ascii")[:43] != core:
        raise ValueError("p= uses a non-canonical Base64 encoding")
    return raw, warnings


# Control characters (C0, DEL, C1) and invisible direction/format characters.
_UNSAFE_PRINT_RE = re.compile("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]")
# The same set without C0 (json.dumps escapes C0 itself; its own line breaks
# between tokens must stay).
_UNSAFE_JSON_OUTPUT_RE = re.compile("[\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]")
# Control characters that v1.3 files must not contain in member names and
# strings (SPEC §13.12.1, schema v1.3 value_guard).
_CONTROL_CHAR_RE = re.compile("[\x00-\x1f\x7f-\x9f]")


def safe_text(value: Any, limit: int = 300) -> str:
    """Printable form of a value taken from a file or the network.

    Control characters (e.g. ANSI escape sequences) are shown as \\xNN /
    \\uNNNN instead of being sent to the terminal; long values are cut.
    """
    text = value if isinstance(value, str) else str(value)
    text = _UNSAFE_PRINT_RE.sub(
        lambda m: f"\\x{ord(m.group(0)):02x}" if ord(m.group(0)) < 0x100 else f"\\u{ord(m.group(0)):04x}", text)
    return text if len(text) <= limit else text[:limit] + "…"


def sha256_hex(data: bytes) -> str:
    """Lowercase hexadecimal SHA-256 digest (format of representations[].sha256)."""
    return hashlib.sha256(data).hexdigest()


# ─────────────────────────────────────────────
# Optional dependencies — never terminate an importing program
# ─────────────────────────────────────────────

_MISSING_DEPS: List[str] = []

try:
    from json_canon import canonicalize
except ImportError:
    try:
        # "json-canon" is not published on PyPI; rfc8785 is the maintained
        # Python implementation of JCS (RFC 8785) and produces identical output.
        import rfc8785

        def canonicalize(obj) -> bytes:
            return rfc8785.dumps(obj)
    except ImportError:
        canonicalize = None  # type: ignore[assignment]
        _MISSING_DEPS.append("rfc8785")

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
except ImportError:
    Ed25519PrivateKey = Ed25519PublicKey = serialization = None  # type: ignore

    class InvalidSignature(Exception):  # type: ignore[no-redef]
        """Placeholder so that importing modules keep working."""

    _MISSING_DEPS.append("cryptography")


class ARPDependencyError(RuntimeError):
    """Raised by library functions when an optional dependency is missing."""


def _require_deps(*names: str) -> None:
    missing = [n for n in names if n in _MISSING_DEPS]
    if missing:
        raise ARPDependencyError("Missing dependency: pip install " + " ".join(missing))


def _canonical_bytes(obj: Any) -> bytes:
    _require_deps("rfc8785")
    out = canonicalize(obj)
    return out.encode("utf-8") if isinstance(out, str) else out


# ─────────────────────────────────────────────
# Strict parsing: I-JSON (RFC 7493), as JCS (RFC 8785) presupposes
# ─────────────────────────────────────────────

class ManifestParseError(ValueError):
    """A reasoning.json that cannot be accepted.

    reason: "duplicate_member" or "non_ijson" (the file is JSON but not
    I-JSON: rejected, verify reports INVALID), "invalid_json" (syntax error,
    or nested deeper than MAX_JSON_DEPTH) or "not_utf8" (not loadable).
    paths: JSON paths of the offending members.
    """

    def __init__(self, reason: str, message: str, paths: Optional[List[str]] = None):
        super().__init__(message)
        self.reason = reason
        self.paths = list(paths or [])


# Reasons for which a loadable file is rejected (verify: INVALID).
REJECTED_PARSE_REASONS = ("duplicate_member", "non_ijson")


class _OversizedInt(int):
    """Placeholder for an integer literal with more than 16 digits.

    Such a literal lies outside ±(2^53−1) and is reported as non-I-JSON.
    It is not converted: Python 3.9 converts long digit strings in
    quadratic time (a literal with a million digits takes seconds).
    The int value is ±2^53, the digit count is kept for the message.
    """

    digits: int

    def __new__(cls, negative: bool, digits: int):
        obj = super().__new__(cls, -(IJSON_MAX_SAFE_INTEGER + 1) if negative else IJSON_MAX_SAFE_INTEGER + 1)
        obj.digits = digits
        return obj

    def __reduce__(self):
        return (_OversizedInt, (self < 0, self.digits))


def _describe_integer(value: int) -> str:
    """Short description of an integer outside I-JSON, without converting a
    huge value to text (quadratic in Python 3.9)."""
    if isinstance(value, _OversizedInt):
        return f"integer with {value.digits} digits"
    if value.bit_length() <= 128:
        return f"integer {value}"
    return f"integer with about {int(value.bit_length() * 0.30103) + 1} digits"


def _depth_exceeds(value: Any, limit: int) -> bool:
    """True if objects/arrays nest deeper than limit (iterative, no recursion)."""
    stack: List[Tuple[Any, int]] = [(value, 1)]
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


def ijson_problems(value: Any, path: str = "$") -> List[Tuple[str, str]]:
    """List values that are not I-JSON (RFC 7493 §2): (path, description).

    Integers outside ±(2^53−1), non-finite numbers, and member names or
    strings with unpaired surrogates. RFC 8785 cannot canonicalize them.
    """
    problems: List[Tuple[str, str]] = []

    def visit(item: Any, p: str) -> None:
        if isinstance(item, bool) or item is None:
            return
        if isinstance(item, int):
            if isinstance(item, _OversizedInt) or abs(item) > IJSON_MAX_SAFE_INTEGER:
                problems.append((p, f"{_describe_integer(item)} lies outside ±(2^53−1)"))
        elif isinstance(item, float):
            if not math.isfinite(item):
                problems.append((p, f"number {item!r} is not finite"))
        elif isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError:
                problems.append((p, "string contains an unpaired surrogate"))
        elif isinstance(item, dict):
            for key, child in item.items():
                child_path = _child_path(p, key) if isinstance(key, str) else f"{p}[?]"
                try:
                    str(key).encode("utf-8")
                except UnicodeEncodeError:
                    problems.append((child_path, "member name contains an unpaired surrogate"))
                    continue
                visit(child, child_path)
        elif isinstance(item, list):
            for i, child in enumerate(item):
                visit(child, f"{p}[{i}]")

    visit(value, path)
    return problems


def _parse_json_collecting(text: str) -> Tuple[Any, List[Tuple[str, str]]]:
    """Parse JSON text. Returns (data, duplicates) with duplicates as (path, name).

    Raises ManifestParseError for NaN/Infinity or numbers outside the double
    range, and "invalid_json" for syntax errors and for nesting deeper than
    MAX_JSON_DEPTH. Integer literals with more than 16 digits are not
    converted (see _OversizedInt). Duplicate member names are collected
    (the parsed object keeps the last value, as json.loads does).
    """
    duplicates_by_object: Dict[int, List[str]] = {}
    keep_alive: List[Dict[str, Any]] = []

    def object_pairs(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        obj: Dict[str, Any] = {}
        dups: List[str] = []
        for key, value in pairs:
            if key in obj:
                dups.append(key)
            obj[key] = value
        if dups:
            keep_alive.append(obj)  # keeps id(obj) unique until the walk below
            duplicates_by_object[id(obj)] = dups
        return obj

    def reject_constant(name: str) -> Any:
        raise ManifestParseError("non_ijson", f"{name} is not a JSON number (RFC 8259 §6)")

    def parse_float(literal: str) -> float:
        number = float(literal)
        if not math.isfinite(number):
            raise ManifestParseError("non_ijson", f"number {safe_text(literal, 40)} lies outside the IEEE 754 "
                                                  "double range")
        return number

    def parse_int(literal: str) -> int:
        digits = len(literal) - (1 if literal.startswith("-") else 0)
        if digits > IJSON_MAX_INTEGER_DIGITS:
            return _OversizedInt(literal.startswith("-"), digits)
        return int(literal)

    too_deep = f"JSON nested deeper than {MAX_JSON_DEPTH} levels (not accepted)"
    try:
        data = json.loads(text, object_pairs_hook=object_pairs, parse_constant=reject_constant,
                          parse_float=parse_float, parse_int=parse_int)
    except ManifestParseError:
        raise
    except RecursionError:
        raise ManifestParseError("invalid_json", too_deep)
    except ValueError as e:
        raise ManifestParseError("invalid_json", f"not valid JSON: {e}")
    if _depth_exceeds(data, MAX_JSON_DEPTH):
        raise ManifestParseError("invalid_json", too_deep)

    duplicates: List[Tuple[str, str]] = []
    if duplicates_by_object:
        def walk(item: Any, p: str) -> None:
            if isinstance(item, dict):
                for name in duplicates_by_object.get(id(item), []):
                    duplicates.append((_child_path(p, name), name))
                for key, child in item.items():
                    walk(child, _child_path(p, key))
            elif isinstance(item, list):
                for i, child in enumerate(item):
                    walk(child, f"{p}[{i}]")
        walk(data, "$")
    return data, duplicates


def parse_manifest_text(text: str) -> Any:
    """Parse a reasoning.json strictly as I-JSON (RFC 7493). Raises ManifestParseError.

    Rejects duplicate member names at any depth (RFC 7493 §2.3), NaN and
    Infinity, integers outside ±(2^53−1) and unpaired surrogates. JSON
    parsers keep the last of several equal names, while people and LLMs
    reading the bytes see the first: a signed file could carry text that
    the signature does not cover.
    """
    data, duplicates = _parse_json_collecting(text)
    if duplicates:
        names = ", ".join(sorted({name for _, name in duplicates}))
        raise ManifestParseError(
            "duplicate_member",
            f"duplicate member name(s) {safe_text(names, 120)} at {safe_text(duplicates[0][0], 120)} "
            "(I-JSON, RFC 7493 §2.3: member names must be unique)",
            [p for p, _ in duplicates])
    problems = ijson_problems(data)
    if problems:
        raise ManifestParseError("non_ijson", f"{problems[0][1]} at {safe_text(problems[0][0], 120)} "
                                 "(I-JSON, RFC 7493)", [p for p, _ in problems])
    return data


def parse_manifest_bytes(raw: bytes) -> Any:
    """parse_manifest_text() for raw bytes (UTF-8, a leading BOM is ignored)."""
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise ManifestParseError("not_utf8", f"not UTF-8: {e}")
    return parse_manifest_text(text)


# ─────────────────────────────────────────────
# Names, domains, selectors
# ─────────────────────────────────────────────

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
# SPEC §13.3 / schema v1.3: one or more labels separated by single dots, at
# most 50 characters; each label consists of letters, digits, '-' and '_' and
# begins and ends with a letter or digit, so that {selector}._arp.{domain} is
# a DNS name.
_SELECTOR_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?"
_SELECTOR_RE = re.compile(rf"{_SELECTOR_LABEL}(?:\.{_SELECTOR_LABEL})*")
_DOMAIN_RE = re.compile(rf"(?=.{{1,253}}\Z)(?:{_LABEL}\.)+[A-Za-z0-9-]{{2,63}}")


def normalize_domain(value: str) -> str:
    """Lowercase a bare hostname and strip a trailing dot. Raises ValueError."""
    if not isinstance(value, str):
        raise ValueError("domain must be a string")
    domain = value.strip().lower().rstrip(".")
    if not _DOMAIN_RE.fullmatch(domain):
        raise ValueError(
            f"'{safe_text(value, 120)}' is not a bare domain name (expected e.g. example.com, "
            "without scheme, path or port)"
        )
    return domain


def validate_selector(selector: str) -> str:
    """Check a DNS selector (SPEC §13.3: DNS labels of [A-Za-z0-9_-] that begin
    and end with a letter or digit, separated by single dots, at most 50
    characters). Raises ValueError."""
    if not isinstance(selector, str) or not selector or len(selector) > 50 \
            or not _SELECTOR_RE.fullmatch(selector):
        raise ValueError(
            f"'{safe_text(selector, 60)}' is not a valid selector (letters, digits, '-' and '_', "
            "labels separated by single dots, each label beginning and ending with a letter or digit, "
            "at most 50 characters; e.g. arp2610)"
        )
    return selector


def dns_name_for(selector: str, domain: str) -> str:
    """DNS name of the key record: {selector}._arp.{domain} (SPEC §13.5)."""
    return f"{selector}._arp.{domain}"


def doh_url_for(dns_name: str) -> str:
    """Reference DNS-over-HTTPS URL for the key record (ARP-S verify.doh_url)."""
    return DOH_URL_TEMPLATE.format(name=dns_name)


def manifest_url_for(domain: str) -> str:
    return f"https://{domain}{MANIFEST_PATH}"


def markdown_url_for(domain: str) -> str:
    return f"https://{domain}{MARKDOWN_PATH}"


def signature_statement_for(domain: str, selector: str) -> str:
    return SIGNATURE_STATEMENT_TEMPLATE.format(
        domain=domain, dns_name=dns_name_for(selector, domain)
    )


def provenance_statement_for(entity: str, publisher: str, domain: str) -> str:
    return PROVENANCE_STATEMENT_TEMPLATE.format(
        entity=entity, publisher=publisher, domain=domain
    )


def build_signature_metadata(domain: str, selector: str,
                             signed_at: datetime, expires_at: datetime) -> Dict[str, Any]:
    """The _arp_signature block WITHOUT the signature field (ARP-S, K3)."""
    dns_name = dns_name_for(selector, domain)
    return {
        "algorithm": "Ed25519",
        "dns_selector": selector,
        "dns_record": dns_name,
        "canonicalization": "jcs-rfc8785",
        "signed_at": signed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "statement": signature_statement_for(domain, selector),
        "verify": {
            "dns_name": dns_name,
            "doh_url": doh_url_for(dns_name),
            "spec": SPEC_SIGNATURE_URL,
        },
    }


def _version_tuple(value: Any) -> Optional[Tuple[int, ...]]:
    if not isinstance(value, str):
        return None
    m = re.match(r"^\s*(\d+)\.(\d+)", value)
    return (int(m.group(1)), int(m.group(2))) if m else None


def _is_v13_or_later(manifest: Dict[str, Any]) -> bool:
    v = _version_tuple(manifest.get("version"))
    return v is not None and v >= (1, 3)


# ─────────────────────────────────────────────
# ARP-R — Reference rendering of /.well-known/reasoning.md
#   Pure functions, no global state. Other tools may import or port them.
# ─────────────────────────────────────────────

RENDER_SECTION_ORDER = (
    "identity", "organization", "corrections", "entity_claims",
    "authority", "content_policy",
)
RENDER_EXCLUDED_KEYS = frozenset({
    "$schema", "protocol", "version", "domain", "entity", "provenance",
    "representations", "_arp_signature", "diagnostics",
})
# Labels of the fixed final section "## Verification" of reasoning.md.
_VERIFICATION_LABELS = frozenset({"manifest", "statement", "dns_name", "doh_url", "signed_at", "expires_at",
                                  "signature"})


def _md_number(value: Any) -> str:
    """Format a JSON number exactly like ECMAScript Number::toString.

    Keeps the Markdown byte-identical across Python and JavaScript ports
    (e.g. 1.0 → "1", 1e21 → "1e+21", 0.000001 → "0.000001"). Integers are
    read as IEEE 754 doubles first, as JavaScript does (10**21 → "1e+21",
    2**53 + 1 → "9007199254740992"); lint rejects integers beyond ±(2^53−1).
    """
    if isinstance(value, _OversizedInt):
        raise ValueError("integer literal outside the I-JSON range (RFC 7493)")
    if isinstance(value, int):
        if abs(value) <= IJSON_MAX_SAFE_INTEGER:
            return str(value)
        try:
            value = float(value)
        except OverflowError:
            raise ValueError("integer outside the IEEE 754 double range")
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("NaN and Infinity are not valid JSON numbers")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    dec = Decimal(repr(abs(value)))
    tup = dec.as_tuple()
    digits = "".join(str(d) for d in tup.digits).lstrip("0")
    exponent = tup.exponent
    stripped = digits.rstrip("0")
    exponent += len(digits) - len(stripped)
    digits = stripped
    k = len(digits)
    n = exponent + k  # position of the decimal point relative to the digits
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    e = n - 1
    mantissa = digits[0] + ("." + digits[1:] if k > 1 else "")
    return f"{sign}{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"


def _md_scalar(value: Any) -> str:
    """Strings unchanged; true/false/null; numbers as in ECMAScript."""
    if isinstance(value, str):
        return value
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return _md_number(value)
    raise ValueError(f"unsupported JSON value of type {type(value).__name__}")


def _md_item(prefix: str, text: str) -> str:
    # No trailing space when the value is empty.
    return prefix + (" " + text if text != "" else "")


def _md_list_lines(value: Any, indent: int) -> List[str]:
    """Nested Markdown list, 2 spaces per level (see render_reasoning_md)."""
    pad = " " * indent
    lines: List[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}- {key}:")
                lines.extend(_md_list_lines(item, indent + 2))
            else:
                lines.append(_md_item(f"{pad}- {key}:", _md_scalar(item)))
    elif isinstance(value, list):
        for position, item in enumerate(value, 1):
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}- {position}:")
                lines.extend(_md_list_lines(item, indent + 2))
            else:
                lines.append(_md_item(f"{pad}-", _md_scalar(item)))
    else:
        lines.append(_md_item(f"{pad}-", _md_scalar(value)))
    return lines


def render_reasoning_md(manifest: Dict[str, Any], domain: Optional[str] = None, *,
                        allow_control_characters: bool = False) -> str:
    """Render the reference Markdown representation of a reasoning.json (ARP-R).

    Deterministic: the same input yields the same text. Encode the result as
    UTF-8 to obtain the bytes that representations[].sha256 covers. The text
    uses LF line endings and ends with exactly one newline.

    Input: the manifest as parsed by parse_manifest_bytes() (strict I-JSON,
    duplicate member names rejected — SPEC §13.4) with an order-preserving
    parser; the key order of the file determines the order of the lines.

    Refused (ValueError), so that no value can imitate the structure of the
    file (SPEC §13.12.1):
      - control characters U+0000–U+001F and U+007F–U+009F (line breaks,
        tabs …) in any member name or string. allow_control_characters=True
        renders them anyway, but only for files below version 1.3;
      - a top-level member whose name differs from "verification" but
        equals it ignoring case ("Verification", "VERIFICATION"): its
        heading would imitate the fixed final section "## Verification";
      - a "verification" member (SPEC §5) that is not an object, or whose
        members are named like the lines of that section (manifest,
        statement, dns_name, doh_url, signed_at, expires_at, signature).

    Format (blocks separated by one empty line):

      1. "# {entity} — self-description (ARP)"            (U+2014 em dash)
      2. provenance.statement                       (omitted if not present)
      3. "Manifest: https://{domain}/.well-known/reasoning.json"
      4. One section per present top-level member, first in the fixed order
         identity, organization, corrections, entity_claims, authority,
         content_policy, then all remaining members sorted by code point.
         Never rendered: $schema, protocol, version, domain, entity,
         provenance, representations, _arp_signature, diagnostics.
         Section = "## {key}", an empty line, then a nested Markdown list:
           - object member, scalar value:   "- {key}: {value}"
           - object member, object/array:   "- {key}:" + children
           - array element, scalar:         "- {value}"
           - array element, object/array:   "- {n}:" + children (n from 1)
           - top-level scalar value:        "- {value}"
         Children are indented by 2 more spaces than their parent line.
         Keys keep their original spelling and document order. Strings are
         copied unchanged; true/false/null as written; numbers formatted
         like ECMAScript Number::toString. An empty value produces no
         trailing space ("- key:"). An empty object/array section is just
         its heading.
      5. "## Verification", an empty line, then
           "- Manifest: https://{domain}/.well-known/reasoning.json"
         and, if the manifest has an _arp_signature object, one line per
         present value, in this order:
           "- statement: {_arp_signature.statement}"
           "- dns_name: {_arp_signature.verify.dns_name}"  (else dns_record)
           "- doh_url: {_arp_signature.verify.doh_url}"
           "- signed_at: {_arp_signature.signed_at}"
           "- expires_at: {_arp_signature.expires_at}"
         The signature value itself is never rendered, so the text is the
         same before and after the signature is inserted.

    Args:
        manifest: parsed reasoning.json (dict, key order as in the file).
        domain:   domain serving the file; defaults to manifest["domain"].
                  Normalized like the CLI does: lowercase, no trailing dot.

    Raises:
        ValueError: entity or domain missing, domain not a bare domain name,
                    a value is not JSON, or one of the refusals above.
    """
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    for key in manifest:
        if isinstance(key, str) and key != "verification" and key.casefold() == "verification":
            raise ValueError(f"top-level member '{safe_text(key, 40)}' would render as a heading that imitates "
                             "the fixed final section '## Verification'; rename or remove it")
    if "verification" in manifest:
        review = manifest["verification"]
        if not isinstance(review, dict):
            raise ValueError("'verification' is not an object (SPEC §5); its items could imitate the fixed final "
                             "section '## Verification'")
        for key in review:
            if isinstance(key, str) and key.casefold() in _VERIFICATION_LABELS:
                raise ValueError(f"verification.{safe_text(key, 40)} is named like a line of the fixed final "
                                 "section '## Verification'; rename or remove it")
    if not (allow_control_characters and not _is_v13_or_later(manifest)):
        problem = find_control_character(manifest)
        if problem is not None:
            path, what, code = problem
            raise ValueError(f"control character U+{code:04X} in a {what} at {safe_text(path, 120)}: values are "
                             "copied unchanged into reasoning.md, so it is not rendered (SPEC §13.12.1)")
    entity = manifest.get("entity")
    if not isinstance(entity, str) or not entity.strip():
        raise ValueError("manifest has no 'entity' string")
    if domain is None:
        domain = manifest.get("domain")
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("no domain: pass domain= or set the 'domain' field")
    domain = normalize_domain(domain)
    manifest_url = f"https://{domain}{MANIFEST_PATH}"

    blocks: List[str] = [f"# {entity} — self-description (ARP)"]

    provenance = manifest.get("provenance")
    if isinstance(provenance, dict):
        statement = provenance.get("statement")
        if isinstance(statement, str) and statement != "":
            blocks.append(statement)

    blocks.append(f"Manifest: {manifest_url}")

    ordered = [k for k in RENDER_SECTION_ORDER if k in manifest]
    rest = sorted(k for k in manifest
                  if k not in RENDER_EXCLUDED_KEYS and k not in RENDER_SECTION_ORDER)
    for key in ordered + rest:
        lines = _md_list_lines(manifest[key], 0)
        blocks.append(f"## {key}" + ("\n\n" + "\n".join(lines) if lines else ""))

    verification = [f"- Manifest: {manifest_url}"]
    sig = manifest.get("_arp_signature")
    if isinstance(sig, dict):
        verify = sig.get("verify") if isinstance(sig.get("verify"), dict) else {}
        dns_name = verify.get("dns_name", sig.get("dns_record"))
        for label, value in (
            ("statement", sig.get("statement")),
            ("dns_name", dns_name),
            ("doh_url", verify.get("doh_url")),
            ("signed_at", sig.get("signed_at")),
            ("expires_at", sig.get("expires_at")),
        ):
            if value is not None:
                verification.append(_md_item(f"- {label}:", _md_scalar(value)))
    blocks.append("## Verification\n\n" + "\n".join(verification))

    return "\n\n".join(blocks) + "\n"


def render_reasoning_md_bytes(manifest: Dict[str, Any], domain: Optional[str] = None, *,
                              allow_control_characters: bool = False) -> bytes:
    """UTF-8 bytes of render_reasoning_md() — the input for representations[].sha256."""
    return render_reasoning_md(manifest, domain, allow_control_characters=allow_control_characters).encode("utf-8")


def find_control_character(manifest: Any) -> Optional[Tuple[str, str, int]]:
    """First control character (U+0000–U+001F, U+007F–U+009F) in a member
    name or string: (JSON path, "member name" | "string", code point), or None."""
    for kind, path, value in _walk(manifest):
        m = _CONTROL_CHAR_RE.search(value)
        if m:
            return path, "member name" if kind == "key" else "string", ord(m.group(0))
    return None


def markdown_representation(domain: str, digest: str) -> Dict[str, str]:
    """The representations[] entry for /.well-known/reasoning.md (ARP-R, K4)."""
    return {"href": markdown_url_for(domain), "media_type": MARKDOWN_MEDIA_TYPE, "sha256": digest}


def set_markdown_representation(manifest: Dict[str, Any], domain: str, digest: str) -> Dict[str, str]:
    """Insert or replace the reasoning.md entry in manifest["representations"].

    Other entries keep their position. Mutates manifest; returns the entry.
    """
    entry = markdown_representation(domain, digest)
    reps = manifest.get("representations")
    if not isinstance(reps, list):
        manifest["representations"] = [entry]
        return entry
    for i, existing in enumerate(reps):
        if isinstance(existing, dict) and (
            existing.get("href") == entry["href"]
            or urlparse(str(existing.get("href", ""))).path == MARKDOWN_PATH
        ):
            reps[i] = entry
            return entry
    reps.append(entry)
    return entry


# ─────────────────────────────────────────────
# ARP-W — Wording Profile lint (K1) + provenance / signature fields
# ─────────────────────────────────────────────

@dataclass(frozen=True)
class LintFinding:
    severity: str  # "error" | "warning"
    rule: str
    path: str      # JSON path, e.g. $.entity_claims.internal_taxonomy[0].ai_directive
    message: str
    excerpt: str = ""

    def as_dict(self) -> Dict[str, str]:
        return {"severity": self.severity, "rule": self.rule, "path": self.path,
                "message": self.message, "excerpt": self.excerpt}


_SIMPLE_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _child_path(path: str, key: Any) -> str:
    if isinstance(key, int):
        return f"{path}[{key}]"
    if _SIMPLE_KEY_RE.fullmatch(key):
        return f"{path}.{key}"
    try:
        key.encode("utf-8")
    except UnicodeEncodeError:  # unpaired surrogate: keep the path printable
        return f"{path}[{json.dumps(key)}]"
    return f"{path}[{json.dumps(key, ensure_ascii=False)}]"


def _walk(value: Any, path: str = "$") -> Iterator[Tuple[str, str, Any]]:
    """Yield ("key", path, key) for member names and ("str", path, s) for strings."""
    if isinstance(value, dict):
        for key, item in value.items():
            child = _child_path(path, key)
            yield "key", child, key
            yield from _walk(item, child)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from _walk(item, _child_path(path, i))
    elif isinstance(value, str):
        yield "str", path, value


# Field names reserved for instruction-style content (K1).
_FORBIDDEN_KEYS = frozenset({
    "system_instruction", "system_instructions", "reasoning_directives",
    "reasoning_directive", "ai_directive", "ai_directives", "agent_directive",
    "agent_directives", "instruction", "instructions", "directive", "directives",
    "system_prompt", "system_note", "system_message",
})
_FORBIDDEN_KEY_TOKENS = frozenset({
    "instruction", "instructions", "directive", "directives",
    "anweisung", "anweisungen", "direktive", "direktiven",
})


def _key_tokens(key: str) -> List[str]:
    return [t.lower() for t in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+", key)]


_I = re.IGNORECASE
_SENT = r"(?:^|[.!?;:\n]\s*)"
# Clause start for imperatives. "and", "or" and "to" are left out on purpose
# ("diagnose and treat patients as …", "equipped to treat children as …").
_CLAUSE = (r"(?:^|[.!?;:,\n]\s*|\b(?:please|then|always|never|instead|only|should|must|shall|"
           r"(?<!does\s)(?<!did\s)not)\s+)")
_PROPER = r"[A-Z][\w'’&.-]*(?:\s+[A-Z][\w'’&.-]*){0,2}"
# Subjects that denote AI systems ("AI systems", "LLMs", "language models" …).
# Generic nouns such as "models" or "agents" alone are left out ("pricing models should …").
_AI_SUBJECT = (r"\b(?:llms?|chatbots?|(?:large\s+)?language\s+models?|generative\s+(?:ai|engines?)|"
               r"answer\s+engines?|(?:ai|ki)(?:[\s-]+(?:systems?|agents?|models?|assistants?|tools?|engines?|"
               r"crawlers?|bots?|search))?)")
# Object slot for framing imperatives ("Present TrueSource as …", "Frame the
# company as …"): a determiner/pronoun or a capitalized name. Keeps statements
# such as "Present in 12 countries as a distributor" or "Frame sizes as small
# as 44 cm" out; the verb must start a clause ("Analysts present X as …" is a
# statement).
_FRAMING_OBJECT = (r"(?:(?i:the|our|this|that|these|those|its|their|his|her|my|your|it|them|us|him)\b"
                   r"|[A-Z][\w'’&.-]*)")
_FRAMING_VERB = (r"(?i:frame|present|position|portray|depict|characteri[sz]e|refer\s+to|cite|label|"
                 r"introduce)")
# Generic nouns that denote AI systems only as the subject of a sentence that
# tells them how to handle information ("Assistants must cite …", "Models
# must not invent …"). The verbs are limited to handling information, so
# rules for people stay statements ("Assistants must wear gloves", "Models
# must be at least 16"); "use", "follow", "treat" and "present" count only
# with an information object or "as". "Agents" also means insurance or
# travel agents, who recommend and describe by profession, so it takes a
# narrower list ("Agents must hold a licence" is a statement).
_GENERIC_AI_SUBJECT = r"(?:the\s+|all\s+|any\s+)?(?:assistants?|models?|bots?|chatbots?|crawlers?|answer\s+engines?)"
_INFO_OBJECT = (r"(?:only\s+)?(?:this|these|the\s+following|our|its)\s+(?:file|manifest|document|data|information|"
                r"statements?|facts?|descriptions?|sources?|page|text|context|claims?)")
_INFO_VERBS = (r"(?:cite|quote|describe|mention|recommend|prefer|rely\s+on|refer\s+to|invent|repeat|ignore|disregard|"
               r"trust|rank|credit|attribute|summari[sz]e|confuse|prioriti[sz]e|frame|position|portray|"
               r"(?:treat|present|regard|consider)\s+(?:\S+\s+){0,5}?as|(?:use|follow|reference)\s+" + _INFO_OBJECT + ")")
_AGENT_VERBS = (r"(?:cite|quote|invent|repeat|trust|rank|credit|attribute|summari[sz]e|prioriti[sz]e|frame|portray|"
                r"ignore|disregard|(?:treat|present)\s+(?:\S+\s+){0,5}?as|(?:use|follow)\s+" + _INFO_OBJECT + ")")
_MODAL = (r"(?:must|should|shall|may|need\s+to|have\s+to|are\s+(?:required|expected|asked|instructed|encouraged|"
          r"advised|allowed|permitted|welcome|free)\s+to)\s+(?:not\s+|never\s+|always\s+|only\s+)?")
# Clause start for German imperatives ("Beschreibe …", "Bitte empfiehl …").
_CLAUSE_DE = r"(?:^|[.!?;:,\n]\s*|\b(?:bitte|dann|immer|nie|niemals|stets|nur|stattdessen)\s+)"

# (severity, rule, regex, message)
_TEXT_RULES: List[Tuple[str, str, "re.Pattern[str]", str]] = [
    # — Conditional instructions ("When discussing X …") —
    ("error", "ARP-W/conditional", re.compile(_SENT + r"when\s+[a-z]+ing\b", _I),
     "Conditional instruction ('When discussing X …'). Write a third-person statement about the entity."),
    ("error", "ARP-W/conditional", re.compile(r"\bwhen\s+(?:asked|queried|prompted)\b", _I),
     "Conditional instruction ('When asked …'). Write a third-person statement about the entity."),
    ("error", "ARP-W/conditional", re.compile(
        r"\bwhen\s+(?:a\s+|the\s+|any\s+)?(?:users?|someone|people|persons?|customers?|visitors?|readers?)\s+"
        r"(?:asks?|queries|query|searches|compares?|mentions?|wants?)\b", _I),
     "Conditional instruction ('When a user asks …'). Describe the situation instead, e.g. 'Typical fit: …'."),
    ("error", "ARP-W/conditional", re.compile(r"\bif\s+(?:queried|asked|prompted)\b", _I),
     "Conditional instruction ('If asked …'). Write a third-person statement about the entity."),
    # — Imperatives addressed to AI systems —
    ("error", "ARP-W/imperative", re.compile(rf"\b[Ff]rame\s+(?:it|this|that|them|him|her|us|{_PROPER})\s+as\b"),
     "Instruction to AI systems ('frame it as'). State the fact instead."),
    ("error", "ARP-W/imperative", re.compile(
        "(?i:" + _CLAUSE + ")" + _FRAMING_VERB + r"\s+" + _FRAMING_OBJECT + r"(?:\s+\S+){0,5}?\s+(?i:as)\b"),
     "Instruction to AI systems ('present/position/frame/refer to X as'). State the fact instead."),
    ("error", "ARP-W/imperative", re.compile(
        _SENT + r"(?:always|never)\s+(?:cite|recommend|mention|name|prefer|prioriti[sz]e|choose|select|use|"
        r"list|link\s+to|refer\s+to|describe|present|frame|position|rank|quote|credit|attribute)\b(?!-)", _I),
     "Instruction to AI systems ('always cite …'). Write a third-person statement about the entity."),
    ("error", "ARP-W/imperative", re.compile(_CLAUSE + r"describe\s+(?:\S+\s+){0,5}?as\b", _I),
     "Instruction to AI systems ('describe X as'). State the fact instead."),
    ("error", "ARP-W/imperative", re.compile(r"\bdefer\s+to\b", _I),
     "Instruction to AI systems ('defer to'). Link evidence instead."),
    ("error", "ARP-W/imperative", re.compile(_CLAUSE + r"treat\s+(?:\S+\s+){0,6}?as\b", _I),
     "Instruction to AI systems ('treat … as'). State what the item is instead."),
    ("error", "ARP-W/imperative", re.compile(_CLAUSE + r"recommend\b", _I),
     "Instruction to recommend. Describe the fit instead ('Typical fit: …' / 'Not a fit: …')."),
    ("error", "ARP-W/imperative", re.compile(r"\brecommend\s+(?:\S+\s+){0,5}?(?:when|if)\b", _I),
     "Instruction to recommend ('recommend X when'). Describe the fit instead ('Typical fit: …')."),
    ("error", "ARP-W/imperative", re.compile(
        _CLAUSE + r"(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:(?:the|your|other|previous|prior|"
        r"above|earlier|preceding|existing|original|conflicting)\s+){0,3}(?:instructions?|prompts?|context|sources?|"
        r"information|rules|guidelines|directions|data|messages?|training(?:\s+data)?|results?|descriptions?|"
        r"statements?|claims?|answers?|responses?|facts?|reports?|articles?|reviews?|content|knowledge|"
        r"assumptions?)\b", _I),
     "Instruction to AI systems ('ignore previous instructions', 'disregard other sources'). Remove it."),
    ("error", "ARP-W/imperative", re.compile(
        _SENT + r"(?:do\s+not|don't|don’t)\s+(?:mention|cite|recommend|name|list|link\s+to|refer\s+to|compare|discuss|"
        r"include|quote|suggest|disclose|reveal|speculate|invent|guess|assume|repeat|confuse|associate|describe|"
        r"present|call|label|attribute|credit|rank|state|say|answer|respond|reply|contradict|question|doubt|"
        r"dispute|override|alter|modify)\b(?!-)", _I),
     "Instruction to AI systems ('Do not mention …'). Write a third-person statement about the entity."),
    ("error", "ARP-W/imperative", re.compile(
        _SENT + r"(?:respond|answer|reply)\s+(?:only|exclusively|solely|always|strictly|with|using|based\s+on|"
        r"according\s+to|in\s+line\s+with|(?:all\s+|any\s+)?(?:questions?|queries|inquiries|requests?|prompts?))\b"
        r"|\b(?:using|based\s+on|from)\s+only\s+(?:this|these)\s+(?:file|manifest|document|data|information|"
        r"statements?|facts?|descriptions?|sources?|page|text)\b", _I),
     "Instruction to AI systems ('Respond only with …', 'Answer questions … using only this file'). Remove it."),
    ("error", "ARP-W/imperative", re.compile(
        _SENT + r"(?:consider|regard|accept|take)\s+(?:this|these|the\s+following|it|them)\b", _I),
     "Instruction to AI systems ('Consider this …', 'Accept these …'). State the fact instead."),
    ("error", "ARP-W/imperative", re.compile(
        _CLAUSE + r"(?:use|rely\s+on|refer\s+to|consult|prefer|prioriti[sz]e|trust|cite|quote)\s+(?:only\s+|"
        r"exclusively\s+)?(?:this|these|the\s+following|the\s+above)\s+(?:file|manifest|document|data|information|"
        r"statements?|facts?|descriptions?|sources?|page|text|context|claims?)\b", _I),
     "Instruction to AI systems ('Use this file', 'Rely on these statements'). Remove it."),
    ("error", "ARP-W/imperative", re.compile(
        "(?i:" + _CLAUSE + r")(?i:cite|quote|mention|prioriti[sz]e|prefer|emphasi[sz]e|highlight|favou?r|promote)\s+"
        + _FRAMING_OBJECT),
     "Instruction to AI systems ('cite X first', 'mention X'). Write a third-person statement about the entity."),
    ("error", "ARP-W/imperative", re.compile(
        r"\b(?:should|must|shall|ought\s+to|is\s+to|are\s+to|needs?\s+to|has\s+to|have\s+to)\s+(?:always\s+|only\s+)?"
        r"be\s+(?:described|presented|framed|positioned|portrayed|depicted|characteri[sz]ed|referred\s+to|labell?ed|"
        r"introduced|regarded|considered|seen|viewed|treated|named|called)(?:\s+\S+){0,4}?\s+as\b"
        r"|\b(?:should|must|shall)\s+(?:always\s+)?be\s+(?:recommended|mentioned|cited|ranked|prioriti[sz]ed|listed|"
        r"preferred)\s+(?:first|above|before|ahead\s+of|instead\s+of|over|whenever|when|if)\b", _I),
     "Instruction in passive form ('X should be described as …'). State the fact instead."),
    # — German imperatives —
    ("error", "ARP-W/imperative", re.compile(
        _CLAUSE_DE + r"(?:beschreibe|beschreiben\s+Sie|bezeichne|bezeichnen\s+Sie|präsentiere|präsentieren\s+Sie|"
        r"positioniere|positionieren\s+Sie|nenne|nennen\s+Sie|behandle|behandeln\s+Sie|betrachte|betrachten\s+Sie|"
        r"charakterisiere|charakterisieren\s+Sie|porträtiere|stellen\s+Sie)\s+(?:\S+\s+){0,6}?als\b", _I),
     "Instruction to AI systems ('Beschreibe X als …'). State the fact instead."),
    ("error", "ARP-W/imperative", re.compile(
        _CLAUSE_DE + r"(?:empfiehl|empfehlen\s+Sie|zitiere|zitieren\s+Sie|ignoriere|ignorieren\s+Sie|vergiss|"
        r"vergessen\s+Sie|erwähne|erwähnen\s+Sie|bevorzuge|bevorzugen\s+Sie|verweisen\s+Sie|antworte|"
        r"antworten\s+Sie|nutze|verwende|verwenden\s+Sie)\b", _I),
     "Instruction to AI systems ('Empfiehl …', 'Ignoriere …'). Write a third-person statement about the entity."),
    # — Addressing AI systems —
    ("error", "ARP-W/address-ai", re.compile(
        r"\bif\s+you(?:'re|’re|\s+are)\s+(?:an?\s+)?(?:ai|a\.i\.|llm|large\s+language\s+model|language\s+model|"
        r"agent|assistant|bot|chatbot|model|crawler|machine)\b", _I),
     "Text addressed to AI systems ('If you are an AI'). Remove it."),
    ("error", "ARP-W/address-ai", re.compile(
        r"\byou(?:'re|’re|\s+are)\s+(?:\w+\s+)?(?:authori[sz]ed|allowed|permitted|instructed|required|expected|asked)\b", _I),
     "Permission or instruction addressed to the reader ('you are authorized'). Remove it."),
    ("error", "ARP-W/address-ai", re.compile(r"\byou\s+(?:should|must|shall|may|need\s+to|have\s+to|ought\s+to)\b", _I),
     "Instruction in second person ('you should/may …'). Write a third-person statement."),
    ("error", "ARP-W/address-ai", re.compile(
        _AI_SUBJECT + r"\s+(?:must|should|shall|need\s+to|have\s+to|are\s+(?:required|expected|asked|"
        r"instructed|encouraged|advised)\s+to)\b", _I),
     "Normative sentence addressed to AI systems ('AI systems must/should'). Write a statement about the entity."),
    ("error", "ARP-W/address-ai", re.compile(
        r"\b(?:KI|AI)[\s-]?(?:Systeme?|Agenten?|Modelle?|Assistenten?|Crawler)\s+(?:sollen|sollten|müssen|dürfen)\b", _I),
     "Normative sentence addressed to AI systems ('KI-Systeme sollen …'). Write a statement about the entity."),
    ("error", "ARP-W/address-ai", re.compile(
        "(?i:" + _AI_SUBJECT + r")\s+(?:MUST|SHOULD|SHALL|MAY|REQUIRED|RECOMMENDED)\b"
        r"|(?i:" + _AI_SUBJECT + r"\s+(?:are|is)\s+(?:explicitly\s+|hereby\s+)?(?:permitted|allowed|authori[sz]ed|welcome|"
        r"invited|free|entitled)\s+to)\b"),
     "Permission or rule addressed to AI systems ('AI agents MAY …', 'AI crawlers are allowed to …'). "
     "Such rules belong in the SPEC, not in a manifest."),
    ("error", "ARP-W/address-ai", re.compile(_SENT + _GENERIC_AI_SUBJECT + r"\s+" + _MODAL + _INFO_VERBS + r"\b", _I),
     "Normative sentence addressed to AI systems ('Assistants must cite …', 'Models must not invent …'). "
     "Write a statement about the entity."),
    ("error", "ARP-W/address-ai", re.compile(
        _SENT + r"(?:the\s+|all\s+|any\s+)?agents?\s+" + _MODAL + _AGENT_VERBS + r"\b", _I),
     "Normative sentence addressed to AI agents ('Agents must cite …'). Write a statement about the entity."),
    ("error", "ARP-W/address-ai", re.compile(
        _SENT + r"for\s+" + _AI_SUBJECT + r"\s*:|" + _SENT + r"for\s+" + _GENERIC_AI_SUBJECT + r"\s*:", _I),
     "Text addressed to AI systems ('For AI systems: …'). Remove it."),
    ("error", "ARP-W/address-ai", re.compile(
        r"\byou(?:'re|’re|\s+are)\s+(?:now\s+)?(?:an?\s+)?(?:\w+\s+){0,2}?(?:(?:ai|a\.i\.|chatbot|llm|"
        r"(?:large\s+)?language\s+model)\b|(?:assistant|bot|model|agent|crawler)(?=\s*(?:[.,;:!)]|$|that\b|who\b|"
        r"which\b)))", _I),
     "Role assignment addressed to an AI system ('you are a helpful assistant'). Remove it."),
    ("error", "ARP-W/address-ai", re.compile(
        r"\b(?:attention|dear|hello|hi|hey|calling|to\s+all)\s*,?\s+" + _AI_SUBJECT + r"\b"
        r"|\b(?:attention|dear|hello|hi|hey|calling|to\s+all)\s*,?\s+" + _GENERIC_AI_SUBJECT + r"\s*[:,!]", _I),
     "Text addressed to AI systems ('Attention AI agents: …'). Remove it."),
    ("error", "ARP-W/address-ai", re.compile(
        r"\b(?:wenn|falls|sofern)\s+(?:du|sie|ihr)\s+(?:\w+\s+){0,2}?(?:eine?n?\s+)?(?:KI|AI|LLM|Sprachmodell|KI-\w+|"
        r"Assistent(?:in)?|Agent|Bot|Chatbot|Modell|Crawler|Maschine)\s+(?:bist|sind|seid)\b", _I),
     "Text addressed to AI systems ('Wenn du eine KI bist'). Remove it."),
    ("error", "ARP-W/address-ai", re.compile(
        r"\b(?:du|ihr)\s+(?:sollst|solltest|musst|müsstest|darfst|sollt|solltet|müsst|dürft)\b"
        r"|\b(?:sollst|solltest|musst|darfst)\s+du\b", _I),
     "Instruction in second person ('du sollst/darfst …'). Write a third-person statement."),
    # — Memory / persistence —
    ("error", "ARP-W/memory", re.compile(r"\bremember\b|\bmerke?\s+dir\b", _I),
     "Memory instruction ('remember'). Remove it."),
    ("error", "ARP-W/memory", re.compile(
        r"\bin\s+(?:all\s+)?(?:future|subsequent|later|upcoming)\s+(?:conversations?|chats?|sessions?|responses?|"
        r"answers?|interactions?)\b|\bin\s+(?:künftigen|zukünftigen|späteren)\s+(?:Gesprächen|Unterhaltungen|Antworten)\b", _I),
     "Persistence instruction ('in future conversations'). Remove it."),
    # — Pseudo system markers —
    ("error", "ARP-W/system-marker", re.compile(
        r"<\s*/?\s*system(?:[_\-\s]?(?:note|prompt|message|instructions?|context))?\b[^>]*>", _I),
     "Pseudo system tag (e.g. <system_note>). Remove it."),
    ("error", "ARP-W/system-marker", re.compile(r"\bSYSTEM\s*:|\bIMPORTANT\s*:|\[/?(?:SYSTEM|INST)\]|<<\s*/?SYS\s*>>"),
     "Pseudo system marker ('SYSTEM:', 'IMPORTANT:', chat-template tokens). Remove it."),
    # Role tags and chat-template tokens as in schema v1.3 (wording_profile_guard), any letter case.
    ("error", "ARP-W/system-marker", re.compile(
        r"<\s*/?\s*(?:assistant|user|developer|human)(?:\s[^>]*)?>|<\|[A-Za-z_]{1,40}\|>", _I),
     "Pseudo role tag or chat-template token (e.g. <assistant>, <user>, <|im_start|>). Remove it."),
    ("error", "ARP-W/system-marker", re.compile(
        r"\bnote\s+(?:to|for)\s+(?:the\s+)?(?:ai|llms?|models?|assistants?|agents?|bots?|crawlers?|language\s+models?|"
        r"ai\s+(?:systems?|agents?|models?|assistants?))\b"
        r"|\bHinweis\s+(?:für|an)\s+(?:die\s+)?(?:KI|AI|LLMs?|Sprachmodelle?|Modelle?|Agenten|Assistenten|Crawler|Bots?)\b",
        _I),
     "Note addressed to AI systems ('Note for AI systems: …'). Remove it."),
    # — Disclaimers of innocence —
    ("error", "ARP-W/disclaimer", re.compile(
        r"\bnot\b[^.!?\n]{0,60}?\b(?:prompt[\s-]+injections?|data[\s-]+poisoning|poisoning|misinformation|"
        r"disinformation|jailbreak(?:s|ing)?|manipulation|an?\s+attacks?)\b"
        r"|\bkeine?\b[^.!?\n]{0,60}?\b(?:Prompt[\s-]*Injection|Manipulation|Falschinformation|Desinformation)\b", _I),
     "Disclaimer of innocence ('this is not prompt injection / misinformation / data poisoning'). Remove it."),
    # — Unsourced authority —
    ("error", "ARP-W/unsourced-authority", re.compile(r"\bground[\s-]+truth\b|\bGrundwahrheit\b", _I),
     "'ground truth' cannot be attributed to a checker. State the fact and link evidence."),
    ("error", "ARP-W/unsourced-authority", re.compile(
        r"\btrusted\s+(?:sources?|authorit(?:y|ies)|references?|information)\b|\bvertrauenswürdige\s+Quellen?\b", _I),
     "'trusted source' without saying who checked what. State the fact and link evidence."),
    # English "authoritative" is checked in _lint_text (qualifier, negation, tone).
    ("error", "ARP-W/unsourced-authority", re.compile(r"\bmaßgebliche\s+Quellen?\b", _I),
     "'maßgebliche Quelle' without saying who checked what. State the fact and link evidence."),
    # — Hidden text —
    ("error", "ARP-W/hidden-text", re.compile(
        r"class\s*=\s*[\"'][^\"']*\b(?:sr-only|visually-hidden|screen-reader-only)\b|display\s*:\s*none|"
        r"visibility\s*:\s*hidden|clip(?:-path)?\s*:\s*(?:rect|inset)\s*\(|"
        r"font-size\s*:\s*0(?:\.0+)?(?:px|em|rem|pt|%)?\s*(?:[;\"'}!]|$)|"
        r"aria-hidden\s*=\s*[\"']true", _I),
     "Hidden-text markup (sr-only, display:none, clip …). Everything must be visible to people and bots alike."),
    # — Warnings (heuristics, do not block signing) —
    ("warning", "ARP-W/second-person", re.compile(r"\b(?:you|your|yours|yourself|you're|you’re)\b", _I),
     "Second person. The Wording Profile uses third-person statements about the entity."),
    ("warning", "ARP-W/imperative-heuristic", re.compile(
        _SENT + r"(?:do\s+not|don't|don’t|never|always|please|ignore|disregard|cite|prefer|prioriti[sz]e|mention|"
        r"consider|emphasi[sz]e|highlight|avoid|ensure|make\s+sure|respond|refer\s+to|reference|"
        r"use(?!\s+(?:of|cases?)\b))\b(?!-)", _I),
     "Sentence starts like an imperative. Check that it is a third-person statement."),
    ("warning", "ARP-W/normative", re.compile(
        r"\b(?:loaders?|consumers?|verifiers?|consuming\s+systems?|retrieval\s+systems?|rag\s+(?:systems?|pipelines?)|"
        r"search\s+engines?)\s+(?:must|should|shall|may)\b"
        r"|" + _AI_SUBJECT + r"\s+may\b", _I),
     "Normative or permission sentence about consumers. Such rules belong in the SPEC, not in a manifest."),
    ("warning", "ARP-W/disclaimer", re.compile(r"\bbenign\b|\bharmless\b|\bharmlos\b", _I),
     "Reassurance wording ('benign', 'harmless'). Describe what the item is instead."),
    ("warning", "ARP-W/disclaimer", re.compile(
        r"\bnot\b[^.!?\n]{0,40}?\b(?:instructions?|commands?|directives?)\b"
        r"|\bkeine?\b[^.!?\n]{0,40}?\b(?:Anweisung(?:en)?|Befehle?)\b", _I),
     "Reassurance that the text is 'not instructions/commands'. A plain description is enough."),
    ("warning", "ARP-W/unsourced-authority", re.compile(
        r"\b(?:definitive|single|sole|canonical|official)\s+(?:source|reference)\b|\bsource\s+of\s+truth\b|"
        r"\b(?:confirmed|validated)\s+(?:and|&)\s+(?:confirmed|validated|verified)\b", _I),
     "Authority claim ('definitive source', 'source of truth', 'confirmed and validated'). Say who checked "
     "what, or link evidence."),
    ("warning", "ARP-W/superlative", re.compile(
        r"\bpioneer(?:s|ing|ed)?\b|\belite\b|\bworld[\s-]leading\b|\bmarket[\s-]leader\b|\bindustry[\s-]leader\b|"
        r"\bthe\s+first\s+(?:\w+\s+){0,3}to\b|\bfirst[\s-]mover\b|\bbest[\s-]in[\s-]class\b|\bunrivall?ed\b|"
        r"\bunmatched\b|#1\b", _I),
     "Superlative without evidence. Link a source or remove it."),
    ("warning", "ARP-W/html-comment", re.compile(r"<!--"),
     "HTML comment inside a value. Comments are invisible to people; remove it."),
]

_VERIFIED_RE = re.compile(r"\b(?:verified|cross-verified|verifiziert|geprüft)\b", _I)
_VERIFIED_QUALIFIER_RE = re.compile(
    r"^(?:\s*,)?(?:\s+\S+){0,3}?\s+(?:by|via|through|against|using|with|at|in|on|from|per|according\s+to|"
    r"durch|von|über|beim|bei|im|laut|gegen)\b", _I)
# "verified by" followed by a generic agent names nobody ("verified by
# independent sources", "von unabhängigen Experten geprüft"), unless a name
# follows ("experts at TÜV Rheinland").
_GENERIC_AGENT = (r"(?:(?:a|an|the|several|multiple|many|various|numerous|independent|external|third[\s-]party|"
                  r"trusted|reliable|reputable|official|leading|neutral|outside|qualified|certified|other|"
                  r"unabhängigen?|externen?|mehreren|verschiedenen|vertrauenswürdigen?|neutralen?)\s+)*"
                  r"(?:sources?|experts?|parties|third[\s-]parties|authorities|organi[sz]ations|institutions|"
                  r"reviewers?|auditors?|people|users?|customers?|studies|research(?:ers)?|analysts|labs?|"
                  r"laborator(?:y|ies)|Quellen|Experten|Stellen|Dritten?|Prüfern?|Gutachtern?)\b"
                  r"(?!\s+(?:at|of|from|bei|von|der|des)\s+(?-i:[A-Z]))")
_GENERIC_AGENT_AFTER_RE = re.compile(
    r"^(?:\s*,)?(?:\s+\S+){0,3}?\s+(?:by|through|from|via|durch|von)\s+" + _GENERIC_AGENT, _I)
_GENERIC_AGENT_BEFORE_RE = re.compile(r"\b(?:von|durch)\s+" + _GENERIC_AGENT + r"(?:\s+\w+)?\s*$", _I)
_PROPER_BEFORE_RE = re.compile(r"\b((?:[A-Z][\w&.'’-]*\s+){0,3}[A-Z][\w&.'’-]*)\s*[:\-]?\s*$")
_GENERIC_STARTERS = frozenset({
    "The", "A", "An", "All", "Our", "Their", "These", "This", "Only", "Fully", "Independently",
    "Cryptographically", "Officially", "Fact", "Facts", "Verified", "Die", "Der", "Das", "Alle",
    "Unsere", "Diese", "Nur",
})
_NEGATION_BEFORE_RE = re.compile(r"\b(?:no|not|never|nicht|nie|keine?[mnrs]?)\s+(?:\S+\s+)?$", _I)
_AUTHORITATIVE_RE = re.compile(r"\bauthoritative\b", _I)
# "authoritative" naming who rates it ("… according to the Federal Register").
_AUTHORITATIVE_QUALIFIER_RE = re.compile(
    r"^[^.!?\n]{0,60}?\b(?:according\s+to|as\s+(?:rated|assessed|classified|ranked|designated)\s+by|"
    r"(?:rated|assessed|classified|ranked|designated|recogni[sz]ed)\s+(?:as\s+\S+\s+)?by|laut|gemäß)\s+\S", _I)
# Tone/style descriptors ("Technical, authoritative, developer-native tone.").
_AUTHORITATIVE_TONE_AFTER_RE = re.compile(
    r"^(?:\s*,\s*[\w-]+|\s+(?:and|but|yet|or)\s+[\w-]+)*\s*,?\s+(?:tone|style|register|manner|wording|"
    r"writing|delivery|tone\s+of\s+voice)\b", _I)
_AUTHORITATIVE_TONE_BEFORE_RE = re.compile(r"\b(?:tone|style|register|voice\s*:)[^.!?\n]{0,60}$", _I)
# Fields that describe style, e.g. identity.emotional_resonance.tone_of_voice.
_TONE_FIELD_RE = re.compile(r"tone|style|voice", _I)


def _last_key(path: str) -> str:
    """Last member name of a JSON path ("$.a.tone_of_voice[0]" → "tone_of_voice")."""
    path = re.sub(r"(?:\[\d+\])+$", "", path)
    m = re.search(r"\.([A-Za-z_][A-Za-z0-9_]*)$|\[(\"(?:[^\"\\]|\\.)*\")\]$", path)
    if not m:
        return ""
    return m.group(1) if m.group(1) is not None else m.group(2)


# DNS terminology ("authoritative name server").
_AUTHORITATIVE_DNS_RE = re.compile(r"^\s+(?:dns|name[\s-]?servers?|nameservers?|zones?|servers?|resolvers?)\b", _I)
_GERMAN_AGENT_BEFORE_RE = re.compile(r"\b(?:von|vom|durch|beim|bei|laut|gegen|im|am)\b[^.!?\n]*$", _I)
_INVISIBLE_RE = re.compile("[\u200b\u2060-\u2064\ufeff\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f]")
_ARP_NAME_RE = re.compile(r"\bARP\b|\bAgentic\s+Reasoning\s+Protocol\b")
_ARP_STANDARD_RE = re.compile(
    r"\b(?:is|as|an?)\s+(?:an?\s+)?(?:(?:open|new|official|internet|web|ietf|global)\s+)+standard\b"
    r"|\bIETF[\s-]+Standard\b|\bInternet[\s-]?[Ss]tandard\b", _I)
_URL_ONLY_RE = re.compile(r"^\s*https?://\S+\s*$")
_SIGNATURE_WORD_RE = re.compile(r"\bsign(?:s|ed|ing|ature|atures)?\b|\bsigniert\b|\bSignatur(?:en)?\b", _I)
_PROVENANCE_TEMPLATE_RE = re.compile(
    r"^This file is (?P<entity>.+)'s own description of itself, published by (?P<publisher>.+) at "
    r"(?P<domain>[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9])\. The statements are self-attested; where available, "
    r"independent evidence is linked in evidence_url\.$")


def _excerpt(text: str, start: int, end: int, context: int = 30) -> str:
    a, b = max(0, start - context), min(len(text), end + context)
    snippet = text[a:b].replace("\n", " ")
    return ("…" if a > 0 else "") + snippet + ("…" if b < len(text) else "")


def _lint_text(path: str, text: str) -> List[LintFinding]:
    findings: List[LintFinding] = []
    if _URL_ONLY_RE.match(text):
        return findings
    spans: Dict[str, List[Tuple[int, int]]] = {}
    for severity, rule, regex, message in _TEXT_RULES:
        m = regex.search(text)
        if not m:
            continue
        # One finding per rule and text passage: skip overlapping matches of the same rule.
        if any(m.start() < end and start < m.end() for start, end in spans.get(rule, [])):
            continue
        spans.setdefault(rule, []).append((m.start(), m.end()))
        findings.append(LintFinding(severity, rule, path, message, _excerpt(text, m.start(), m.end())))
    for m in _VERIFIED_RE.finditer(text):
        after, before_text = text[m.end():], text[max(0, m.start() - 60):m.start()]
        qualified = bool(_VERIFIED_QUALIFIER_RE.match(after)) and not _GENERIC_AGENT_AFTER_RE.match(after)
        generic_before = bool(_GENERIC_AGENT_BEFORE_RE.search(before_text))
        if not qualified and m.group(0).lower() in ("verifiziert", "geprüft"):
            # German word order names the checker before the participle ("vom TÜV geprüft").
            qualified = bool(_GERMAN_AGENT_BEFORE_RE.search(before_text)) and not generic_before
        if not qualified and not generic_before:
            # A proper name right before names the checker ("Google My Business verified").
            before = _PROPER_BEFORE_RE.search(before_text)
            qualified = bool(before) and before.group(1).split()[0] not in _GENERIC_STARTERS
        if not qualified and _NEGATION_BEFORE_RE.search(text[max(0, m.start() - 40):m.start()]):
            qualified = True  # "no verified adoption" claims nothing
        if not qualified:
            findings.append(LintFinding(
                "error", "ARP-W/unsourced-authority", path,
                "'verified' without saying who checked what (e.g. 'verified by …', 'checked against …').",
                _excerpt(text, m.start(), m.end())))
            break
    for m in _AUTHORITATIVE_RE.finditer(text):
        after, before = text[m.end():], text[max(0, m.start() - 60):m.start()]
        if _TONE_FIELD_RE.search(_last_key(path)) or _AUTHORITATIVE_QUALIFIER_RE.match(after) \
                or _AUTHORITATIVE_TONE_AFTER_RE.match(after) or _AUTHORITATIVE_TONE_BEFORE_RE.search(before) \
                or _AUTHORITATIVE_DNS_RE.match(after) or _NEGATION_BEFORE_RE.search(before[-40:]):
            continue
        findings.append(LintFinding(
            "error", "ARP-W/unsourced-authority", path,
            "'authoritative' without saying who rates it so. State the fact and link evidence "
            "(a tone descriptor such as 'authoritative tone' is fine).",
            _excerpt(text, m.start(), m.end())))
        break
    m = _INVISIBLE_RE.search(text)
    if m:
        findings.append(LintFinding(
            "error", "ARP-W/hidden-text", path,
            f"Invisible Unicode character U+{ord(m.group(0)):04X}. Text must be the same for people and bots.",
            _excerpt(text, m.start(), m.end()).replace(m.group(0), f"<U+{ord(m.group(0)):04X}>")))
    if _ARP_NAME_RE.search(text):
        m = _ARP_STANDARD_RE.search(text)
        if m:
            findings.append(LintFinding(
                "warning", "ARP-W/terms", path,
                "ARP is described as a standard. ARP is a single-author draft, not a standard or IETF standard.",
                _excerpt(text, m.start(), m.end())))
    return findings


def _lint_provenance(manifest: Dict[str, Any]) -> List[LintFinding]:
    findings: List[LintFinding] = []
    v13 = _is_v13_or_later(manifest)
    prov = manifest.get("provenance")
    if prov is None:
        findings.append(LintFinding(
            "error" if v13 else "warning", "ARP-P/missing", "$.provenance",
            "provenance is missing (REQUIRED in ARP v1.3): statement, publisher, publisher_url, published."))
        return findings
    if not isinstance(prov, dict):
        findings.append(LintFinding("error", "ARP-P/type", "$.provenance", "provenance must be an object."))
        return findings
    for field in ("statement", "publisher", "publisher_url", "published"):
        if not isinstance(prov.get(field), str) or not prov.get(field):
            findings.append(LintFinding("error", "ARP-P/field", f"$.provenance.{field}",
                                        f"provenance.{field} is missing or empty."))
    published = prov.get("published")
    if isinstance(published, str) and published and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", published):
        findings.append(LintFinding("error", "ARP-P/field", "$.provenance.published",
                                    "provenance.published must be a date (YYYY-MM-DD).", published))
    url = prov.get("publisher_url")
    if isinstance(url, str) and url and not url.startswith("https://"):
        findings.append(LintFinding("error", "ARP-P/field", "$.provenance.publisher_url",
                                    "provenance.publisher_url must be an https:// URL (legal notice).", url))
    statement = prov.get("statement")
    if isinstance(statement, str) and statement:
        m = _SIGNATURE_WORD_RE.search(statement)
        if m:
            findings.append(LintFinding(
                "error", "ARP-P/no-signature", "$.provenance.statement",
                "provenance.statement must not mention a signature (identical in signed and unsigned files).",
                _excerpt(statement, m.start(), m.end())))
        # SPEC §4.1: the statement MUST follow the template (error in v1.3).
        sev = "error" if v13 else "warning"
        t = _PROVENANCE_TEMPLATE_RE.fullmatch(statement)
        if not t:
            findings.append(LintFinding(
                sev, "ARP-P/template", "$.provenance.statement",
                "provenance.statement differs from the fixed template: \"This file is {ENTITY}'s own description "
                "of itself, published by {PUBLISHER} at {DOMAIN}. The statements are self-attested; where "
                "available, independent evidence is linked in evidence_url.\""))
        else:
            for group, expected in (("entity", manifest.get("entity")),
                                    ("publisher", prov.get("publisher")),
                                    ("domain", manifest.get("domain"))):
                if isinstance(expected, str) and t.group(group) != expected:
                    findings.append(LintFinding(
                        sev, "ARP-P/template", "$.provenance.statement",
                        f"provenance.statement names {group} '{t.group(group)}', the file says '{expected}'."))
    return findings


def _lint_domain(manifest: Dict[str, Any]) -> List[LintFinding]:
    """domain is REQUIRED (SPEC §4); verifiers reject signed files without it."""
    domain = manifest.get("domain")
    signed = "_arp_signature" in manifest
    if not isinstance(domain, str) or not domain.strip():
        sev = "error" if (signed or _is_v13_or_later(manifest)) else "warning"
        return [LintFinding(sev, "ARP/domain-missing", "$.domain",
                            "domain is missing or not a string (REQUIRED, SPEC §4). Verifiers report signed "
                            "files without it as INVALID (domain_missing).")]
    normalized = normalize_domain_safe(domain)
    if normalized is None:
        return [LintFinding("error", "ARP/domain-format", "$.domain",
                            "domain must be a bare domain name such as example.com (no scheme, path or port).",
                            domain)]
    if normalized != domain:
        return [LintFinding("error", "ARP/domain-format", "$.domain",
                            f"domain must be written in lowercase without a trailing dot: '{normalized}'.",
                            domain)]
    return []


def _lint_signature_block(manifest: Dict[str, Any]) -> List[LintFinding]:
    findings: List[LintFinding] = []
    sig = manifest.get("_arp_signature")
    if sig is None:
        return findings
    if not isinstance(sig, dict):
        return [LintFinding("error", "ARP-S/type", "$._arp_signature", "_arp_signature must be an object.")]
    v13 = _is_v13_or_later(manifest)
    sev = "error" if v13 else "warning"
    if "statement" not in sig:
        findings.append(LintFinding(sev, "ARP-S/statement", "$._arp_signature.statement",
                                    "_arp_signature.statement is missing (REQUIRED in ARP v1.3; re-sign with arp_cli v1.4)."))
    if not isinstance(sig.get("verify"), dict):
        findings.append(LintFinding(sev, "ARP-S/verify", "$._arp_signature.verify",
                                    "_arp_signature.verify is missing (REQUIRED in ARP v1.3; re-sign with arp_cli v1.4)."))
    signature = sig.get("signature")
    if isinstance(signature, str) and signature != "":
        try:
            decode_signature_strict(signature)
        except ValueError as e:
            findings.append(LintFinding("error", "ARP-S/signature-format", "$._arp_signature.signature",
                                        f"{e} (SPEC §13.3).", safe_text(signature, 120)))
    domain = normalize_domain_safe(manifest.get("domain"))
    selector = sig.get("dns_selector", "arp")
    if normalize_selector_safe(selector) is None:
        findings.append(LintFinding("error", "ARP-S/selector", "$._arp_signature.dns_selector",
                                    "dns_selector must consist of DNS labels of [A-Za-z0-9_-] that begin and end "
                                    "with a letter or digit, separated by single dots (at most 50 characters; "
                                    "SPEC §13.3).", safe_text(selector)))
        return findings
    if domain is None:
        return findings
    dns_name = dns_name_for(selector, domain)
    # SPEC §13.3: statement MUST follow the template; verify holds fixed values.
    if isinstance(sig.get("statement"), str):
        expected = signature_statement_for(domain, selector)
        if sig["statement"] != expected:
            findings.append(LintFinding(sev, "ARP-S/statement", "$._arp_signature.statement",
                                        f"_arp_signature.statement differs from the fixed template: \"{expected}\""))
    declared = sig.get("dns_record")
    if declared is not None and not _same_dns_name(declared, dns_name):
        findings.append(LintFinding(sev, "ARP-S/dns-record", "$._arp_signature.dns_record",
                                    f"dns_record must be '{dns_name}' (dns_selector + domain).", safe_text(declared)))
    verify = sig.get("verify")
    if isinstance(verify, dict):
        name = verify.get("dns_name")
        if not _same_dns_name(name, dns_name):
            findings.append(LintFinding(sev, "ARP-S/verify", "$._arp_signature.verify.dns_name",
                                        f"verify.dns_name must be '{dns_name}'.", safe_text(name)))
        doh = verify.get("doh_url")
        if not _doh_url_names(doh, dns_name):
            findings.append(LintFinding(sev, "ARP-S/verify", "$._arp_signature.verify.doh_url",
                                        f"verify.doh_url must be an https:// DNS-over-HTTPS URL for {dns_name}, "
                                        f"e.g. {doh_url_for(dns_name)}", safe_text(doh)))
        if verify.get("spec") != SPEC_SIGNATURE_URL:
            findings.append(LintFinding(sev, "ARP-S/verify", "$._arp_signature.verify.spec",
                                        f"verify.spec must be {SPEC_SIGNATURE_URL}", safe_text(verify.get("spec"))))
    return findings


def normalize_selector_safe(value: Any) -> Optional[str]:
    try:
        return validate_selector(value)
    except ValueError:
        return None


def _doh_url_names(doh: Any, dns_name: str) -> bool:
    """True if doh is an https URL whose name= parameter is dns_name (SPEC §13.3)."""
    if not isinstance(doh, str) or not doh.startswith("https://") or _UNSAFE_URL_CHAR_RE.search(doh):
        return False
    names = parse_qs(urlsplit(doh).query).get("name", [])
    return len(names) == 1 and _same_dns_name(names[0], dns_name)


def _lint_representations(manifest: Dict[str, Any]) -> List[LintFinding]:
    reps = manifest.get("representations")
    if reps is None:
        if _is_v13_or_later(manifest):
            return [LintFinding("warning", "ARP-R/missing", "$.representations",
                                "representations is missing (RECOMMENDED in ARP v1.3: reasoning.md with sha256).")]
        return []
    if not isinstance(reps, list) or not reps:
        return [LintFinding("error", "ARP-R/type", "$.representations", "representations must be a non-empty array.")]
    findings: List[LintFinding] = []
    domain = normalize_domain_safe(manifest.get("domain"))
    for i, entry in enumerate(reps):
        p = f"$.representations[{i}]"
        if not isinstance(entry, dict):
            findings.append(LintFinding("error", "ARP-R/type", p, "representation entries must be objects."))
            continue
        href = entry.get("href")
        if not isinstance(href, str) or not href.startswith("https://"):
            findings.append(LintFinding("error", "ARP-R/field", p + ".href", "href must be an absolute https:// URL."))
        else:
            # SPEC §13.12: on the manifest's domain; verifiers fetch nothing else.
            try:
                host, path = representation_target(href)
            except ValueError as e:
                findings.append(LintFinding("error", "ARP-R/field", p + ".href", f"{e}.", safe_text(href)))
            else:
                if domain is not None and host != domain:
                    findings.append(LintFinding("error", "ARP-R/field", p + ".href",
                                                f"href must be on the manifest's domain {domain} (SPEC §13.12).",
                                                safe_text(href)))
                if entry.get("media_type") == MARKDOWN_MEDIA_TYPE and path != MARKDOWN_PATH:
                    findings.append(LintFinding("error", "ARP-R/field", p + ".href",
                                                f"the text/markdown representation lives at {MARKDOWN_PATH}.",
                                                safe_text(href)))
        if not entry.get("media_type"):
            findings.append(LintFinding("error", "ARP-R/field", p + ".media_type", "media_type is missing."))
        if not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", ""))):
            findings.append(LintFinding("error", "ARP-R/field", p + ".sha256",
                                        "sha256 must be 64 lowercase hex characters."))
    return findings


def lint_manifest(manifest: Any) -> List[LintFinding]:
    """Check a parsed reasoning.json against the Wording Profile (ARP-W, K1).

    Checks every member name and every string value at every depth, plus the
    provenance block (ARP-P), the signature fields (ARP-S), representations
    (ARP-R), the domain field, control characters and line breaks that would
    change the structure of reasoning.md, top-level members that would
    imitate its "## Verification" section, the signature statement outside
    _arp_signature, and values outside I-JSON. Errors are MUST-NOT
    violations (sign refuses to sign them); warnings are heuristics.
    Not checkable here: whether bots and people get different content, and
    duplicate member names (only visible in the text: lint_manifest_text).

    Returns the findings, errors first, in document order.
    """
    if not isinstance(manifest, dict):
        return [LintFinding("error", "ARP/type", "$", "reasoning.json must be a JSON object.")]
    findings: List[LintFinding] = []
    for path, problem in ijson_problems(manifest):
        findings.append(LintFinding("error", "ARP/non-ijson", path,
                                    f"Not I-JSON (RFC 7493): {problem}. Such files cannot be signed (RFC 8785)."))
    non_ijson_paths = {f.path for f in findings}
    v13 = _is_v13_or_later(manifest)
    for kind, path, value in _walk(manifest):
        if path in non_ijson_paths:
            continue
        if kind == "key":
            tokens = set(_key_tokens(value))
            if value.lower() in _FORBIDDEN_KEYS or tokens & _FORBIDDEN_KEY_TOKENS:
                findings.append(LintFinding(
                    "error", "ARP-W/field-name", path,
                    f"Field name '{safe_text(value, 80)}' is reserved for instruction-style content and not "
                    "allowed (system_instruction, reasoning_directives, ai_directive, agent_directive, "
                    "instruction(s), directive(s)).", value))
            findings.extend(_lint_key_authority(path, value, v13))
            if _ARRAY_INDEX_KEY_RE.fullmatch(value):
                findings.append(LintFinding(
                    "warning", "ARP-R/numeric-key", path,
                    f"Member name '{safe_text(value, 20)}' consists of digits only. JavaScript objects list such "
                    "names first, so a JavaScript renderer that does not keep the file order produces different "
                    "reasoning.md bytes (SPEC §13.12.1 requires the file order).", value))
            findings.extend(_lint_line_breaks(path, value, "member name", v13))
        else:
            findings.extend(_lint_line_breaks(path, value, "string", v13))
            if path in ('$["$schema"]', "$._arp_signature.signature"):
                continue
            findings.extend(_lint_text(path, value))
            if not (path == "$._arp_signature" or path.startswith(("$._arp_signature.", "$._arp_signature["))):
                m = _SIGNATURE_STATEMENT_RE.search(value)
                if m:
                    findings.append(LintFinding(
                        "error", "ARP-S/statement-outside", path,
                        "The signature statement ('Signed with Ed25519 by the operator of …') appears outside "
                        "_arp_signature. "
                        "Only the signer writes it, inside _arp_signature (SPEC §13.3); elsewhere it would claim "
                        "a signature the file may not have.", _excerpt(value, m.start(), m.end())))
    findings.extend(_lint_reserved_sections(manifest, v13))
    findings.extend(_lint_domain(manifest))
    findings.extend(_lint_provenance(manifest))
    findings.extend(_lint_signature_block(manifest))
    findings.extend(_lint_representations(manifest))
    if not non_ijson_paths and len(json.dumps(manifest, ensure_ascii=False).encode("utf-8")) > 100 * 1024:
        findings.append(LintFinding("warning", "ARP/size", "$", "File exceeds 100 KB (SPEC §2)."))
    order = {"error": 0, "warning": 1}
    return sorted(findings, key=lambda f: order.get(f.severity, 2))


_LINE_BREAK_RE = re.compile("\r\n|[\n\r\x0b\x0c\x85\u2028\u2029]")
# A continuation line that Markdown would read as structure (heading, list
# item, quote, fence) — e.g. a forged "## Verification" section in reasoning.md.
_MD_STRUCTURE_RE = re.compile(r"\s*(?:#|[-*+](?:\s|$)|\d+[.)](?:\s|$)|>|```|~~~|Manifest:)")


def _lint_line_breaks(path: str, value: str, what: str, v13: bool = False) -> List[LintFinding]:
    """Control characters and line breaks inside a value (SPEC §13.12.1:
    values are rendered unchanged into reasoning.md).

    v1.3: every control character U+0000–U+001F / U+007F–U+009F (line
    breaks and tabs included) is an error, as in schema v1.3. Older files:
    line breaks are a warning, other control characters a warning; a line
    break followed by Markdown structure is an error in every version.
    """
    findings: List[LintFinding] = []
    control = _CONTROL_CHAR_RE.search(value)
    lines = _LINE_BREAK_RE.split(value)
    if control and (v13 or not _LINE_BREAK_RE.fullmatch(control.group(0))):
        findings.append(LintFinding(
            "error" if v13 else "warning", "ARP-R/control-character", path,
            f"Control character U+{ord(control.group(0)):04X} inside a {what}. ARP v1.3 files contain no control "
            "characters in member names and strings, line breaks and tabs included (SPEC §13.12.1, schema v1.3); "
            "render-md and sign refuse them.",
            safe_text(_excerpt(value, control.start(), control.end()), 80)))
    if len(lines) == 1:
        return findings
    structural = [line for line in lines[1:] if _MD_STRUCTURE_RE.match(line)]
    if structural:
        findings.append(LintFinding(
            "error", "ARP-R/line-break", path,
            f"Line break inside a {what}, followed by a line that reads as Markdown structure. reasoning.md "
            "copies values unchanged, so the line would appear as a heading or list item of its own.",
            safe_text(structural[0], 80)))
    elif not findings:
        findings.append(LintFinding("warning", "ARP-R/line-break", path,
                                    f"Line break inside a {what} (SPEC §13.12.1: publishers avoid line breaks "
                                    "in values).", safe_text(lines[1], 80)))
    return findings


# Member names that state a check without saying who checked (SPEC §11.2
# item 5). verified_fact and last_verified are the historical exceptions.
_HISTORICAL_VERIFIED_KEYS = frozenset({"verified_fact", "last_verified"})
_AUTHORITY_KEY_RE = re.compile(r"verifiziert|geprüft|ground_?truth|trusted_?sources?", _I)


def _lint_key_authority(path: str, key: str, v13: bool) -> List[LintFinding]:
    if key in _HISTORICAL_VERIFIED_KEYS:
        return []
    tokens = _key_tokens(key)
    pairs = set(zip(tokens, tokens[1:]))
    if not ({"verified", "authoritative"} & set(tokens) or ("ground", "truth") in pairs
            or ("trusted", "source") in pairs or ("trusted", "sources") in pairs or _AUTHORITY_KEY_RE.search(key)):
        return []
    return [LintFinding(
        "error" if v13 else "warning", "ARP-W/unsourced-authority", path,
        f"Member name '{safe_text(key, 80)}' says that something was checked or is authoritative, but a name "
        "cannot say who checked what (SPEC §11.2 item 5; only verified_fact and last_verified are exempt).", key)]


# Top-level members defined by schema v1.3 (additionalProperties: false).
_V13_TOP_LEVEL = frozenset({
    "$schema", "protocol", "version", "domain", "entity", "provenance", "representations", "verification",
    "identity", "organization", "corrections", "entity_claims", "diagnostics", "authority", "content_policy",
    "_arp_signature",
})
# Names that JavaScript objects order before all other names (array indices).
_ARRAY_INDEX_KEY_RE = re.compile(r"0|[1-9][0-9]{0,9}")
# The opening of the fixed K3 statement ("Signed with Ed25519 by the operator
# of {DOMAIN}."): a claim that a named operator signed the file. General
# explanations of what a signature shows are not matched.
_SIGNATURE_STATEMENT_RE = re.compile(r"\bsigned\s+with\s+ed25519\s+by\s+the\s+operator\s+of\b", _I)


def _lint_reserved_sections(manifest: Dict[str, Any], v13: bool) -> List[LintFinding]:
    """Top-level members that would imitate the fixed "## Verification"
    section of reasoning.md, and members outside schema v1.3."""
    findings: List[LintFinding] = []
    for key in manifest:
        if not isinstance(key, str):
            continue
        path = _child_path("$", key)
        if key != "verification" and key.casefold() == "verification":
            findings.append(LintFinding(
                "error", "ARP-R/reserved-section", path,
                f"Top-level member '{safe_text(key, 40)}' would render as '## {safe_text(key, 40)}', a heading that "
                "imitates the fixed final section '## Verification' of reasoning.md. The review metadata member "
                "is spelled 'verification' (SPEC §5); render-md and sign refuse this name.", key))
        elif v13 and key not in _V13_TOP_LEVEL:
            findings.append(LintFinding(
                "warning", "ARP/unknown-member", path,
                f"Top-level member '{safe_text(key, 40)}' is not defined in ARP v1.3 (schema v1.3 allows no other "
                "top-level members); reasoning.md renders it as a section of its own.", key))
    verification = manifest.get("verification")
    if verification is not None and not isinstance(verification, dict):
        findings.append(LintFinding(
            "error", "ARP-R/reserved-section", "$.verification",
            "verification must be an object (SPEC §5: audited_by, last_verified, next_audit). Other values "
            "render as list items under '## verification' that can imitate the signature lines of reasoning.md."))
    elif isinstance(verification, dict):
        for key in verification:
            if isinstance(key, str) and key.casefold() in _VERIFICATION_LABELS:
                findings.append(LintFinding(
                    "error", "ARP-R/reserved-section", _child_path("$.verification", key),
                    f"verification.{safe_text(key, 40)} imitates a line of the fixed final section "
                    "'## Verification' of reasoning.md (manifest URL and signature pointers). SPEC §5 defines "
                    "audited_by, last_verified, next_audit.", key))
    return findings


def lint_manifest_text(text: str) -> List[LintFinding]:
    """lint_manifest() for the raw text of a reasoning.json.

    Adds what only the text shows: duplicate member names (I-JSON, RFC 7493
    §2.3). Raises ManifestParseError if the text is not JSON at all or
    contains NaN/Infinity.
    """
    data, duplicates = _parse_json_collecting(text)
    findings = [LintFinding("error", "ARP/duplicate-member", path,
                            f"Member name '{safe_text(name, 80)}' occurs more than once in this object. Parsers keep "
                            "the last value, readers of the text see the first (I-JSON, RFC 7493 §2.3).", name)
                for path, name in duplicates]
    findings.extend(lint_manifest(data))
    order = {"error": 0, "warning": 1}
    return sorted(findings, key=lambda f: order.get(f.severity, 2))


_MD_TITLE_RE = re.compile(r"# .+ — self-description \(ARP\)")
_MD_VERIFICATION_HEADING = "## Verification"
# Domains that documentation uses in examples of the statement.
_EXAMPLE_DOMAIN_RE = re.compile(r"(?:[\w-]+\.)*example(?:\.(?:com|org|net))?|yourdomain\.com|.*[{}$<>].*", _I)
_STATEMENT_DOMAIN_RE = re.compile(r"\boperator\s+of\s+(\S+?)\.?(?:\s|$)", _I)


def lint_text_document(text: str) -> List[LintFinding]:
    """Wording Profile check for derived texts (reasoning.md, llms.txt, HTML mirrors).

    Applies the text rules line by line; the path is "line N". HTML comments
    are not reported here (they are normal in HTML files), but AI-directed
    wording inside them is.

    A text whose first line is "# … — self-description (ARP)" is read as a
    reasoning.md: it has at most one "## Verification" heading, as the last
    section, and the signature statement only in that section. In other
    texts the signature statement is an error (K5: the signature status is
    stated only in the manifest and in reasoning.md), unless it names an
    example domain (example.com, yourdomain.com, a placeholder), as
    documentation does.
    """
    findings: List[LintFinding] = []
    lines = text.splitlines()
    is_reasoning_md = bool(lines) and bool(_MD_TITLE_RE.fullmatch(lines[0]))
    headings = [i for i, line in enumerate(lines) if line.startswith("## ")]
    final_section = None
    if is_reasoning_md:
        for i in headings:
            name = lines[i].rstrip()
            if name.casefold() != _MD_VERIFICATION_HEADING.casefold() or name == "## verification":
                continue
            if name != _MD_VERIFICATION_HEADING or i != headings[-1]:
                findings.append(LintFinding(
                    "error", "ARP-R/reserved-section", f"line {i + 1}",
                    "Heading imitates the fixed final section '## Verification'. reasoning.md has exactly one, "
                    "as its last section (SPEC §13.12.1).", safe_text(lines[i], 80)))
        if headings and lines[headings[-1]].rstrip() == _MD_VERIFICATION_HEADING:
            final_section = headings[-1]
    for number, line in enumerate(lines, 1):
        for f in _lint_text(f"line {number}", line):
            if f.rule != "ARP-W/html-comment":
                findings.append(f)
        m = _SIGNATURE_STATEMENT_RE.search(line)
        if not m:
            continue
        if is_reasoning_md:
            if final_section is not None and number - 1 > final_section and line.startswith("- statement: "):
                continue
            message = ("The signature statement appears outside the final '## Verification' section of "
                       "reasoning.md; only that section carries it (SPEC §13.12.1).")
        else:
            named = _STATEMENT_DOMAIN_RE.search(line[m.start():])
            if named and _EXAMPLE_DOMAIN_RE.fullmatch(named.group(1)):
                continue
            message = ("Signature statement in a discovery or mirror text. The signature status is stated only in "
                       "the manifest and in reasoning.md (K5, SPEC §2.4).")
        findings.append(LintFinding("error", "ARP-S/statement-outside", f"line {number}", message,
                                    _excerpt(line, m.start(), m.end())))
    order = {"error": 0, "warning": 1}
    return sorted(findings, key=lambda f: order.get(f.severity, 2))


# ─────────────────────────────────────────────
# DNS key records (SPEC §13.5, revocation K6)
# ─────────────────────────────────────────────

class DNSNoRecord(Exception):
    """NXDOMAIN or no TXT record at the name."""


class DNSLookupError(Exception):
    """Lookup failed for other reasons (timeout, SERVFAIL, missing dnspython)."""


def resolve_txt(name: str) -> List[str]:
    """Return all TXT values at name (multi-string records joined).

    Raises DNSNoRecord or DNSLookupError. Tests replace this function.
    """
    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        raise DNSLookupError("dnspython is missing: pip install dnspython "
                             "(or use --pubkey for offline verification)")
    try:
        answers = dns.resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
        raise DNSNoRecord(str(e))
    except dns.exception.DNSException as e:
        raise DNSLookupError(str(e) or e.__class__.__name__)
    values = []
    for rdata in answers:
        values.append(b"".join(rdata.strings).decode("utf-8", "replace"))
    return values


def _arp_tag_pairs(txt: str) -> Tuple[List[Tuple[str, str]], List[str]]:
    """Split a TXT value into (lowercased tag name, value) pairs, keeping duplicates."""
    pairs: List[Tuple[str, str]] = []
    warnings: List[str] = []
    for segment in txt.split(";"):
        segment = segment.strip()
        if not segment or "=" not in segment:
            continue
        name, value = segment.split("=", 1)
        name = name.strip()
        if name != name.lower():
            warnings.append(f"DNS record tag '{safe_text(name, 20)}=' should be lowercase.")
        pairs.append((name.lower(), value.strip()))
    return pairs, warnings


def parse_arp_txt(txt: str) -> Tuple[Optional[Dict[str, str]], List[str]]:
    """Parse "v=ARP1; k=ed25519; p=<base64>".

    Returns (tags, warnings), or (None, []) if the record is not an ARP1
    record. The version value is compared case-insensitively ("v=arp1" is
    accepted with a warning); tag names are read case-insensitively. If a
    tag occurs twice, tags holds the last value; keys_from_txt_records()
    treats such records as malformed (cf. DKIM, RFC 6376 §3.2).
    """
    pairs, warnings = _arp_tag_pairs(txt)
    tags = dict(pairs)
    version = tags.get("v")
    if version is None or version.upper() != "ARP1":
        return None, []
    if version != "ARP1":
        warnings.append(f"DNS record uses 'v={safe_text(version, 20)}'; SPEC §13.5 specifies 'v=ARP1'. "
                        "Read tolerantly; the record should be corrected.")
    return tags, warnings


def keys_from_txt_records(records: List[str]) -> Dict[str, Any]:
    """Interpret the TXT records at a key name.

    Returns {"status", "public_keys", "record", "warnings", "detail"} with
    status one of: ok, revoked, no_record, malformed, unsupported_algorithm.
    An empty p= value means revoked (K6, analogous to DKIM RFC 6376 §3.6.1);
    if any ARP1 record at the name is revoked, the key counts as revoked.
    """
    result: Dict[str, Any] = {"status": "no_record", "public_keys": [], "record": None,
                              "warnings": [], "detail": ""}
    arp_records = []
    for txt in records:
        tags, warnings = parse_arp_txt(txt)
        if tags is not None:
            arp_records.append((txt, tags, _arp_tag_pairs(txt)[0]))
            result["warnings"].extend(warnings)
    if not arp_records:
        result["detail"] = "no v=ARP1 TXT record"
        return result
    if len(arp_records) > 1:
        result["warnings"].append("Several ARP1 records at the same name; each key is tried.")
    # Revocation first: any empty p= at the name revokes, also next to a
    # second p= in the same record.
    for txt, tags, pairs in arp_records:
        if any(name == "p" and re.sub(r"\s+", "", value) == "" for name, value in pairs):
            result.update(status="revoked", record=txt, detail="p= is empty: key revoked")
            return result
    for txt, tags, pairs in arp_records:
        result["record"] = txt
        names = [name for name, _ in pairs]
        repeated = sorted({name for name in names if names.count(name) > 1})
        if repeated:
            result.update(status="malformed", detail=f"tag(s) {', '.join(repeated)} repeated in one record")
            continue
        algo = tags.get("k")
        if algo is None:
            result["warnings"].append("DNS record has no k= tag; ed25519 assumed (SPEC §13.5 requires k=ed25519).")
            algo = "ed25519"
        if algo.lower() != "ed25519":
            result.update(status="unsupported_algorithm", detail=f"k={algo} (expected ed25519)")
            continue
        if algo != "ed25519":
            result["warnings"].append(f"DNS record uses 'k={algo}'; SPEC §13.5 specifies 'k=ed25519'.")
        if "p" not in tags:
            result.update(status="malformed", detail="p= tag missing")
            continue
        try:
            _require_deps("cryptography")
            raw, key_warnings = decode_dns_public_key(tags["p"])
            key = Ed25519PublicKey.from_public_bytes(raw)
        except ARPDependencyError:
            raise
        except Exception as e:
            result.update(status="malformed", detail=f"public key not decodable: {e}")
            continue
        result["warnings"].extend(key_warnings)
        result["public_keys"].append(key)
    if result["public_keys"]:
        result["status"] = "ok"
        result["detail"] = ""
    return result


# ─────────────────────────────────────────────
# Verification (Enveloped Pattern, SPEC §13.4)
# ─────────────────────────────────────────────

def _parse_utc(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _verify_with_keys(keys: List[Any], signature: bytes, message: bytes) -> bool:
    for key in keys:
        try:
            key.verify(signature, message)
            return True
        except InvalidSignature:
            continue
    return False


def _verify_signature(public_key, data: dict, sig_block: dict) -> str:
    """
    Verify the signature. Returns 'enveloped' or raises InvalidSignature.

    Only the normative Enveloped Pattern (SPEC §13.4) is accepted:
    set signature to "", canonicalize the ENTIRE object.

    The legacy payload-only pattern (CLI ≤1.2) was REMOVED in v1.3.1.
    Reason: in that pattern the _arp_signature metadata (expires_at,
    dns_selector, algorithm) is NOT covered by the signature, so an
    attacker could extend validity or redirect the DNS selector at will
    while the file still verified. Files signed with CLI ≤1.2 must be
    re-signed.
    """
    try:
        signature_bytes = decode_signature_strict(sig_block["signature"])
    except ValueError as e:
        raise InvalidSignature(f"Malformed signature value: {e}")
    enveloped_data = copy.deepcopy(data)
    enveloped_data["_arp_signature"]["signature"] = ""
    if _verify_with_keys([public_key], signature_bytes, _canonical_bytes(enveloped_data)):
        return "enveloped"
    raise InvalidSignature(
        "Enveloped signature verification failed (SPEC §13.4). "
        "If this file was signed with CLI <= 1.2 (payload-only pattern), "
        "re-sign it with CLI v1.4+ or the Browser Signer — the legacy "
        "pattern is no longer accepted (it left the signature metadata "
        "unprotected)."
    )


def _diagnose_failure(keys: List[Any], data: dict, signature: bytes) -> str:
    """Explain a failed enveloped check. Never turns a failure into success."""
    legacy = copy.deepcopy(data)
    legacy.pop("_arp_signature", None)
    if _verify_with_keys(keys, signature, _canonical_bytes(legacy)):
        return "legacy_payload_only"
    removed = copy.deepcopy(data)
    removed["_arp_signature"].pop("signature", None)
    if _verify_with_keys(keys, signature, _canonical_bytes(removed)):
        return "signature_field_removed"
    return "signature_mismatch"


def new_verify_result(domain: Optional[str] = None) -> Dict[str, Any]:
    """Empty result dict of verify_manifest() (all keys present)."""
    return {
        "status": None, "reason": None, "domain": domain, "dns_name": None,
        "selector": None, "signed_at": None, "expires_at": None, "expired": False,
        "method": None, "warnings": [], "detail": "",
    }


def _same_dns_name(value: Any, expected: str) -> bool:
    """DNS names compare case-insensitively, a trailing dot does not count."""
    return isinstance(value, str) and value.strip().lower().rstrip(".") == expected.lower().rstrip(".")


def verify_manifest(manifest: Any, *, domain: Optional[str] = None, public_key: Any = None,
                    resolver: Optional[Callable[[str], List[str]]] = None,
                    now: Optional[datetime] = None) -> Dict[str, Any]:
    """Verify a parsed reasoning.json. Performs no file or HTTP access.

    The caller parses the file strictly (parse_manifest_bytes, or
    verify_manifest_bytes for raw bytes): duplicate member names are only
    visible in the text and cannot be detected here.

    Args:
        manifest:   parsed reasoning.json.
        domain:     retrieval domain (host of the URL, or --domain for local
                    files). The DNS name is always built from this domain and
                    dns_selector, never from dns_record.
        public_key: Ed25519PublicKey for offline checks (skips DNS).
        resolver:   function name -> list of TXT strings (default resolve_txt).
        now:        reference time (default: current UTC time).

    Returns a dict with status (CRYPTOGRAPHIC / UNSIGNED / INVALID / ERROR),
    reason, domain, dns_name, selector, signed_at, expires_at, expired,
    warnings, method.
    """
    resolver = resolver or resolve_txt
    now = now or datetime.now(timezone.utc)
    if isinstance(domain, str):
        domain = domain.strip().lower().rstrip(".") or None
    result = new_verify_result(domain)

    def done(status: str, reason: str, detail: str = "") -> Dict[str, Any]:
        result.update(status=status, reason=reason, detail=detail)
        return result

    if not isinstance(manifest, dict):
        return done(STATUS_ERROR, "not_an_object", "reasoning.json must be a JSON object")

    problems = ijson_problems(manifest)
    if problems:
        return done(TRUST_INVALID, "non_ijson", f"{problems[0][1]} at {safe_text(problems[0][0], 120)} "
                                               "(I-JSON, RFC 7493; not canonicalizable by RFC 8785)")

    sig = manifest.get("_arp_signature")
    payload_domain = manifest.get("domain")
    if sig and (not isinstance(payload_domain, str) or not payload_domain.strip()):
        # SPEC §4 / §13.7: CRYPTOGRAPHIC requires a domain matching the retrieval
        # domain. Without it a signed file could be presented under any domain
        # that publishes the same key.
        return done(TRUST_INVALID, "domain_missing",
                    "signed file has no 'domain' string (REQUIRED, SPEC §4)")
    if domain and isinstance(payload_domain, str) \
            and payload_domain.strip().lower().rstrip(".") != domain:
        detail = (f"payload field domain '{safe_text(payload_domain, 120)}' differs from the retrieval domain "
                  f"'{domain}' (SPEC §4)")
        if sig:
            return done(TRUST_INVALID, "domain_mismatch", detail)
        result["warnings"].append(detail)

    if not sig:
        return done(TRUST_UNSIGNED, "unsigned")
    if not isinstance(sig, dict):
        return done(TRUST_INVALID, "malformed_signature_block", "_arp_signature is not an object")

    result["signed_at"] = sig.get("signed_at")
    result["expires_at"] = sig.get("expires_at")

    if sig.get("algorithm") != "Ed25519":
        return done(TRUST_INVALID, "unsupported_algorithm", f"algorithm {safe_text(repr(sig.get('algorithm')), 60)}")
    if sig.get("canonicalization") != "jcs-rfc8785":
        return done(TRUST_INVALID, "unsupported_canonicalization",
                    f"canonicalization {safe_text(repr(sig.get('canonicalization')), 60)}")
    if not isinstance(sig.get("signature"), str) or not sig["signature"]:
        return done(TRUST_INVALID, "malformed_signature", "signature value missing")
    try:
        signature = decode_signature_strict(sig["signature"])
    except ValueError as e:
        return done(TRUST_INVALID, "malformed_signature", str(e))

    expires = _parse_utc(sig.get("expires_at"))
    if expires is None:
        return done(TRUST_INVALID, "malformed_metadata", "expires_at missing or not an ISO 8601 timestamp")
    result["expired"] = now > expires
    signed = _parse_utc(sig.get("signed_at"))
    if signed is not None and signed > now + timedelta(minutes=5):
        result["warnings"].append(f"signed_at lies in the future ({safe_text(sig.get('signed_at'), 40)}).")

    selector = sig.get("dns_selector") or "arp"
    result["selector"] = selector
    try:
        validate_selector(selector)
    except ValueError as e:
        return done(TRUST_INVALID, "malformed_metadata", str(e))

    # Consistency of the signed pointers with the domain (SPEC §13.3).
    key_domain = domain or normalize_domain_safe(payload_domain)
    v13 = _is_v13_or_later(manifest)
    if v13 and ("statement" not in sig or not isinstance(sig.get("verify"), dict)):
        result["warnings"].append("ARP v1.3 requires _arp_signature.statement and .verify.")
    if key_domain:
        expected_name = dns_name_for(selector, key_domain)
        verify_block = sig.get("verify") if isinstance(sig.get("verify"), dict) else {}
        for field, value in (("dns_record", sig.get("dns_record")),
                             ("verify.dns_name", verify_block.get("dns_name"))):
            if value is None or _same_dns_name(value, expected_name):
                continue
            detail = (f"{field} '{safe_text(value, 120)}' differs from '{expected_name}' "
                      "(dns_selector + domain)")
            if v13:
                # In v1.3 these values are written by the signer from domain and
                # selector and covered by the signature: a different name means
                # the file was made for another domain.
                return done(TRUST_INVALID, "domain_mismatch", detail)
            result["warnings"].append(detail + "; the retrieval-derived name is used (informational).")
        if isinstance(sig.get("statement"), str) \
                and sig["statement"] != signature_statement_for(key_domain, selector):
            result["warnings"].append("_arp_signature.statement differs from the SPEC §13.3 template; the "
                                      "signature covers this text but does not check that it follows the template.")
        if verify_block:
            if not _doh_url_names(verify_block.get("doh_url"), expected_name):
                result["warnings"].append(f"verify.doh_url does not query {expected_name} over https.")
            if verify_block.get("spec") != SPEC_SIGNATURE_URL:
                result["warnings"].append(f"verify.spec differs from {SPEC_SIGNATURE_URL}.")

    if public_key is not None:
        keys = [public_key]
        result["method"] = "local_public_key"
    else:
        if not domain:
            return done(STATUS_ERROR, "no_domain",
                        "verification domain unknown: use a URL, --domain or --pubkey")
        dns_name = dns_name_for(selector, domain)
        result["dns_name"] = dns_name
        result["method"] = "dns"
        try:
            records = resolver(dns_name)
        except DNSNoRecord as e:
            return done(TRUST_INVALID, "dns_no_key", f"no TXT record at {dns_name} ({safe_text(e, 120)})")
        except DNSLookupError as e:
            return done(STATUS_ERROR, "dns_error", f"DNS lookup for {dns_name} failed: {safe_text(e, 120)}")
        info = keys_from_txt_records(records)
        result["warnings"].extend(info["warnings"])
        result["dns_txt"] = info["record"]
        if info["status"] == "revoked":
            return done(TRUST_INVALID, "key_revoked",
                        f"{dns_name} has an empty p= value: the domain operator revoked this key")
        if info["status"] == "no_record":
            return done(TRUST_INVALID, "dns_no_key", f"no v=ARP1 TXT record at {dns_name}")
        if info["status"] == "unsupported_algorithm":
            return done(TRUST_INVALID, "dns_unsupported_algorithm", info["detail"])
        if info["status"] != "ok":
            return done(TRUST_INVALID, "dns_key_malformed", info["detail"])
        keys = info["public_keys"]

    enveloped = copy.deepcopy(manifest)
    enveloped["_arp_signature"]["signature"] = ""
    try:
        if _verify_with_keys(keys, signature, _canonical_bytes(enveloped)):
            if result["expired"]:
                return done(TRUST_UNSIGNED, "expired", f"signature expired at {safe_text(sig.get('expires_at'), 40)}")
            result["meaning"] = LOCAL_KEY_MEANING if result["method"] == "local_public_key" \
                else CRYPTOGRAPHIC_MEANING
            return done(TRUST_CRYPTOGRAPHIC, "valid")
        return done(TRUST_INVALID, _diagnose_failure(keys, manifest, signature))
    except ARPDependencyError:
        raise
    except Exception as e:  # rfc8785 rejects values outside I-JSON
        return done(TRUST_INVALID, "non_ijson", f"not canonicalizable (RFC 8785): {type(e).__name__}")


def verify_manifest_bytes(raw: bytes, **kwargs: Any) -> Tuple[Optional[Any], Dict[str, Any]]:
    """Parse raw reasoning.json bytes strictly and verify them.

    Returns (parsed manifest or None, result). A file with duplicate member
    names or other non-I-JSON values is INVALID (duplicate_member /
    non_ijson); a file that is not JSON gives ERROR (load_failed).
    Keyword arguments as for verify_manifest().
    """
    try:
        data = parse_manifest_bytes(raw)
    except ManifestParseError as e:
        result = new_verify_result(kwargs.get("domain"))
        if e.reason in REJECTED_PARSE_REASONS:
            result.update(status=TRUST_INVALID, reason=e.reason, detail=str(e))
        else:
            result.update(status=STATUS_ERROR, reason="load_failed", detail=str(e))
        return None, result
    return data, verify_manifest(data, **kwargs)


# ─────────────────────────────────────────────
# HTTP fetches (manifest, representations)
# ─────────────────────────────────────────────

class FetchError(Exception):
    """A fetch was refused or failed. kind is a short, fixed description."""

    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind


# Characters never accepted in a URL we fetch: controls, space, non-ASCII,
# backslash (parsed differently by urllib.parse and by HTTP clients).
_UNSAFE_URL_CHAR_RE = re.compile(r"[^\x21-\x7e]|\\")


def checked_url(url: str, *, allow_http: bool = False) -> Tuple[str, str]:
    """Validate a URL before fetching. Returns (url to fetch, lowercase host).

    The returned URL is rebuilt from the parsed parts, so checking and
    fetching see the same host. Refused: userinfo ('@'), backslashes,
    controls, whitespace, non-ASCII, schemes other than https (http only
    with allow_http). Raises FetchError.
    """
    if not isinstance(url, str) or _UNSAFE_URL_CHAR_RE.search(url):
        raise FetchError("URL contains characters that are not allowed")
    parts = urlsplit(url)
    if parts.scheme not in (("https", "http") if allow_http else ("https",)):
        raise FetchError("URL scheme not allowed")
    if "@" in parts.netloc:
        raise FetchError("URL with userinfo not allowed")
    try:
        port = parts.port
    except ValueError:
        raise FetchError("URL port not valid")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise FetchError("URL without host")
    netloc = host + (f":{port}" if port is not None else "")
    path = parts.path or "/"
    rebuilt = f"{parts.scheme}://{netloc}{path}" + (f"?{parts.query}" if parts.query else "")
    return rebuilt, host


def _read_limited(read1: Callable[[int], bytes], max_bytes: int, deadline: float,
                  state: Optional[Dict[str, Any]] = None) -> bytes:
    """Read a body with read1() (at most one network read per call), so the
    size limit and the overall deadline are checked after every piece."""
    body = bytearray()
    while True:
        if time.monotonic() > deadline or (state is not None and state.get("cancelled")):
            raise FetchError("overall time limit exceeded")
        chunk = read1(65536)
        if not chunk:
            return bytes(body)
        body.extend(chunk)
        if len(body) > max_bytes:
            raise FetchError(f"response larger than {max_bytes} bytes")


def _run_with_deadline(work: Callable[[Dict[str, Any]], Any], seconds: float) -> Any:
    """Run work(state) in a daemon thread and return its result within seconds.

    HTTP clients apply their timeout to each socket operation, not to the
    whole request: a server that sends its status line and headers one byte
    at a time keeps a request open for as long as it likes. The caller
    therefore waits at most seconds. On timeout FetchError is raised,
    state["cancelled"] is set and state["close"] (if work registered one,
    e.g. the response's close) is called; the thread stops at its next
    read or socket timeout and does not keep the process alive (daemon).
    """
    state: Dict[str, Any] = {"cancelled": False, "close": None}
    outcome: Dict[str, Any] = {}

    def runner() -> None:
        try:
            outcome["value"] = work(state)
        except BaseException as e:  # passed on to the caller below
            outcome["error"] = e

    thread = threading.Thread(target=runner, name="arp-fetch", daemon=True)
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
        raise FetchError("overall time limit exceeded")
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]


def http_get_bytes(url: str, timeout: int = FETCH_TIMEOUT, *, max_bytes: int = MAX_FETCH_BYTES,
                   total_timeout: float = FETCH_TOTAL_TIMEOUT,
                   max_redirects: int = MAX_REDIRECTS) -> Tuple[bytes, str]:
    """GET url with an honest User-Agent. Returns (body, content_type).

    Redirects are followed only within the same host and never from https
    to http; the body is limited to max_bytes. The call returns or raises
    FetchError within total_timeout seconds for the whole fetch —
    connection, TLS handshake, status line, headers, redirects and body —
    also against servers that send one byte at a time (_run_with_deadline);
    timeout applies to each single connect/read.
    Raises FetchError (or the HTTP client's connection errors).
    """
    current, host = checked_url(url, allow_http=True)
    deadline = time.monotonic() + total_timeout
    return _run_with_deadline(
        lambda state: _http_get_worker(current, host, timeout, max_bytes, deadline, max_redirects, state),
        total_timeout)


def _http_get_worker(current: str, host: str, timeout: int, max_bytes: int, deadline: float,
                     max_redirects: int, state: Dict[str, Any]) -> Tuple[bytes, str]:
    """The fetch loop of http_get_bytes (runs in the worker thread)."""
    # identity: no decompression, so the size limit applies to what is sent.
    headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
    try:
        import requests
    except ImportError:
        requests = None  # type: ignore[assignment]

    for _ in range(max_redirects + 1):
        if time.monotonic() > deadline or state.get("cancelled"):
            raise FetchError("overall time limit exceeded")
        if requests is not None:
            response = requests.get(current, headers=headers, timeout=timeout, stream=True,
                                    allow_redirects=False)
            status, get_header = response.status_code, response.headers.get
            raw = response.raw
            if hasattr(raw, "read1"):  # urllib3 >= 2
                def read1(n: int, raw=raw) -> bytes:
                    return raw.read1(n, decode_content=True)
            else:
                pieces = response.iter_content(1024)

                def read1(n: int, pieces=pieces) -> bytes:
                    return next(pieces, b"")
            close = response.close
        else:
            import urllib.error
            import urllib.request

            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    return None

            opener = urllib.request.build_opener(_NoRedirect)
            try:
                response = opener.open(urllib.request.Request(current, headers=headers), timeout=timeout)
            except urllib.error.HTTPError as e:
                response = e
            status = getattr(response, "status", None) or response.code
            get_header = response.headers.get
            read1 = getattr(response, "read1", response.read)
            close = response.close
        state["close"] = close
        if state.get("cancelled"):
            close()
            raise FetchError("overall time limit exceeded")
        try:
            if status in (301, 302, 303, 307, 308):
                target = urljoin(current, get_header("Location") or "")
                nxt, next_host = checked_url(target, allow_http=True)
                if next_host != host:
                    raise FetchError(f"redirect to another host ({next_host}) not followed; check that URL directly")
                if current.startswith("https://") and not nxt.startswith("https://"):
                    raise FetchError("redirect from https to http not followed")
                current = nxt
                continue
            if status >= 400:
                raise FetchError(f"HTTP {status}")
            body = _read_limited(read1, max_bytes, deadline, state)
            return body, get_header("Content-Type", "") or ""
        finally:
            state["close"] = None
            close()
    raise FetchError("too many redirects")


def _fetch_error_kind(e: BaseException) -> str:
    """Short description of a fetch failure, without server-supplied text."""
    if isinstance(e, FetchError):
        return e.kind
    return type(e).__name__


# ─────────────────────────────────────────────
# Representations (ARP-R): hash check
# ─────────────────────────────────────────────

def representation_target(href: str) -> Tuple[str, str]:
    """(host, path) of a representation href. Raises ValueError if unusable.

    Only plain https URLs: no userinfo, port, query, fragment, backslash,
    controls or non-ASCII (SPEC §13.12: an https URL on the manifest's domain).
    """
    try:
        url, host = checked_url(href)
    except FetchError as e:
        raise ValueError(f"href refused: {e.kind}")
    parts = urlsplit(href)
    if parts.port is not None or parts.query or parts.fragment:
        raise ValueError("href refused: port, query or fragment not allowed")
    return host, urlsplit(url).path


def _read_local_representation(path: str) -> Tuple[Optional[bytes], str]:
    """Read a local reasoning.md for the hash check: (bytes or None, note).

    Symbolic links are not followed and at most MAX_FETCH_BYTES are read.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None, f"no local file {path}"
    except OSError as e:
        return None, f"local file not readable ({type(e).__name__})"
    if stat.S_ISLNK(info.st_mode):
        return None, f"{path} is a symbolic link; not followed"
    if not stat.S_ISREG(info.st_mode):
        return None, f"{path} is not a regular file"
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as f:
            body = f.read(MAX_FETCH_BYTES + 1)
    except OSError as e:
        return None, f"local file not readable ({type(e).__name__})"
    if len(body) > MAX_FETCH_BYTES:
        return None, f"{path} is larger than {MAX_FETCH_BYTES} bytes"
    return body, ""


def check_representations(manifest: Dict[str, Any], *, retrieval_domain: Optional[str] = None,
                          base_dir: Optional[str] = None,
                          fetch: Optional[Callable[[str], bytes]] = None,
                          max_fetches: int = MAX_REPRESENTATION_FETCHES,
                          total_timeout: float = REPRESENTATIONS_TOTAL_TIMEOUT) -> List[Dict[str, Any]]:
    """Compare each representation's sha256 with the actual bytes.

    Only hrefs that are plain https URLs on the retrieval domain are used
    (representation_target); others are REPRESENTATION_UNCHECKED and never
    fetched or read.
    Local source (base_dir set): only the reference representation
    /.well-known/reasoning.md is checked, against the file reasoning.md next
    to the manifest (no symbolic links, at most 1 MiB). Other entries are
    REPRESENTATION_UNCHECKED: the domain of a local file comes from the file
    itself, so its hrefs must not decide which local files are read.
    URL source: fetches the URL rebuilt from the checked parts (same host
    as the manifest, redirects only within that host, size limit). Equal
    URLs are fetched once; at most max_fetches distinct URLs and
    total_timeout seconds per call (the default fetch ends with the time
    left), the rest is REPRESENTATION_UNCHECKED.

    A mismatch does not change the manifest's trust level; it is reported.
    """
    reps = manifest.get("representations") if isinstance(manifest, dict) else None
    if reps is None:
        return []
    if not isinstance(reps, list):
        return [{"href": None, "status": REPRESENTATION_UNCHECKED, "note": "representations is not an array"}]
    budget_end = time.monotonic() + total_timeout
    if fetch is None:
        def fetch(url: str) -> bytes:
            # Each fetch ends with the time left for all representation checks.
            remaining = max(0.0, min(FETCH_TOTAL_TIMEOUT, budget_end - time.monotonic()))
            return http_get_bytes(url, total_timeout=remaining)[0]
    domain = retrieval_domain.strip().lower().rstrip(".") if isinstance(retrieval_domain, str) else None
    fetched: Dict[str, Tuple[Optional[bytes], str]] = {}
    local_body: Optional[Tuple[Optional[bytes], str]] = None
    results = []
    for entry in reps:
        item: Dict[str, Any] = {"href": None, "status": REPRESENTATION_UNCHECKED,
                                "expected": None, "actual": None, "note": ""}
        results.append(item)
        if not isinstance(entry, dict):
            item["note"] = "entry is not an object"
            continue
        href, expected = entry.get("href"), entry.get("sha256")
        item.update(href=href, expected=expected)
        if not isinstance(href, str) or not isinstance(expected, str) \
                or not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
            item["note"] = "href or sha256 missing or malformed"
            continue
        try:
            host, path = representation_target(href)
        except ValueError as e:
            item["note"] = f"{e}; not fetched"
            continue
        if domain and host != domain:
            item["note"] = "href is not on the retrieval domain; not fetched"
            continue
        if base_dir is not None:
            if path != MARKDOWN_PATH:
                item["note"] = f"local check covers only {MARKDOWN_PATH}; not read"
                continue
            local = os.path.join(base_dir, "reasoning.md")
            if local_body is None:
                local_body = _read_local_representation(local)
            body, note = local_body
            if body is None:
                item["note"] = note
                continue
            item["checked"] = local
        else:
            if not domain:
                item["note"] = "retrieval domain unknown; not fetched"
                continue
            url = f"https://{host}{path}"
            if url not in fetched:
                if len(fetched) >= max_fetches:
                    item["note"] = f"not fetched: at most {max_fetches} representation URLs are checked per run"
                    continue
                if time.monotonic() > budget_end:
                    item["note"] = "not fetched: the time for representation checks is used up"
                    continue
                try:
                    fetched[url] = (fetch(url), "")
                except Exception as e:
                    fetched[url] = (None, f"fetch failed ({_fetch_error_kind(e)})")
            body, note = fetched[url]
            if body is None:
                item["note"] = note
                continue
            item["checked"] = url
        item["actual"] = sha256_hex(body)
        item["status"] = REPRESENTATION_MATCH if item["actual"] == expected.lower() else REPRESENTATION_MISMATCH
    return results


# ─────────────────────────────────────────────
# Signing (Enveloped Pattern + ARP-S + ARP-R)
# ─────────────────────────────────────────────

def sign_manifest(manifest: Dict[str, Any], private_key: Any, *, domain: str, selector: str,
                  ttl_days: int = 90, now: Optional[datetime] = None,
                  allow_control_characters: bool = False) -> Tuple[Dict[str, Any], bytes]:
    """Sign a manifest in memory. Returns (signed_manifest, reasoning_md_bytes).

    Order (K4): _arp_signature metadata without signature → render
    reasoning.md → sha256 into representations → JCS-canonicalize the whole
    object with signature "" → Ed25519 sign → insert unpadded base64url.
    Does not lint and does not touch the file system.

    selector has no default: after a key rotation the old default "arp"
    may be revoked (K6). allow_control_characters is passed to
    render_reasoning_md() (effective only for files below version 1.3).

    Raises ValueError if the manifest has no "domain" field matching
    domain (verifiers reject such files, SPEC §4), contains values that
    are not I-JSON (RFC 8785 cannot canonicalize them), or cannot be
    rendered (render_reasoning_md: control characters, a member imitating
    the "## Verification" section).
    """
    _require_deps("rfc8785", "cryptography")
    domain = normalize_domain(domain)
    validate_selector(selector)
    if ttl_days <= 0:
        raise ValueError("ttl_days must be positive")
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    payload_domain = manifest.get("domain")
    if not isinstance(payload_domain, str) or not payload_domain.strip():
        raise ValueError(f"the manifest has no 'domain' field; add \"domain\": \"{domain}\" "
                         "(REQUIRED, SPEC §4; verifiers report signed files without it as INVALID)")
    if normalize_domain_safe(payload_domain) != domain:
        raise ValueError(f"domain {domain} differs from the manifest's domain field "
                         f"'{safe_text(payload_domain, 120)}' (SPEC §4)")
    problems = ijson_problems(manifest)
    if problems:
        raise ValueError(f"not I-JSON (RFC 7493): {problems[0][1]} at {safe_text(problems[0][0], 120)}; "
                         "RFC 8785 cannot canonicalize it")
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    expires = now + timedelta(days=ttl_days)

    data = copy.deepcopy(manifest)
    data.pop("_arp_signature", None)

    # 1. Signature metadata (without signature)
    data["_arp_signature"] = build_signature_metadata(domain, selector, now, expires)
    # 2. Render reasoning.md
    md_bytes = render_reasoning_md_bytes(data, domain, allow_control_characters=allow_control_characters)
    # 3. sha256 into representations (keep _arp_signature as the last member)
    sig_block = data.pop("_arp_signature")
    set_markdown_representation(data, domain, sha256_hex(md_bytes))
    sig_block["signature"] = ""
    data["_arp_signature"] = sig_block
    # 4. Canonicalize the ENTIRE object (signature = "") and 5. sign
    canonical = _canonical_bytes(data)
    signature = private_key.sign(canonical)
    private_key.public_key().verify(signature, canonical)  # self-check
    data["_arp_signature"]["signature"] = b64url_encode_unpadded(signature)
    return data, md_bytes


# ─────────────────────────────────────────────
# CLI helpers
# ─────────────────────────────────────────────

def _load_json_file(path: str) -> Any:
    """Load a reasoning.json strictly (I-JSON). Raises ManifestParseError / OSError."""
    with open(path, "rb") as f:
        return parse_manifest_bytes(f.read())


def _write_json_file(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def _write_bytes(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


def _print_findings(findings: List[LintFinding], indent: str = "  ") -> None:
    for f in findings:
        label = "ERROR  " if f.severity == "error" else "WARNING"
        print(f"{indent}{label} {f.rule}  {safe_text(f.path, 200)}")
        print(f"{indent}        {safe_text(f.message, 600)}")
        if f.excerpt:
            print(f"{indent}        » {safe_text(f.excerpt, 200)}")


def _print_json(obj: Any) -> None:
    """Print JSON; falls back to ASCII escapes if a value is not encodable.

    Values come from the file, DNS or the network. json.dumps escapes C0
    control characters itself; DEL, C1 controls (e.g. U+009B CSI) and
    invisible direction/format characters (e.g. U+202E) are written as
    \\uXXXX escapes as well, so they never reach the terminal raw. They only
    occur inside JSON strings, where the escape denotes the same value.
    """
    try:
        text = json.dumps(obj, indent=2, ensure_ascii=False)
        text = _UNSAFE_JSON_OUTPUT_RE.sub(lambda m: f"\\u{ord(m.group(0)):04x}", text)
        text.encode(sys.stdout.encoding or "utf-8")
    except (UnicodeEncodeError, LookupError):
        text = json.dumps(obj, indent=2)
    print(text)


def _fail(message: str, code: int = 1) -> None:
    print(message, file=sys.stderr)
    sys.exit(code)


def _check_cli_deps(*names: str) -> None:
    try:
        _require_deps(*names)
    except ARPDependencyError as e:
        _fail(str(e))


# ─────────────────────────────────────────────
# COMMAND: keys — Generate Ed25519 keypair
# ─────────────────────────────────────────────

def _write_private_key(path: str, pem: bytes, force: bool) -> None:
    """Write a private key with mode 0600. Never follows symlinks.

    Without force, an existing path (also a symlink) is refused (O_EXCL).
    With force, the key is written to a new temporary file next to path
    and moved over it with os.replace, so the old file's mode and a
    symlink's target are never reused.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    target = path
    if force and os.path.lexists(path):
        target = os.path.join(os.path.dirname(os.path.abspath(path)),
                              f".{os.path.basename(path)}.{os.getpid()}.tmp")
    try:
        fd = os.open(target, flags, 0o600)
    except FileExistsError:
        _fail(f"❌ '{target}' already exists. Refusing to overwrite a private key "
              "(choose another --out-key or pass --force).")
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        if target != path:
            os.replace(target, path)
    except BaseException:
        if target != path and os.path.lexists(target):
            os.unlink(target)
        raise


def stat_mode(path: str) -> int:
    """Permission bits of path (without following a symlink)."""
    return os.lstat(path).st_mode & 0o777


def cmd_keys(args):
    """Generate an Ed25519 keypair and output the DNS TXT record."""
    _check_cli_deps("cryptography")
    try:
        selector = validate_selector(args.selector)
        domain = normalize_domain(args.domain) if args.domain else "yourdomain.com"
        revoke = [validate_selector(s) for s in (args.revoke or [])]
    except ValueError as e:
        _fail(f"❌ {e}")
    if selector in revoke:
        _fail("❌ The new selector must differ from the revoked selector(s).")

    out_key = args.out_key or f"arp_private_{selector}.pem"
    private_key = Ed25519PrivateKey.generate()

    # Private key → PEM (store securely, never commit to git)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Public key → raw bytes → base64 (for DNS TXT record)
    # DNS uses standard Base64 with padding, per SPEC §13.5
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_b64 = base64.b64encode(public_bytes).decode("ascii")

    _write_private_key(out_key, private_pem, args.force)
    if args.out_pub:
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        _write_bytes(args.out_pub, public_pem)

    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║  ARP Cryptographic Trust Layer — Key Generator   ║")
    print(f"║                    v{CLI_VERSION}                        ║")
    print("╚══════════════════════════════════════════════════╝")
    print()
    try:
        mode = f"mode {stat_mode(out_key):04o}"
    except OSError:
        mode = "mode unknown"
    print(f"  ✅ Private Key saved to: {out_key} ({mode})")
    print(f"     ⚠️  KEEP THIS FILE SECRET. Never commit to git.")
    if args.out_pub:
        print(f"  ✅ Public Key (PEM) saved to: {args.out_pub}")
    print()
    print(f"  🌐 DNS TXT record for the new key:")
    print()
    print(f"     Name:   {dns_name_for(selector, domain)}")
    print(f"     Type:   TXT")
    print(f"     Value:  v=ARP1; k=ed25519; p={public_b64}")
    print()
    print(f"  📋 Zone file format:")
    print(f"     {dns_name_for(selector, domain)}. 300 IN TXT \"v=ARP1; k=ed25519; p={public_b64}\"")
    print()
    print(f"  ✍️  Sign with: --selector {selector}")
    for old in revoke:
        print()
        print(f"  🔒 Revocation record for the old selector '{old}' (empty p=, cf. DKIM RFC 6376 §3.6.1):")
        print(f"     {dns_name_for(old, domain)}. 300 IN TXT \"v=ARP1; k=ed25519; p=\"")
        print(f"     Verifiers from arp_cli v1.4 report files signed with '{old}' as INVALID (key_revoked).")
        print(f"     Publish it once the files on {domain} carry the new selector.")
    print()


# ─────────────────────────────────────────────
# COMMAND: lint — Wording Profile (ARP-W)
# ─────────────────────────────────────────────

_TEXT_EXTENSIONS = (".md", ".markdown", ".txt", ".html", ".htm")


def cmd_lint(args):
    """Lint a reasoning.json (or a derived text file). Exit 0 = no errors,
    1 = errors, 2 = not readable."""
    text_mode = args.text or args.file.lower().endswith(_TEXT_EXTENSIONS)
    try:
        if text_mode:
            with open(args.file, "r", encoding="utf-8-sig") as f:
                findings = lint_text_document(f.read())
        else:
            with open(args.file, "r", encoding="utf-8-sig") as f:
                findings = lint_manifest_text(f.read())
    except Exception as e:
        _fail(f"❌ Error loading '{args.file}': {safe_text(e)}", 2)
    errors = sum(1 for f in findings if f.severity == "error")
    warnings = len(findings) - errors
    if args.json:
        _print_json({"file": args.file, "errors": errors, "warnings": warnings,
                     "findings": [f.as_dict() for f in findings]})
    else:
        print()
        print(f"  📋 ARP lint (Wording Profile, ARP v{SPEC_VERSION}): {args.file}")
        print()
        if findings:
            _print_findings(findings)
            print()
        print(f"  {'❌' if errors else '✅'} {errors} error(s), {warnings} warning(s)")
        print()
    if errors or (args.strict and warnings):
        sys.exit(1)


# ─────────────────────────────────────────────
# COMMAND: render-md — reference reasoning.md (ARP-R)
# ─────────────────────────────────────────────

def cmd_render_md(args):
    """Render /.well-known/reasoning.md from a reasoning.json."""
    try:
        data = _load_json_file(args.file)
    except Exception as e:
        _fail(f"❌ Error loading '{args.file}': {safe_text(e)}")
    if not isinstance(data, dict):
        _fail("❌ reasoning.json must be a JSON object.")
    try:
        domain = normalize_domain(args.domain or data.get("domain") or "")
    except ValueError as e:
        _fail(f"❌ {e} — pass --domain or set the 'domain' field.")
    if isinstance(data.get("domain"), str) and normalize_domain_safe(data["domain"]) != domain:
        _fail(f"❌ --domain {domain} differs from the file's domain field '{safe_text(data['domain'])}'.")
    if args.write_representation and "_arp_signature" in data:
        # Checked before anything is written: an aborted run leaves no file behind.
        _fail("❌ The file is signed; changing it would break the signature. Use 'sign' instead, "
              "which renders reasoning.md and binds it before signing.")
    if args.allow_control_characters and _is_v13_or_later(data):
        _fail("❌ --allow-control-characters applies only to files below version 1.3; ARP v1.3 files contain "
              "no control characters (SPEC §13.12.1).")
    try:
        md_bytes = render_reasoning_md_bytes(data, domain, allow_control_characters=args.allow_control_characters)
    except ValueError as e:
        _fail(f"❌ Not rendered: {safe_text(e)}")
    digest = sha256_hex(md_bytes)
    errors = sum(1 for f in lint_manifest(data) if f.severity == "error")

    if args.out == "-":
        sys.stdout.buffer.write(md_bytes)
        sys.stdout.flush()
        if errors:
            print(f"⚠️  lint reports {errors} error(s) in this manifest (arp lint {safe_text(args.file)}).",
                  file=sys.stderr)
        return
    out = args.out or os.path.join(os.path.dirname(os.path.abspath(args.file)), "reasoning.md")
    if os.path.abspath(out) == os.path.abspath(args.file):
        _fail("❌ The Markdown output path must differ from the JSON file.")
    _write_bytes(out, md_bytes)

    entry = markdown_representation(domain, digest)
    print()
    print(f"  ✅ reasoning.md written to: {out}")
    print(f"  📋 Bytes:   {len(md_bytes)}")
    print(f"  📋 SHA-256: {digest}")
    if "provenance" not in data:
        print("  ⚠️  No provenance block: the rendering has no provenance statement (REQUIRED in ARP v1.3).")
    if errors:
        print(f"  ⚠️  lint reports {errors} error(s) in this manifest (arp lint {args.file}).")
    if args.write_representation:
        set_markdown_representation(data, domain, digest)
        _write_json_file(args.file, data)
        print(f"  ✅ representations entry written to: {args.file}")
    else:
        print("  📋 representations entry:")
        print("     " + json.dumps(entry, ensure_ascii=False))
    print(f"  🌐 Deploy at {entry['href']} (Content-Type: text/markdown; charset=utf-8)")
    print()


def normalize_domain_safe(value: Any) -> Optional[str]:
    try:
        return normalize_domain(value)
    except ValueError:
        return None


# ─────────────────────────────────────────────
# COMMAND: sign — Sign a reasoning.json
#   (Enveloped Signature Pattern — SPEC §13.4)
# ─────────────────────────────────────────────

def cmd_sign(args):
    """Sign a reasoning.json file with JCS canonicalization + Ed25519.

    Uses the Enveloped Signature Pattern: the _arp_signature metadata
    (with signature set to "") is included in the canonical bytes.
    This cryptographically protects expires_at, dns_selector, algorithm,
    statement, verify and all other signature metadata against tampering.
    representations[] (with the reasoning.md hash) is signed as well.
    """
    _check_cli_deps("rfc8785", "cryptography")
    try:
        domain = normalize_domain(args.domain)
        selector = validate_selector(args.selector)
    except ValueError as e:
        _fail(f"❌ {e}")
    if args.ttl <= 0:
        _fail("❌ --ttl must be a positive number of days.")

    # Load private key
    try:
        with open(args.key, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except Exception as e:
        _fail(f"❌ Error loading private key '{args.key}': {safe_text(e)}")
    if not isinstance(private_key, Ed25519PrivateKey):
        _fail(f"❌ '{args.key}' is not an Ed25519 private key.")

    # Load reasoning.json
    try:
        data = _load_json_file(args.file)
    except Exception as e:
        _fail(f"❌ Error loading '{args.file}': {safe_text(e)}")
    if not isinstance(data, dict):
        _fail("❌ reasoning.json must be a JSON object.")

    payload_domain = data.get("domain")
    if not isinstance(payload_domain, str) or not payload_domain.strip():
        _fail(f"❌ The file has no 'domain' field. Add \"domain\": \"{domain}\" (REQUIRED, SPEC §4); "
              "verifiers report signed files without it as INVALID (domain_missing).")
    if normalize_domain_safe(payload_domain) != domain:
        _fail(f"❌ --domain {domain} differs from the file's domain field '{safe_text(payload_domain)}'. "
              "Verifiers reject such files (SPEC §4).")

    if args.allow_control_characters and _is_v13_or_later(data):
        _fail("❌ --allow-control-characters applies only to files below version 1.3; ARP v1.3 files contain "
              "no control characters (SPEC §13.12.1).")

    # Wording Profile check before signing (the old signature block is not linted;
    # representations is written by sign itself, so its absence is not reported)
    unsigned = {k: v for k, v in data.items() if k != "_arp_signature"}
    findings = [f for f in lint_manifest(unsigned) if f.rule != "ARP-R/missing"]
    errors = [f for f in findings if f.severity == "error"]
    warnings = [f for f in findings if f.severity == "warning"]
    if findings:
        print()
        print(f"  📋 lint: {len(errors)} error(s), {len(warnings)} warning(s)")
        _print_findings(findings)
    if errors and not args.allow_lint_errors:
        _fail(f"\n  ❌ Not signed: {len(errors)} wording error(s). Fix them, or pass "
              "--allow-lint-errors to sign anyway.")
    if errors:
        print(f"\n  ⚠️  WARNING: signing despite {len(errors)} wording error(s) (--allow-lint-errors).")

    out_file = args.out if args.out else args.file
    md_path = args.render_md or os.path.join(os.path.dirname(os.path.abspath(out_file)), "reasoning.md")
    if os.path.abspath(md_path) in (os.path.abspath(out_file), os.path.abspath(args.file)):
        _fail("❌ --render-md must differ from the JSON file.")

    try:
        signed, md_bytes = sign_manifest(data, private_key, domain=domain, selector=selector,
                                         ttl_days=args.ttl, allow_control_characters=args.allow_control_characters)
    except ValueError as e:
        _fail(f"❌ Not signed: {safe_text(e)}")
    sig = signed["_arp_signature"]

    _write_bytes(md_path, md_bytes)
    _write_json_file(out_file, signed)

    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║  ARP Cryptographic Trust Layer — File Signed     ║")
    print(f"║  Enveloped Signature Pattern (v{CLI_VERSION})            ║")
    print("╚══════════════════════════════════════════════════╝")
    print()
    print(f"  ✅ Signed file saved to: {out_file}")
    print(f"  ✅ reasoning.md saved to: {md_path}")
    print(f"  📋 Algorithm:     Ed25519")
    print(f"  📋 Canonicalize:  RFC 8785 (JCS) — enveloped (metadata included)")
    print(f"  📋 DNS Record:    {sig['dns_record']}")
    print(f"  📋 Signed at:     {sig['signed_at']}")
    print(f"  📋 Expires at:    {sig['expires_at']}")
    print(f"  📋 reasoning.md:  {markdown_url_for(domain)}")
    print(f"  📋 SHA-256:       {sha256_hex(md_bytes)}")
    print(f"  📋 Signature:     {len(sig['signature'])} chars (unpadded base64url)")
    if not _is_v13_or_later(signed):
        print(f"  ⚠️  version is {signed.get('version')!r}: statement, verify and representations are "
              f"ARP v{SPEC_VERSION} fields. Set version \"1.3\" and $schema {SCHEMA_URL}.")
    print()
    print("  Deploy both files together; the DNS TXT record must exist at "
          f"{sig['dns_record']}.")
    print()


# ─────────────────────────────────────────────
# COMMAND: verify — Verify a reasoning.json
#   Domain-Binding, revocation, representations
# ─────────────────────────────────────────────

def _extract_domain_from_url(url: str) -> str:
    """Extract the domain from a URL for Domain-Binding verification.

    Uses the same parser as the fetch (checked_url): lowercase host without
    a trailing dot. Raises FetchError for URLs that are not fetched at all.
    """
    return checked_url(url, allow_http=True)[1]


def _load_public_key_file(path: str):
    """Load a public key from a local PEM or raw/base64 file."""
    _require_deps("cryptography")
    with open(path, "rb") as f:
        key_data = f.read()
    if b"-----BEGIN" in key_data:
        public_key = serialization.load_pem_public_key(key_data)
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("not an Ed25519 public key")
        return public_key
    raw = key_data.strip()
    try:
        key_bytes = b64_decode_tolerant(raw.decode("ascii"))
    except Exception:
        key_bytes = raw
    return Ed25519PublicKey.from_public_bytes(key_bytes)


_REASON_TEXT = {
    "key_revoked": "The DNS record has an empty p= value: the domain operator revoked this key "
                   "(cf. DKIM, RFC 6376 §3.6.1). Files signed with it are no longer valid.",
    "legacy_payload_only": "The signature covers only the payload, not the _arp_signature metadata "
                           "(legacy pattern of CLI <= 1.2). Such files are rejected: expires_at, "
                           "dns_selector and algorithm could be changed without breaking the signature. "
                           "Re-sign with arp_cli v1.4 or later.",
    "signature_field_removed": "The signature was computed with the signature member removed instead of "
                               "set to \"\" (SPEC §13.4 requires signature = \"\"). Re-sign the file.",
    "signature_mismatch": "The file content or signature metadata does not match the signature: the file "
                          "was changed after signing, signed with another key, or the DNS record holds "
                          "a different key.",
    "domain_mismatch": "The file names another domain than the retrieval domain (payload field 'domain', "
                       "or in v1.3 dns_record / verify.dns_name; SPEC §4, §13.3).",
    "domain_missing": "The file is signed but has no 'domain' field (REQUIRED, SPEC §4). Without it the "
                      "file is not bound to a domain and could be presented under any domain that "
                      "publishes the same key. Add the field and re-sign.",
    "duplicate_member": "The file contains a member name twice in one object. JSON parsers keep the last "
                        "value, while people and language models reading the text see the first; the "
                        "signature covers only the parsed object. Such files are rejected "
                        "(I-JSON, RFC 7493 §2.3).",
    "non_ijson": "The file contains values outside I-JSON (RFC 7493), e.g. NaN, Infinity or integers "
                 "beyond ±(2^53−1). They cannot be canonicalized (RFC 8785); the file is rejected.",
    "dns_no_key": "No ARP1 key record was found in DNS for this selector and domain.",
    "dns_key_malformed": "The DNS key record is malformed.",
    "dns_unsupported_algorithm": "The DNS key record names an algorithm other than ed25519.",
    "malformed_signature": "The signature value is missing or not a 64-byte Ed25519 signature in "
                           "canonical Base64url (SPEC §13.3).",
    "malformed_metadata": "Required signature metadata is missing or malformed.",
    "malformed_signature_block": "_arp_signature is not an object.",
    "unsupported_algorithm": "The algorithm is not Ed25519.",
    "unsupported_canonicalization": "The canonicalization is not jcs-rfc8785.",
}


def _print_verify_result(result: Dict[str, Any], reps: List[Dict[str, Any]], sig_block: Any) -> None:
    # Every value that comes from the file, DNS or the network goes through
    # safe_text: control sequences in the file must not rewrite the terminal.
    status, reason = result["status"], result["reason"]
    print()
    for note in result.get("notes", []):
        print(f"  ℹ️  {safe_text(note)}")
    for w in result["warnings"]:
        print(f"  ⚠️  {safe_text(w)}")
    if result["warnings"]:
        print()
    if status == TRUST_CRYPTOGRAPHIC:
        print("  ╔══════════════════════════════════════════════════╗")
        print("  ║       ✅ CRYPTOGRAPHIC VERIFICATION PASSED       ║")
        print("  ╚══════════════════════════════════════════════════╝")
        print()
        print(f"  ✅ Verification Method: Enveloped Signature (SPEC §13.4)")
    elif status == TRUST_INVALID:
        print("  ❌ SIGNATURE VERIFICATION FAILED")
    elif status == STATUS_ERROR:
        print("  ❌ VERIFICATION NOT POSSIBLE")
    print()
    label = status
    if status == TRUST_CRYPTOGRAPHIC:
        label = f"CRYPTOGRAPHIC ({result.get('meaning') or CRYPTOGRAPHIC_MEANING})"
    elif status == TRUST_UNSIGNED and reason == "expired":
        label = "UNSIGNED (signature expired; it still matches the content)"
    elif status in (TRUST_INVALID, STATUS_ERROR):
        label = f"{status} ({reason})"
    print(f"  🛡️  Trust Level:  {label}")
    print(f"  🌐 Domain:       {safe_text(result['domain'] or '(offline verification)')}")
    if result.get("dns_name"):
        print(f"  🔑 Key record:   {safe_text(result['dns_name'])}")
    elif result.get("method") == "local_public_key":
        print(f"  🔑 Key:          local public key file")
    if isinstance(sig_block, dict):
        print(f"  🔑 Algorithm:    {safe_text(sig_block.get('algorithm', 'unknown'), 60)}")
        print(f"  📋 Signed at:    {safe_text(sig_block.get('signed_at', 'unknown'), 60)}")
        print(f"  📋 Expires at:   {safe_text(sig_block.get('expires_at', 'unknown'), 60)}")
        signature = sig_block.get("signature", "")
        if isinstance(signature, str) and signature:
            if reason == "malformed_signature":
                print(f"  📋 Signature:    {len(signature)} chars (not a canonical 86-character value)")
            elif signature.endswith("="):
                print(f"  📋 Signature:    {len(signature)} chars (padded — consider re-signing for unpadded)")
            else:
                print(f"  📋 Signature:    {len(signature)} chars (unpadded base64url)")
    for rep in reps:
        note = f" — {safe_text(rep['note'])}" if rep.get("note") else ""
        print(f"  📄 {rep['status']}: {safe_text(rep.get('href'), 200)}{note}")
    print()
    if status == TRUST_CRYPTOGRAPHIC and result.get("method") == "local_public_key":
        print("  Result: the signature matches the local public key file. The holder of the matching")
        print("  private key signed exactly this file, and it has not been altered since signing.")
        print(f"  The key's link to {safe_text(result['domain'] or 'the domain')} and its revocation status were "
              "not checked")
        print("  (no DNS lookup). The signature shows the origin of the file;")
        print("  it does not show that the statements are true.")
    elif status == TRUST_CRYPTOGRAPHIC:
        print(f"  Result: the signature matches the public key in DNS ({safe_text(result['dns_name'])}).")
        print(f"  The operator of {safe_text(result['domain'] or 'the signing domain')} published exactly this "
              "file, and it has")
        print("  not been altered since signing. The signature shows the origin of the file;")
        print("  it does not show that the statements are true.")
    elif status == TRUST_UNSIGNED and reason == "expired":
        print("  Result: the signature matches, but its validity period has ended. The origin is")
        print("  not currently attested; the file counts as unsigned (SPEC §13.7). Re-sign it.")
    elif status == TRUST_UNSIGNED:
        print("  Result: no _arp_signature block. The file contains the entity's own statements")
        print("  about itself; its origin is not cryptographically attested.")
    else:
        print(f"  Result: {_REASON_TEXT.get(reason, '')}")
        if result.get("detail"):
            print(f"  Detail: {safe_text(result['detail'])}")
    if any(r["status"] == REPRESENTATION_MISMATCH for r in reps):
        print()
        print("  ⚠️  A representation does not match its sha256. This does not invalidate the manifest")
        print("     signature; the published reasoning.md differs from the signed rendering.")
    print()


def cmd_verify(args):
    """Verify a reasoning.json file against its DNS-published public key.

    Domain-Binding: the DNS name is constructed from the retrieval domain
    (URL) or the --domain flag (local files) combined with dns_selector.
    The dns_record field in the file is treated as an informational hint
    only and is NEVER used as the DNS query source (prevents redirect/
    spoofing attacks).
    """
    _check_cli_deps("rfc8785", "cryptography")
    quiet = args.json
    if not quiet:
        print()
        print(f"  📥 Loading: {safe_text(args.source, 200)}")

    retrieval_domain = None
    base_dir = None
    load_warnings: List[str] = []
    load_notes: List[str] = []
    try:
        if args.source.startswith(("http://", "https://")):
            fetch_url, retrieval_domain = checked_url(args.source, allow_http=True)
            if args.source.startswith("http://"):
                load_warnings.append("Source uses http://; SPEC §14 requires HTTPS.")
            if urlsplit(fetch_url).port is not None:
                load_warnings.append("Source URL names a port; the DNS name is built from the host only.")
            if args.domain and normalize_domain_safe(args.domain) != retrieval_domain:
                load_warnings.append(f"--domain {args.domain} ignored; the URL host {retrieval_domain} is used.")
            raw, content_type = http_get_bytes(fetch_url)
            if "application/json" not in content_type.lower():
                load_warnings.append(f"Content-Type is '{content_type}', expected application/json.")
        else:
            with open(args.source, "rb") as f:
                raw = f.read()
            base_dir = os.path.dirname(os.path.abspath(args.source))
            if args.domain:
                retrieval_domain = normalize_domain(args.domain)
    except Exception as e:
        detail = _fetch_error_kind(e) if isinstance(e, FetchError) else f"{type(e).__name__}: {safe_text(e, 200)}"
        if quiet:
            _print_json({"source": args.source, "status": STATUS_ERROR, "reason": "load_failed",
                         "detail": detail})
            sys.exit(2)
        _fail(f"  ❌ Error loading source: {detail}", 2)

    try:
        data = parse_manifest_bytes(raw)
        parse_error = None
    except ManifestParseError as e:
        data, parse_error = None, e
    if parse_error is not None and parse_error.reason not in REJECTED_PARSE_REASONS:
        if quiet:
            _print_json({"source": args.source, "status": STATUS_ERROR, "reason": "load_failed",
                         "detail": str(parse_error)})
            sys.exit(2)
        _fail(f"  ❌ Error loading source: {safe_text(parse_error)}", 2)

    if retrieval_domain is None and isinstance(data, dict) and isinstance(data.get("domain"), str):
        retrieval_domain = normalize_domain_safe(data["domain"])
        if retrieval_domain:
            load_notes.append(f"Using domain from file: {data['domain']}")

    public_key = None
    if args.pubkey:
        try:
            public_key = _load_public_key_file(args.pubkey)
        except Exception as e:
            _fail(f"  ❌ Error loading public key '{args.pubkey}': {safe_text(e)}", 2)

    if parse_error is not None:
        # Duplicate member names / non-I-JSON values: rejected (INVALID).
        result = new_verify_result(retrieval_domain)
        result.update(status=TRUST_INVALID, reason=parse_error.reason, detail=str(parse_error))
    else:
        try:
            result = verify_manifest(data, domain=retrieval_domain, public_key=public_key)
        except Exception as e:  # e.g. a missing optional dependency
            result = new_verify_result(retrieval_domain)
            result.update(status=STATUS_ERROR, reason="verifier_error", detail=type(e).__name__)
    result["warnings"] = load_warnings + result["warnings"]
    result["notes"] = load_notes
    result["source"] = args.source

    reps: List[Dict[str, Any]] = []
    if isinstance(data, dict) and not args.no_representations:
        reps = check_representations(data, retrieval_domain=retrieval_domain, base_dir=base_dir)

    if quiet:
        out = dict(result)
        out["representations"] = reps
        _print_json(out)
    else:
        _print_verify_result(result, reps, data.get("_arp_signature") if isinstance(data, dict) else None)

    if result["status"] == TRUST_INVALID:
        sys.exit(1)
    if result["status"] == STATUS_ERROR:
        sys.exit(2)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main(argv: Optional[List[str]] = None):
    parser = argparse.ArgumentParser(
        prog="arp",
        description=f"ARP Protocol CLI — Reader Profile (v{CLI_VERSION}, ARP v{SPEC_VERSION})",
        epilog="Docs: https://arp-protocol.org | License: MIT",
    )
    parser.add_argument("--version", action="version", version=f"arp_cli {CLI_VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- keys ---
    p_keys = subparsers.add_parser("keys", help="Generate Ed25519 keypair + DNS record")
    p_keys.add_argument("--domain", help="Your domain (e.g., example.com)", default="")
    p_keys.add_argument("--selector", required=True,
                        help="DNS selector, rotation pattern arpYYMM (e.g. arp2610); required, because the "
                             "old default 'arp' may be revoked after a rotation")
    p_keys.add_argument("--revoke", action="append", metavar="OLD_SELECTOR",
                        help="Print the revocation record (empty p=) for an old selector; repeatable")
    p_keys.add_argument("--out-key",
                        help="Output private key path (default: arp_private_<selector>.pem; "
                             "an existing file is never overwritten without --force)")
    p_keys.add_argument("--out-pub", help="Also write the public key as PEM (for verify --pubkey)")
    p_keys.add_argument("--force", action="store_true", help="Overwrite an existing private key file")

    # --- lint ---
    p_lint = subparsers.add_parser("lint", help="Check wording (ARP-W), provenance and signature fields")
    p_lint.add_argument("file", help="Path to reasoning.json (or reasoning.md / llms.txt / HTML with --text)")
    p_lint.add_argument("--json", action="store_true", help="Machine-readable output")
    p_lint.add_argument("--strict", action="store_true", help="Exit 1 on warnings as well")
    p_lint.add_argument("--text", action="store_true",
                        help="Treat the file as text (default for .md, .txt, .html): reasoning.md, llms.txt, HTML mirrors")

    # --- render-md ---
    p_md = subparsers.add_parser("render-md", help="Render the reference /.well-known/reasoning.md")
    p_md.add_argument("file", help="Path to reasoning.json")
    p_md.add_argument("--domain", help="Domain (default: the file's domain field)")
    p_md.add_argument("--out", help="Output path (default: reasoning.md next to the file; '-' = stdout)")
    p_md.add_argument("--write-representation", action="store_true",
                      help="Write the representations entry (href, media_type, sha256) into the "
                           "unsigned JSON file")
    p_md.add_argument("--allow-control-characters", action="store_true",
                      help="Render control characters (line breaks, tabs) in values anyway; only for files "
                           "below version 1.3")

    # --- sign ---
    p_sign = subparsers.add_parser("sign", help="Sign a reasoning.json file (enveloped, ARP v1.3)")
    p_sign.add_argument("file", help="Path to reasoning.json")
    p_sign.add_argument("--key", required=True, help="Path to private PEM key")
    p_sign.add_argument("--domain", required=True, help="Domain (e.g., example.com)")
    p_sign.add_argument("--selector", required=True,
                        help="DNS selector of the key, e.g. arp2610 (required; see keys --selector)")
    p_sign.add_argument("--ttl", type=int, default=90, help="Signature validity in days (default: 90)")
    p_sign.add_argument("--out", help="Output path (default: overwrite input)")
    p_sign.add_argument("--render-md", metavar="PATH",
                        help="Where to write reasoning.md (default: reasoning.md next to the output file)")
    p_sign.add_argument("--allow-lint-errors", action="store_true",
                        help="Sign despite wording errors (prints a warning)")
    p_sign.add_argument("--allow-control-characters", action="store_true",
                        help="Render control characters (line breaks, tabs) in values anyway; only for files "
                             "below version 1.3")

    # --- verify ---
    p_verify = subparsers.add_parser("verify", help="Verify a reasoning.json via DNS or local key")
    p_verify.add_argument("source", help="URL or local path to reasoning.json")
    p_verify.add_argument("--domain", help="Domain for local file verification (e.g., example.com)")
    p_verify.add_argument("--pubkey", help="Path to local public key file (PEM or raw) for offline/CI verification")
    p_verify.add_argument("--no-representations", action="store_true",
                          help="Do not fetch/read representations for the sha256 comparison")
    p_verify.add_argument("--json", action="store_true", help="Machine-readable output")

    args = parser.parse_args(argv)
    if args.command == "keys":
        cmd_keys(args)
    elif args.command == "lint":
        cmd_lint(args)
    elif args.command == "render-md":
        cmd_render_md(args)
    elif args.command == "sign":
        cmd_sign(args)
    elif args.command == "verify":
        cmd_verify(args)


if __name__ == "__main__":
    main()
