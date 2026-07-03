#!/usr/bin/env python3
"""
ARP Protocol CLI — Cryptographic Trust Layer (v1.3.0)
Command-line tool for generating keys, signing and verifying reasoning.json files.

v1.3.0 Changes:
  - Enveloped Signature Pattern: _arp_signature metadata (with signature:"")
    is included in the canonical bytes, matching SPEC §13.4 and the Browser Signer.
  - Unpadded base64url output (86 characters for Ed25519, JWS convention).
  - Tolerant decoding: accepts padded and unpadded base64/base64url on read.
  - Legacy fallback: verifier tries Payload-only if Enveloped fails, reports
    LEGACY_PAYLOAD_ONLY with re-sign guidance.
  - Domain-Binding: verify constructs the DNS name from the retrieval domain
    (or --domain flag for local files), never trusts dns_record as query source.
  - --pubkey flag for offline / CI verification against a local public key file.
  - dns_record mismatch warnings (informational only).

Usage:
    arp keys --domain truesource.studio
    arp sign reasoning.json --key arp_private.pem --domain truesource.studio
    arp verify https://truesource.studio/.well-known/reasoning.json
    arp verify reasoning.json --domain truesource.studio
    arp verify reasoning.json --pubkey arp_public.pem

Dependencies:
    pip install cryptography rfc8785 dnspython requests

License: MIT
Author: Sascha Deforth (TrueSource)
"""

import argparse
import json
import base64
import copy
import sys
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse


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

    Signatures written by older ARP tooling may be padded base64url;
    DNS public keys use standard padded base64.
    Verification must accept all of these encodings.
    """
    value = value.strip()
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


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
        sys.exit("Missing dependency: pip install rfc8785")

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.exit("Missing dependency: pip install cryptography")


# ─────────────────────────────────────────────
# COMMAND: keys — Generate Ed25519 keypair
# ─────────────────────────────────────────────

def cmd_keys(args):
    """Generate an Ed25519 keypair and output DNS TXT record."""
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

    # Save private key
    with open(args.out_key, "wb") as f:
        f.write(private_pem)

    domain = args.domain if args.domain else "yourdomain.com"
    selector = args.selector

    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║  ARP Cryptographic Trust Layer — Key Generator   ║")
    print("║                    v1.3.0                        ║")
    print("╚══════════════════════════════════════════════════╝")
    print()
    print(f"  ✅ Private Key saved to: {args.out_key}")
    print(f"     ⚠️  KEEP THIS FILE SECRET. Never commit to git.")
    print()
    print(f"  🌐 ACTION REQUIRED — Add this DNS TXT Record:")
    print()
    print(f"     Name:   {selector}._arp.{domain}")
    print(f"     Type:   TXT")
    print(f"     Value:  v=ARP1; k=ed25519; p={public_b64}")
    print()
    print(f"  📋 Zone file format:")
    print(f"     {selector}._arp.{domain}. 300 IN TXT \"v=ARP1; k=ed25519; p={public_b64}\"")
    print()


# ─────────────────────────────────────────────
# COMMAND: sign — Sign a reasoning.json
#   (Enveloped Signature Pattern — SPEC §13.4)
# ─────────────────────────────────────────────

def cmd_sign(args):
    """Sign a reasoning.json file with JCS canonicalization + Ed25519.

    Uses the Enveloped Signature Pattern: the _arp_signature metadata
    (with signature set to "") is included in the canonical bytes.
    This cryptographically protects expires_at, dns_selector, algorithm,
    and all other signature metadata against tampering.
    """
    # Load private key
    try:
        with open(args.key, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except Exception as e:
        sys.exit(f"❌ Error loading private key '{args.key}': {e}")

    # Load reasoning.json
    try:
        with open(args.file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        sys.exit(f"❌ Error loading '{args.file}': {e}")

    # Step 1: Remove any existing signature block (for re-signing)
    data.pop("_arp_signature", None)

    # Step 2: Build the signature metadata with an empty signature field
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=args.ttl)
    selector = args.selector

    data["_arp_signature"] = {
        "algorithm": "Ed25519",
        "dns_selector": selector,
        "dns_record": f"{selector}._arp.{args.domain}",
        "canonicalization": "jcs-rfc8785",
        "signed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "signature": "",  # Empty during canonicalization — metadata IS signed
    }

    # Step 3: JCS Canonicalization (RFC 8785) of the ENTIRE object
    # This includes _arp_signature with signature:"", so that
    # expires_at, dns_selector, etc. are cryptographically protected.
    canonical_bytes = canonicalize(data)

    # Step 4: Sign with Ed25519
    signature = private_key.sign(canonical_bytes)

    # Step 5: Inject the final signature as unpadded base64url (86 chars)
    data["_arp_signature"]["signature"] = b64url_encode_unpadded(signature)

    # Save signed file
    out_file = args.out if args.out else args.file
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║  ARP Cryptographic Trust Layer — File Signed     ║")
    print("║  Enveloped Signature Pattern (v1.3.0)            ║")
    print("╚══════════════════════════════════════════════════╝")
    print()
    print(f"  ✅ Signed file saved to: {out_file}")
    print(f"  📋 Algorithm:     Ed25519")
    print(f"  📋 Canonicalize:  RFC 8785 (JCS) — enveloped (metadata included)")
    print(f"  📋 DNS Record:    {selector}._arp.{args.domain}")
    print(f"  📋 Signed at:     {now.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"  📋 Expires at:    {expires.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"  📋 Payload size:  {len(canonical_bytes)} bytes")
    print(f"  📋 Signature:     {len(data['_arp_signature']['signature'])} chars (unpadded base64url)")
    print()


# ─────────────────────────────────────────────
# COMMAND: verify — Verify a reasoning.json
#   Domain-Binding + Legacy Fallback
# ─────────────────────────────────────────────

def _extract_domain_from_url(url: str) -> str:
    """Extract the domain from a URL for Domain-Binding verification."""
    parsed = urlparse(url)
    return parsed.hostname or ""


def _resolve_public_key_dns(dns_name: str):
    """Resolve public key from DNS TXT record. Returns (public_key, txt_value) or exits."""
    import dns.resolver

    print(f"  🔍 Looking up DNS: {dns_name}")
    try:
        answers = dns.resolver.resolve(dns_name, "TXT")
        txt_value = None
        for rdata in answers:
            txt_str = rdata.to_text().strip('"')
            if txt_str.startswith("v=ARP1"):
                txt_value = txt_str
                break

        if not txt_value:
            sys.exit(f"  ❌ No ARP1 TXT record found at {dns_name}")

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
        sys.exit(f"  ❌ DNS lookup failed: {e}\n  🔴 Trust Level: INVALID")

    print(f"  ✅ DNS record found: {txt_value[:60]}...")

    # Parse public key
    parts = {}
    for segment in txt_value.split(";"):
        segment = segment.strip()
        if "=" in segment:
            k, v = segment.split("=", 1)
            parts[k.strip()] = v.strip()

    if parts.get("k") != "ed25519":
        sys.exit(f"  ❌ Algorithm mismatch: DNS says '{parts.get('k')}', file says 'Ed25519'")

    try:
        public_key_bytes = b64_decode_tolerant(parts["p"])
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except Exception as e:
        sys.exit(f"  ❌ Error decoding public key: {e}")

    return public_key, txt_value


def _load_public_key_file(path: str):
    """Load a public key from a local PEM or raw file."""
    try:
        with open(path, "rb") as f:
            key_data = f.read()

        # Try PEM first
        if b"-----BEGIN" in key_data:
            public_key = serialization.load_pem_public_key(key_data)
        else:
            # Try raw 32-byte key
            raw = key_data.strip()
            # Could be base64-encoded
            try:
                key_bytes = b64_decode_tolerant(raw.decode("ascii"))
            except Exception:
                key_bytes = raw
            public_key = Ed25519PublicKey.from_public_bytes(key_bytes)

        return public_key
    except Exception as e:
        sys.exit(f"  ❌ Error loading public key '{path}': {e}")


def _verify_signature(public_key, data: dict, sig_block: dict) -> str:
    """
    Attempt signature verification. Returns 'enveloped', 'payload_only', or raises.

    Tries the normative Enveloped Pattern first (SPEC §13.4):
    set signature to "", canonicalize the ENTIRE object.

    If that fails, falls back to the legacy Payload-only pattern
    (CLI ≤1.2) and returns 'payload_only'.
    """
    signature_bytes = b64_decode_tolerant(sig_block["signature"])

    # --- Attempt 1: Enveloped Pattern (normative) ---
    enveloped_data = copy.deepcopy(data)
    enveloped_data["_arp_signature"]["signature"] = ""
    canonical_enveloped = canonicalize(enveloped_data)

    try:
        public_key.verify(signature_bytes, canonical_enveloped)
        return "enveloped"
    except InvalidSignature:
        pass

    # --- Attempt 2: Legacy Payload-only (CLI ≤1.2) ---
    payload = {k: v for k, v in data.items() if k != "_arp_signature"}
    canonical_payload = canonicalize(payload)

    try:
        public_key.verify(signature_bytes, canonical_payload)
        return "payload_only"
    except InvalidSignature:
        pass

    # Both failed
    raise InvalidSignature("Verification failed under both enveloped and payload-only patterns")


def cmd_verify(args):
    """Verify a reasoning.json file against its DNS-published public key.

    Domain-Binding: the DNS name is constructed from the retrieval domain
    (URL) or the --domain flag (local files) combined with dns_selector.
    The dns_record field in the file is treated as an informational hint
    only and is NEVER used as the DNS query source (prevents redirect/
    spoofing attacks).
    """
    # Load source (URL or local file)
    print()
    print(f"  📥 Loading: {args.source}")

    retrieval_domain = None

    if args.source.startswith("http"):
        retrieval_domain = _extract_domain_from_url(args.source)
        try:
            import requests
            response = requests.get(args.source, timeout=15)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            sys.exit(f"  ❌ Error fetching URL: {e}")
    else:
        try:
            with open(args.source, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            sys.exit(f"  ❌ Error loading file: {e}")

        # For local files, try --domain, then fall back to data["domain"]
        if args.domain:
            retrieval_domain = args.domain
        elif "domain" in data:
            retrieval_domain = data["domain"]
            print(f"  ℹ️  Using domain from file: {retrieval_domain}")

    # Step 1: Check for signature block
    sig_block = data.get("_arp_signature")
    if not sig_block:
        print("  ⚠️  No _arp_signature block found.")
        print("  🔓 Trust Level: UNSIGNED")
        print("     This file has not been cryptographically signed.")
        print("     AI agents will apply standard heuristic evaluation.")
        return

    # Step 2: Validate algorithm
    if sig_block.get("algorithm") != "Ed25519":
        sys.exit(f"  ❌ Unsupported algorithm: {sig_block.get('algorithm')}")

    # Step 3: Check expiration
    expires_at = sig_block.get("expires_at")
    expired = False
    if expires_at:
        try:
            exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > exp_dt:
                expired = True
                print(f"  ⏰ Signature EXPIRED at {expires_at}")
                print(f"  🔓 Trust Level: UNSIGNED (soft fallback, not invalid)")
                print()
        except ValueError:
            pass

    # Step 4: Obtain public key
    if args.pubkey:
        # Offline / CI mode: use local public key file
        print(f"  🔑 Using local public key: {args.pubkey}")
        public_key = _load_public_key_file(args.pubkey)
    else:
        # Domain-Binding: construct DNS name from retrieval domain + selector
        selector = sig_block.get("dns_selector", "arp")

        if not retrieval_domain:
            sys.exit(
                "  ❌ Cannot determine verification domain.\n"
                "     For URLs: domain is extracted automatically.\n"
                "     For local files: use --domain <domain> or --pubkey <file>."
            )

        dns_name = f"{selector}._arp.{retrieval_domain}"

        # Check dns_record consistency (informational warning only)
        declared_dns = sig_block.get("dns_record", "")
        if declared_dns and declared_dns != dns_name:
            print(f"  ⚠️  dns_record mismatch: file declares '{declared_dns}', "
                  f"but retrieval domain yields '{dns_name}'.")
            print(f"     Using retrieval-derived name (dns_record is informational only).")

        public_key, _ = _resolve_public_key_dns(dns_name)

    # Step 5: Verify signature (enveloped first, then legacy fallback)
    try:
        sig_bytes_check = b64_decode_tolerant(sig_block["signature"])
    except Exception as e:
        sys.exit(f"  ❌ Malformed signature encoding: {e}\n  🔴 Trust Level: INVALID")

    try:
        method = _verify_signature(public_key, data, sig_block)
    except InvalidSignature:
        print()
        print("  ❌ SIGNATURE VERIFICATION FAILED")
        print("  🔴 Trust Level: INVALID — possible data tampering or poisoning")
        print("     The file content does NOT match the cryptographic signature.")
        print("     AI agents MUST apply maximum skepticism.")
        sys.exit(1)

    # Step 6: Report results
    if retrieval_domain:
        domain = retrieval_domain
    else:
        domain = "(offline verification)"

    print()
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║       ✅ CRYPTOGRAPHIC VERIFICATION PASSED       ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print()

    if method == "payload_only":
        print("  ⚠️  Verification Method: LEGACY_PAYLOAD_ONLY")
        print("     This file was signed with CLI ≤1.2 (payload-only pattern).")
        print("     The signature metadata (expires_at, dns_selector, etc.) is")
        print("     NOT cryptographically protected.")
        print()
        print("     👉 ACTION: Re-sign this file with CLI v1.3+ or the Browser Signer")
        print("        to upgrade to the Enveloped Signature Pattern.")
        print()
    else:
        print(f"  ✅ Verification Method: Enveloped Signature (SPEC §13.4)")
        print()

    print(f"  🛡️  Trust Level:  {'UNSIGNED (expired)' if expired else 'CRYPTOGRAPHIC'}")
    print(f"  🌐 Domain:       {domain}")
    print(f"  🔑 Algorithm:    Ed25519")
    print(f"  📋 Signed at:    {sig_block.get('signed_at', 'unknown')}")
    print(f"  📋 Expires at:   {sig_block.get('expires_at', 'unknown')}")

    # Show signature length info
    sig_len = len(sig_block.get("signature", ""))
    if sig_len == 88 or sig_block.get("signature", "").endswith("=="):
        print(f"  📋 Signature:    {sig_len} chars (padded — consider re-signing for unpadded)")
    else:
        print(f"  📋 Signature:    {sig_len} chars (unpadded base64url ✓)")

    print()
    if not expired:
        print("  This file is cryptographically verified as authored by the domain owner.")
        print("  AI agents MAY treat entity_claims as first-party self-attestation.")
    print()


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ARP Protocol CLI — Cryptographic Trust Layer (v1.3.0)",
        epilog="Docs: https://arp-protocol.org | License: MIT",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- keys ---
    p_keys = subparsers.add_parser("keys", help="Generate Ed25519 keypair + DNS record")
    p_keys.add_argument("--domain", help="Your domain (e.g., example.com)", default="")
    p_keys.add_argument("--selector", help="DNS selector prefix", default="arp")
    p_keys.add_argument("--out-key", help="Output private key path", default="arp_private.pem")

    # --- sign ---
    p_sign = subparsers.add_parser("sign", help="Sign a reasoning.json file (enveloped)")
    p_sign.add_argument("file", help="Path to reasoning.json")
    p_sign.add_argument("--key", required=True, help="Path to private PEM key")
    p_sign.add_argument("--domain", required=True, help="Domain (e.g., example.com)")
    p_sign.add_argument("--selector", default="arp", help="DNS selector")
    p_sign.add_argument("--ttl", type=int, default=90, help="Signature validity in days (default: 90)")
    p_sign.add_argument("--out", help="Output path (default: overwrite input)")

    # --- verify ---
    p_verify = subparsers.add_parser("verify", help="Verify a reasoning.json via DNS or local key")
    p_verify.add_argument("source", help="URL or local path to reasoning.json")
    p_verify.add_argument("--domain", help="Domain for local file verification (e.g., example.com)")
    p_verify.add_argument("--pubkey", help="Path to local public key file (PEM or raw) for offline/CI verification")

    args = parser.parse_args()
    if args.command == "keys":
        cmd_keys(args)
    elif args.command == "sign":
        cmd_sign(args)
    elif args.command == "verify":
        cmd_verify(args)


if __name__ == "__main__":
    main()
