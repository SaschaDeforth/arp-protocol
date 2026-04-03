#!/usr/bin/env python3
"""
ARP Protocol CLI — Cryptographic Trust Layer (v1.2)
Command-line tool for generating keys, signing and verifying reasoning.json files.

Usage:
    arp keys --domain truesource.studio
    arp sign reasoning.json --key arp_private.pem --domain truesource.studio
    arp verify https://truesource.studio/reasoning.json

Dependencies:
    pip install cryptography json-canon dnspython requests

License: MIT
Author: Sascha Deforth (TrueSource)
"""

import argparse
import json
import base64
import sys
from datetime import datetime, timezone, timedelta

try:
    from json_canon import canonicalize
except ImportError:
    sys.exit("Missing dependency: pip install json-canon")

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
# ─────────────────────────────────────────────

def cmd_sign(args):
    """Sign a reasoning.json file with JCS canonicalization + Ed25519."""
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

    # Step 1: Remove existing signature (for re-signing)
    data.pop("_arp_signature", None)

    # Step 2: JCS Canonicalization (RFC 8785)
    # Produces deterministic byte output regardless of whitespace or key ordering
    canonical_bytes = canonicalize(data)

    # Step 3: Sign with Ed25519
    signature = private_key.sign(canonical_bytes)
    signature_b64 = base64.urlsafe_b64encode(signature).decode("ascii")

    # Step 4: Build signature block
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
        "signature": signature_b64,
    }

    # Save signed file
    out_file = args.out if args.out else args.file
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║  ARP Cryptographic Trust Layer — File Signed     ║")
    print("╚══════════════════════════════════════════════════╝")
    print()
    print(f"  ✅ Signed file saved to: {out_file}")
    print(f"  📋 Algorithm:     Ed25519")
    print(f"  📋 Canonicalize:  RFC 8785 (JCS)")
    print(f"  📋 DNS Record:    {selector}._arp.{args.domain}")
    print(f"  📋 Signed at:     {now.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"  📋 Expires at:    {expires.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"  📋 Payload size:  {len(canonical_bytes)} bytes")
    print()


# ─────────────────────────────────────────────
# COMMAND: verify — Verify a reasoning.json
# ─────────────────────────────────────────────

def cmd_verify(args):
    """Verify a reasoning.json file against its DNS-published public key."""
    import dns.resolver

    # Load source (URL or local file)
    print()
    print(f"  📥 Loading: {args.source}")

    if args.source.startswith("http"):
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

    # Step 4: Resolve DNS TXT record
    dns_record = sig_block.get("dns_record")
    print(f"  🔍 Looking up DNS: {dns_record}")

    try:
        answers = dns.resolver.resolve(dns_record, "TXT")
        txt_value = None
        for rdata in answers:
            txt_str = rdata.to_text().strip('"')
            if txt_str.startswith("v=ARP1"):
                txt_value = txt_str
                break

        if not txt_value:
            sys.exit(f"  ❌ No ARP1 TXT record found at {dns_record}")

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
        sys.exit(f"  ❌ DNS lookup failed: {e}\n  🔴 Trust Level: INVALID")

    print(f"  ✅ DNS record found: {txt_value[:60]}...")

    # Step 5: Parse public key from DNS
    parts = {}
    for segment in txt_value.split(";"):
        segment = segment.strip()
        if "=" in segment:
            k, v = segment.split("=", 1)
            parts[k.strip()] = v.strip()

    if parts.get("k") != "ed25519":
        sys.exit(f"  ❌ Algorithm mismatch: DNS says '{parts.get('k')}', file says 'Ed25519'")

    try:
        public_key_bytes = base64.b64decode(parts["p"])
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except Exception as e:
        sys.exit(f"  ❌ Error decoding public key: {e}")

    # Step 6: Reconstruct canonical payload (exclude _arp_signature)
    payload = {k: v for k, v in data.items() if k != "_arp_signature"}
    canonical_bytes = canonicalize(payload)

    # Step 7: Verify Ed25519 signature
    try:
        signature_bytes = base64.urlsafe_b64decode(sig_block["signature"])
        public_key.verify(signature_bytes, canonical_bytes)
    except InvalidSignature:
        print()
        print("  ❌ SIGNATURE VERIFICATION FAILED")
        print("  🔴 Trust Level: INVALID — possible data tampering or poisoning")
        print("     The file content does NOT match the cryptographic signature.")
        print("     AI agents MUST apply maximum skepticism.")
        sys.exit(1)

    # Success
    domain = dns_record.replace(f"{sig_block.get('dns_selector', 'arp')}._arp.", "")
    print()
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║       ✅ CRYPTOGRAPHIC VERIFICATION PASSED       ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print()
    print(f"  🛡️  Trust Level:  {'UNSIGNED (expired)' if expired else 'CRYPTOGRAPHIC'}")
    print(f"  🌐 Domain:       {domain}")
    print(f"  🔑 Algorithm:    Ed25519")
    print(f"  📋 Signed at:    {sig_block.get('signed_at', 'unknown')}")
    print(f"  📋 Expires at:   {sig_block.get('expires_at', 'unknown')}")
    print(f"  📋 Payload:      {len(canonical_bytes)} bytes")
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
        description="ARP Protocol CLI — Cryptographic Trust Layer (v1.2)",
        epilog="Docs: https://arp-protocol.org | License: MIT",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- keys ---
    p_keys = subparsers.add_parser("keys", help="Generate Ed25519 keypair + DNS record")
    p_keys.add_argument("--domain", help="Your domain (e.g., example.com)", default="")
    p_keys.add_argument("--selector", help="DNS selector prefix", default="arp")
    p_keys.add_argument("--out-key", help="Output private key path", default="arp_private.pem")

    # --- sign ---
    p_sign = subparsers.add_parser("sign", help="Sign a reasoning.json file")
    p_sign.add_argument("file", help="Path to reasoning.json")
    p_sign.add_argument("--key", required=True, help="Path to private PEM key")
    p_sign.add_argument("--domain", required=True, help="Domain (e.g., example.com)")
    p_sign.add_argument("--selector", default="arp", help="DNS selector")
    p_sign.add_argument("--ttl", type=int, default=90, help="Signature validity in days (default: 90)")
    p_sign.add_argument("--out", help="Output path (default: overwrite input)")

    # --- verify ---
    p_verify = subparsers.add_parser("verify", help="Verify a reasoning.json via DNS")
    p_verify.add_argument("source", help="URL or local path to reasoning.json")

    args = parser.parse_args()
    if args.command == "keys":
        cmd_keys(args)
    elif args.command == "sign":
        cmd_sign(args)
    elif args.command == "verify":
        cmd_verify(args)


if __name__ == "__main__":
    main()
