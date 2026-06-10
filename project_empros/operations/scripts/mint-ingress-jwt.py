#!/usr/bin/env python3
"""
Sentinel Nexus -- Ingress JWT minting tool (C7).

core_ingress requires an HS256 Bearer token with audience "nexus-ingress",
signed by JWT_SECRET (vault_jwt_secret). This is the only production tool
that mints such tokens -- middleware deploy calls it to provision
[nexus].auth_token; operators can also run it manually for sensors.

Stdlib only -- no pip dependencies -- so it runs on any deploy host or CI runner.

Usage:
    mint-ingress-jwt.py --secret <jwt_secret> --subject middleware-forwarder \
                        [--ttl-days 365] [--audience nexus-ingress]
    JWT_SECRET=... mint-ingress-jwt.py --subject sensor-alpha

Prints the signed token to stdout (single line, no trailing whitespace).
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import time


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def mint(secret: str, subject: str, audience: str, ttl_days: int) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": subject,
        "aud": audience,
        "iat": now,
        "exp": now + ttl_days * 86400,
        "iss": "nexus-deploy",
    }
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url(json.dumps(payload, separators=(",", ":")).encode())
    )
    signature = hmac.new(
        secret.encode(), signing_input.encode("ascii"), hashlib.sha256
    ).digest()
    return signing_input + "." + b64url(signature)


def main() -> int:
    parser = argparse.ArgumentParser(description="Mint a Nexus ingress JWT (HS256)")
    parser.add_argument("--secret", default=os.environ.get("JWT_SECRET", ""),
                        help="Signing secret (or set JWT_SECRET env)")
    parser.add_argument("--subject", required=True,
                        help="Token subject, e.g. middleware-forwarder")
    parser.add_argument("--audience", default="nexus-ingress",
                        help="Token audience (must match ingress validation)")
    parser.add_argument("--ttl-days", type=int, default=365,
                        help="Token lifetime in days (default 365)")
    args = parser.parse_args()

    if not args.secret:
        print("ERROR: no signing secret (use --secret or JWT_SECRET env)", file=sys.stderr)
        return 1
    if args.secret.startswith("CHANGE_ME") or args.secret == "Generated_JWT_Secret":
        print("ERROR: refusing to sign with a placeholder secret -- set a real "
              "vault_jwt_secret first", file=sys.stderr)
        return 1

    print(mint(args.secret, args.subject, args.audience, args.ttl_days))
    return 0


if __name__ == "__main__":
    sys.exit(main())
