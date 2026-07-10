"""
comply54.cli
~~~~~~~~~~~~
Command-line interface for comply54 signed receipts.

Commands:
  verify-receipt    Verify a comply54 signed receipt JWT token.
  generate-keypair  Generate a new Ed25519 keypair for receipt signing.

Usage:
    comply54 verify-receipt <token> --public-key <path/to/public.pem>
    comply54 generate-keypair [--out <directory>]
    comply54 verify-receipt --help
"""

from __future__ import annotations

import argparse
import sys


def _cmd_verify_receipt(args: argparse.Namespace) -> int:
    try:
        from ..receipts import InvalidReceiptError, digest_input, verify_receipt
    except ImportError:
        print(
            "error: Receipt verification requires PyJWT and cryptography.\n"
            "Install with:  pip install 'comply54[signing]'",
            file=sys.stderr,
        )
        return 1

    token = args.token
    try:
        with open(args.public_key, "rb") as fh:
            public_key_pem = fh.read()
    except OSError as exc:
        print(f"error: Cannot read public key: {exc}", file=sys.stderr)
        return 1

    try:
        payload = verify_receipt(token, public_key_pem)
    except InvalidReceiptError as exc:
        print(f"INVALID — {exc}", file=sys.stderr)
        return 2

    status = "ALLOW" if payload.decision == "allow" else payload.decision.upper()
    print(f"comply54 receipt  {status}")
    print(f"  jti              {payload.jti}")
    print(f"  issued_at        {payload.issued_at}")
    print(f"  comply54_version {payload.comply54_version}")
    print(f"  decision         {payload.decision}")
    if payload.pack:
        print(f"  pack             {payload.pack}")
    if payload.regulation:
        print(f"  regulation       {payload.regulation}")
    if payload.rule_triggered:
        print(f"  rule_triggered   {payload.rule_triggered}")
    if payload.messages:
        print(f"  messages[0]      {payload.messages[0]}")
    print(f"  input_digest     {payload.input_digest}")
    print(f"  packs_evaluated  {', '.join(payload.packs_evaluated)}")

    if args.action or args.params_json or args.output or args.context_json:
        import json

        action = args.action or ""
        params = json.loads(args.params_json) if args.params_json else {}
        output = args.output or ""
        context = json.loads(args.context_json) if args.context_json else {}
        recomputed = digest_input(action, params, output, context)
        match = recomputed == payload.input_digest
        print()
        print(f"  input match      {'YES' if match else 'NO — digest mismatch'}")
        if not match:
            print(f"    expected  {payload.input_digest}", file=sys.stderr)
            print(f"    got       {recomputed}", file=sys.stderr)
            return 3

    return 0


def _cmd_generate_keypair(args: argparse.Namespace) -> int:
    try:
        from ..receipts import ReceiptSigner
    except ImportError:
        print(
            "error: Key generation requires cryptography.\n"
            "Install with:  pip install 'comply54[signing]'",
            file=sys.stderr,
        )
        return 1

    import os

    private_pem, public_pem = ReceiptSigner.generate_keypair()

    out_dir = args.out or "."
    os.makedirs(out_dir, exist_ok=True)

    priv_path = os.path.join(out_dir, "comply54_signing_key.pem")
    pub_path = os.path.join(out_dir, "comply54_signing_key.pub.pem")

    with open(priv_path, "wb") as fh:
        fh.write(private_pem)
    with open(pub_path, "wb") as fh:
        fh.write(public_pem)

    print("Ed25519 keypair generated:")
    print(f"  private key  {priv_path}")
    print(f"  public key   {pub_path}")
    print()
    print("Keep the private key secret — store it in your secret manager.")
    print("Distribute the public key to receipt verifiers.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="comply54",
        description="comply54 — African AI governance compliance toolkit",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    scan = sub.add_parser(
        "scan",
        help="Run governance checks from the command line.",
    )
    scan.add_argument("--action", help="Action to evaluate.")
    scan.add_argument("--params", default="{}", metavar="JSON", help="Action parameters as JSON.")
    scan.add_argument("--context", default="{}", metavar="JSON", help="Scenario context as JSON.")
    scan.add_argument(
        "--output", default="", metavar="TEXT", help="Proposed agent output to evaluate."
    )
    scan.add_argument("--pack", action="append", dest="packs", help="Policy pack ID (repeatable).")
    scan.add_argument("--config", metavar="PATH", help="YAML file containing packs and scenarios.")
    scan.add_argument("--format", choices=("table", "json", "html"), default="table")
    scan.add_argument("--report", metavar="PATH", help="Write HTML output to this file.")

    # ── verify-receipt ──────────────────────────────────────────────────────
    vr = sub.add_parser(
        "verify-receipt",
        help="Verify a comply54 signed receipt JWT token.",
        description=(
            "Verify a comply54 signed receipt JWT token against an Ed25519 public key.\n"
            "Optionally pass the original input to confirm the receipt covers that exact call."
        ),
    )
    vr.add_argument("token", help="The JWT receipt token from ComplianceResult.receipt_token.")
    vr.add_argument(
        "--public-key",
        required=True,
        metavar="PATH",
        help="Path to the Ed25519 public key PEM file.",
    )
    vr.add_argument(
        "--action",
        metavar="ACTION",
        help="Original action string — used to verify input_digest.",
    )
    vr.add_argument(
        "--params-json",
        metavar="JSON",
        help="Original params as a JSON string — used to verify input_digest.",
    )
    vr.add_argument(
        "--output",
        metavar="TEXT",
        help="Original output string — used to verify input_digest.",
    )
    vr.add_argument(
        "--context-json",
        metavar="JSON",
        help="Original context as a JSON string — used to verify input_digest.",
    )

    # ── generate-keypair ────────────────────────────────────────────────────
    gk = sub.add_parser(
        "generate-keypair",
        help="Generate a new Ed25519 keypair for comply54 receipt signing.",
        description=(
            "Generate a new Ed25519 keypair.\n"
            "WARNING: for development / CI only. In production, use your secret manager."
        ),
    )
    gk.add_argument(
        "--out",
        metavar="DIR",
        help="Output directory for the keypair files (default: current directory).",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "verify-receipt":
        sys.exit(_cmd_verify_receipt(args))
    elif args.command == "scan":
        from .scan import run_scan

        sys.exit(run_scan(args))
    elif args.command == "generate-keypair":
        sys.exit(_cmd_generate_keypair(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
