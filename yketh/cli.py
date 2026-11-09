"""yketh command line: Ethereum signing with a YubiKey's on-card secp256k1 key.

Follows hw-wallet-cli-spec (https://github.com/mab-xyz/hw-wallet-cli-spec): the sign
commands print one JSON object; `address` and `info` print key=value lines, JSON with --json.
"""

from __future__ import annotations

import argparse
import dataclasses
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any

from . import _eth
from ._card import CardError, open_card


def _pin(env: str, prompt: str) -> str:
    """PIN from $ENV, else from the file named by $ENV_FILE (must not be group/other
    readable), else asked interactively."""
    if pin := os.environ.get(env):
        return pin
    if path := os.environ.get(f"{env}_FILE"):
        p = Path(path).expanduser()
        if p.stat().st_mode & 0o077:
            raise ValueError(f"{p} is accessible by group/others, chmod 600 it")
        return p.read_text().strip()
    return getpass.getpass(prompt)


def _print_json(data: dict[str, Any]) -> None:
    print(json.dumps(data, indent=2))


def _emit(args: argparse.Namespace, data: dict[str, Any]) -> None:
    """key=value lines, or JSON with --json."""
    if args.json:
        _print_json(data)
    else:
        print("\n".join(f"{k}={v}" for k, v in data.items()))


def _read_input(path: str) -> str:
    return sys.stdin.read() if path == "-" else Path(path).read_text()


def _hex(value: str, what: str, size: int | None = None) -> bytes:
    try:
        raw = bytes.fromhex(value.removeprefix("0x"))
    except ValueError:
        raise ValueError(f"{what} is not hex") from None
    if size is not None and len(raw) != size:
        raise ValueError(f"{what} must be {size} bytes, got {len(raw)}")
    return raw


def cmd_info(args: argparse.Namespace) -> None:
    with open_card(args.device, want_serial=True) as card:
        i = card.info()
    _emit(args, dataclasses.asdict(i))


def cmd_address(args: argparse.Namespace) -> None:
    with open_card(args.device) as card:
        point = card.point()
    _emit(args, _eth.address_info(point))


def cmd_generate(args: argparse.Namespace) -> None:
    if not args.yes:
        ans = input("⚠️  This destroys the current OpenPGP signature key on the card. Type 'yes': ")
        if ans.strip() != "yes":
            sys.exit("aborted")
    with open_card(args.device) as card:
        point = card.generate(_pin("YKETH_ADMIN_PIN", "Admin PIN: "))
        fpr = card.info().fingerprint
    _emit(args, {"address": _eth.address_from_point(point), "fingerprint": fpr})


def _signing(args: argparse.Namespace, fn: Any, payload: Any) -> None:
    """Sign with the card (PIN once per call) and print the JSON object `fn` returns."""
    with open_card(args.device) as card:
        point = card.point()
        card.verify_pin(_pin("YKETH_PIN", "PIN: "))
        _print_json(fn(payload, card.sign_digest, point))


def cmd_sign_digest(args: argparse.Namespace) -> None:
    _signing(args, _eth.sign_digest_json, _hex(args.digest, "--digest", 32))


def cmd_sign_tx(args: argparse.Namespace) -> None:
    _signing(args, _eth.sign_transaction, json.loads(_read_input(args.tx)))


def cmd_sign_personal(args: argparse.Namespace) -> None:
    if args.message is not None:
        msg = args.message.encode()
    elif args.message_hex is not None:
        msg = _hex(args.message_hex, "--message-hex")
    else:
        msg = Path(args.message_file).read_bytes()
    _signing(args, _eth.sign_personal, msg)


def cmd_sign_typed_data(args: argparse.Namespace) -> None:
    _signing(args, _eth.sign_typed_data, json.loads(_read_input(args.typed_data)))


def cmd_attest(args: argparse.Namespace) -> None:
    from cryptography.hazmat.primitives.serialization import Encoding

    from . import _attest

    with open_card(args.device) as card:
        leaf, att = card.attest(_pin("YKETH_PIN", "PIN: "))
    pem = leaf.public_bytes(Encoding.PEM) + att.public_bytes(Encoding.PEM)
    res = _attest.verify([leaf, att])
    if args.out:
        Path(args.out).write_bytes(pem)
    if args.json:
        _print_json(dataclasses.asdict(res) | {"bundle": args.out or pem.decode()})
    else:
        print(f"✅ {res.address} attested → {args.out}" if args.out else pem.decode().rstrip())


def cmd_verify(args: argparse.Namespace) -> None:
    from cryptography import x509

    from . import _attest

    certs = x509.load_pem_x509_certificates(Path(args.cert).read_bytes())
    res = _attest.verify(certs, args.address)
    if args.json:
        _print_json(dataclasses.asdict(res))
    else:
        head = (f"✅ {res.address}: private key generated inside YubiKey "
                f"{res.serial} (fw {res.firmware}), not exportable")
        print("\n".join([head, *(f"   ↳ {c}" for c in res.chain)]))


def cmd_touch(args: argparse.Namespace) -> None:
    from yubikit.openpgp import UIF

    uif = {"off": UIF.OFF, "on": UIF.ON, "cached": UIF.CACHED}[args.policy]
    with open_card(args.device) as card:
        card.set_touch(_pin("YKETH_ADMIN_PIN", "Admin PIN: "), uif)
        t = card.info().sig_touch
    _emit(args, {"sig_touch": t})


def build_parser() -> argparse.ArgumentParser:
    device = argparse.ArgumentParser(add_help=False)
    device.add_argument("--device", type=int, default=None, metavar="SERIAL",
                        help="YubiKey serial number (if several are connected)")
    as_json = argparse.ArgumentParser(add_help=False)
    as_json.add_argument("--json", action="store_true", help="print JSON instead of key=value lines")
    p = argparse.ArgumentParser(prog="yketh", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name: str, help: str, *, json_flag: bool = False) -> argparse.ArgumentParser:
        return sub.add_parser(name, help=help, parents=[device, as_json] if json_flag else [device])

    add("info", "OpenPGP SIG slot status", json_flag=True).set_defaults(fn=cmd_info)
    add("address", "public key and Ethereum address of the card key", json_flag=True).set_defaults(fn=cmd_address)
    g = add("generate", "generate a new secp256k1 key on the card (destructive)", json_flag=True)
    g.add_argument("--yes", action="store_true", help="skip confirmation")
    g.set_defaults(fn=cmd_generate)
    d = add("sign-digest", "sign a 32-byte digest")
    d.add_argument("--digest", required=True, metavar="HEX", help="32-byte digest as hex")
    d.set_defaults(fn=cmd_sign_digest)
    t = add("sign-tx", "sign a transaction JSON, print the signed transaction")
    t.add_argument("--tx", default="-", metavar="FILE", help="unsigned transaction JSON, or - for stdin")
    t.set_defaults(fn=cmd_sign_tx)
    m = add("sign-personal", "EIP-191 personal_sign")
    one = m.add_mutually_exclusive_group(required=True)
    one.add_argument("--message", help="UTF-8 message")
    one.add_argument("--message-hex", metavar="HEX", help="message bytes as hex")
    one.add_argument("--message-file", metavar="FILE", help="file with the message bytes")
    m.set_defaults(fn=cmd_sign_personal)
    y = add("sign-typed-data", "sign EIP-712 typed data")
    y.add_argument("--typed-data", default="-", metavar="FILE", help="typed data JSON, or - for stdin")
    y.set_defaults(fn=cmd_sign_typed_data)
    a = add("attest", "export the attestation bundle (proof of on-card generation)", json_flag=True)
    a.add_argument("--out", metavar="FILE", help="write the PEM bundle here")
    a.set_defaults(fn=cmd_attest)
    v = sub.add_parser("verify", help="verify an attestation bundle offline, no card needed", parents=[as_json])
    v.add_argument("--cert", required=True, metavar="FILE", help="PEM bundle written by attest")
    v.add_argument("--address", help="also require the attested key to be this address")
    v.set_defaults(fn=cmd_verify)
    u = add("touch", "require touch for each signature", json_flag=True)
    u.add_argument("policy", choices=["off", "on", "cached"])
    u.set_defaults(fn=cmd_touch)
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        args.fn(args)
    except (CardError, ValueError) as e:
        sys.exit(f"❌ {e}")
    except Exception as e:
        from ._attest import AttestationError  # lazy: pulls in cryptography's x509

        if isinstance(e, AttestationError):
            sys.exit(f"❌ {e}")
        raise


if __name__ == "__main__":
    main()
