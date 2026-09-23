"""yketh command line: Ethereum signing with a YubiKey's on-card secp256k1 key."""

from __future__ import annotations

import argparse
import dataclasses
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from yubikit.openpgp import UIF

from . import _attest, _eth
from ._card import CardError, open_card


def _pin(env: str, prompt: str) -> str:
    return os.environ.get(env) or getpass.getpass(prompt)


def _emit(args: argparse.Namespace, data: dict[str, Any], text: str) -> None:
    print(json.dumps(data, indent=2) if args.json else text)


def cmd_info(args: argparse.Namespace) -> None:
    with open_card(args.serial) as card:
        i = card.info()
    d = dataclasses.asdict(i)
    _emit(args, d, "\n".join(f"{k:14s} {v}" for k, v in d.items()))


def cmd_address(args: argparse.Namespace) -> None:
    with open_card(args.serial) as card:
        addr = _eth.address_from_point(card.point())
    _emit(args, {"address": addr}, addr)


def cmd_generate(args: argparse.Namespace) -> None:
    if not args.yes:
        ans = input("⚠️  This destroys the current OpenPGP signature key on the card. Type 'yes': ")
        if ans.strip() != "yes":
            sys.exit("aborted")
    with open_card(args.serial) as card:
        point = card.generate(_pin("YKETH_ADMIN_PIN", "Admin PIN: "))
        fpr = card.info().fingerprint
    addr = _eth.address_from_point(point)
    _emit(args, {"address": addr, "fingerprint": fpr}, addr)


def _signing(args: argparse.Namespace, fn: Any, payload: Any) -> Any:
    with open_card(args.serial) as card:
        point = card.point()
        card.verify_pin(_pin("YKETH_PIN", "PIN: "))
        return fn(payload, card.sign_digest, point)


def cmd_sign_tx(args: argparse.Namespace) -> None:
    tx = json.loads(Path(args.tx).read_text())
    res = _signing(args, _eth.sign_transaction, tx)
    _emit(args, res, res["raw_transaction"])


def cmd_sign_msg(args: argparse.Namespace) -> None:
    sig = _signing(args, _eth.sign_message, args.message)
    _emit(args, {"message": args.message, "signature": sig}, sig)


def cmd_attest(args: argparse.Namespace) -> None:
    with open_card(args.serial) as card:
        leaf, att = card.attest(_pin("YKETH_PIN", "PIN: "))
    pem = leaf.public_bytes(Encoding.PEM) + att.public_bytes(Encoding.PEM)
    res = _attest.verify([leaf, att])
    if args.output:
        Path(args.output).write_bytes(pem)
    bundle = args.output or pem.decode()
    _emit(args, dataclasses.asdict(res) | {"bundle": bundle},
          f"✅ {res.address} attested → {args.output}" if args.output else pem.decode().rstrip())


def cmd_verify(args: argparse.Namespace) -> None:
    certs = x509.load_pem_x509_certificates(Path(args.bundle).read_bytes())
    res = _attest.verify(certs, args.address)
    d = dataclasses.asdict(res)
    head = (f"✅ {res.address}: private key generated inside YubiKey "
            f"{res.serial} (fw {res.firmware}), not exportable")
    text = "\n".join([head, *(f"   ↳ {c}" for c in res.chain)])
    _emit(args, d, text)


def cmd_touch(args: argparse.Namespace) -> None:
    uif = {"off": UIF.OFF, "on": UIF.ON, "cached": UIF.CACHED}[args.policy]
    with open_card(args.serial) as card:
        card.set_touch(_pin("YKETH_ADMIN_PIN", "Admin PIN: "), uif)
        t = card.info().sig_touch
    _emit(args, {"sig_touch": t}, t)


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                        help="machine-readable output")
    common.add_argument("--serial", type=int, default=argparse.SUPPRESS,
                        help="YubiKey serial (if several are connected)")
    p = argparse.ArgumentParser(prog="yketh", description=__doc__, parents=[common])
    p.set_defaults(json=False, serial=None)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name: str, help: str) -> argparse.ArgumentParser:
        return sub.add_parser(name, help=help, parents=[common])

    add("info", "OpenPGP SIG slot status").set_defaults(fn=cmd_info)
    add("address", "Ethereum address of the card key").set_defaults(fn=cmd_address)
    g = add("generate", "generate a new secp256k1 key on the card (destructive)")
    g.add_argument("--yes", action="store_true", help="skip confirmation")
    g.set_defaults(fn=cmd_generate)
    t = add("sign-tx", "sign a transaction JSON file, print raw tx")
    t.add_argument("tx")
    t.set_defaults(fn=cmd_sign_tx)
    m = add("sign-msg", "EIP-191 personal_sign a text message")
    m.add_argument("message")
    m.set_defaults(fn=cmd_sign_msg)
    a = add("attest", "export attestation bundle (proof of on-card generation)")
    a.add_argument("-o", "--output", help="write PEM bundle here")
    a.set_defaults(fn=cmd_attest)
    v = add("verify-attestation", "verify a bundle offline, no card needed")
    v.add_argument("bundle")
    v.add_argument("--address", help="also require the attested key to be this address")
    v.set_defaults(fn=cmd_verify)
    u = add("touch", "require touch for each signature")
    u.add_argument("policy", choices=["off", "on", "cached"])
    u.set_defaults(fn=cmd_touch)
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        args.fn(args)
    except (CardError, _attest.AttestationError, ValueError) as e:
        sys.exit(f"❌ {e}")


if __name__ == "__main__":
    main()
