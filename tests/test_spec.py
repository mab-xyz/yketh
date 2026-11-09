"""yketh against hw-wallet-cli-spec: `--help` flags, and golden JSON built with a software signer."""

from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path

import hw_wallet_cli_spec as spec_pkg
from test_attest import make_chain
from test_eth import MAIL, POINT, TX, soft_signer

from yketh import _eth


def test_help_conforms() -> None:
    assert spec_pkg.check([sys.executable, "-m", "yketh.cli"], spec_pkg.load_spec()) == []


def test_golden_conforms(tmp_path: Path) -> None:
    samples = {
        "address": _eth.address_info(POINT),
        "sign-digest": _eth.sign_digest_json(bytes(range(32)), soft_signer, POINT),
        "sign-tx": _eth.sign_transaction(TX, soft_signer, POINT),
        "sign-personal": _eth.sign_personal(b"hi", soft_signer, POINT),
        "sign-typed-data": _eth.sign_typed_data(MAIL, soft_signer, POINT),
        "attest": dataclasses.asdict(make_chain().verify()),
        "verify": dataclasses.asdict(make_chain().verify()),
    }
    for command, sample in samples.items():
        (tmp_path / f"{command}.json").write_text(json.dumps(sample))
    spec = spec_pkg.load_spec()
    assert set(samples) == set(spec["commands"])
    assert spec_pkg.check([sys.executable, "-m", "yketh.cli"], spec, tmp_path) == []
