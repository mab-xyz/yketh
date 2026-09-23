"""Ethereum glue tested against a software secp256k1 key standing in for the card."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_keys import keys

from yketh import _eth

PRIV = keys.PrivateKey(bytes.fromhex("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"))
POINT = b"\x04" + PRIV.public_key.to_bytes()
ADDR = PRIV.public_key.to_checksum_address()
TX = json.loads((Path(__file__).parent / "tx1559.json").read_text())


def soft_signer(digest: bytes) -> tuple[int, int]:
    _, r, s = PRIV.sign_msg_hash(digest).vrs
    return r, s


def high_s_signer(digest: bytes) -> tuple[int, int]:
    """Mimic a card returning the high-s twin (valid ECDSA, invalid for Ethereum)."""
    r, s = soft_signer(digest)
    return r, _eth.SECP256K1_N - s


def test_address_from_point() -> None:
    assert _eth.address_from_point(POINT) == ADDR


def test_address_rejects_compressed() -> None:
    with pytest.raises(ValueError):
        _eth.address_from_point(POINT[:33])


def test_normalize_s() -> None:
    n = _eth.SECP256K1_N
    assert _eth.normalize_s(1) == 1
    assert _eth.normalize_s(n - 1) == 1


@pytest.mark.parametrize("signer", [soft_signer, high_s_signer])
def test_sign_1559_recovers(signer) -> None:
    res = _eth.sign_transaction(TX, signer, POINT)
    assert Account.recover_transaction(res["raw_transaction"]) == ADDR
    assert int(res["s"], 16) <= _eth.SECP256K1_N // 2
    assert res["raw_transaction"] == Account.sign_transaction(TX, PRIV.to_bytes()).raw_transaction.to_0x_hex()


def test_sign_legacy_eip155() -> None:
    tx = {"nonce": 1, "gasPrice": 10**9, "gas": 21000, "to": TX["to"], "value": 1,
          "data": "0x", "chainId": 1}
    res = _eth.sign_transaction(tx, soft_signer, POINT)
    assert res["v"] in (37, 38)
    assert Account.recover_transaction(res["raw_transaction"]) == ADDR


def test_sign_message() -> None:
    sig = _eth.sign_message("hi", high_s_signer, POINT)
    assert Account.recover_message(encode_defunct(text="hi"), signature=sig) == ADDR


def test_wrong_key_detected() -> None:
    other = b"\x04" + keys.PrivateKey(b"\x01" * 32).public_key.to_bytes()
    with pytest.raises(ValueError, match="does not match"):
        _eth.sign_transaction(TX, soft_signer, other)


def test_digest_length() -> None:
    with pytest.raises(ValueError):
        _eth.sign_digest(b"\x00" * 31, soft_signer, POINT)
