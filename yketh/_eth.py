"""Ethereum-side glue: addresses, low-s normalization, recovery id, transaction encoding.

The card only returns raw ECDSA ``(r, s)`` over a 32-byte digest; everything that makes
it an Ethereum signature happens here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from eth_account._utils.legacy_transactions import (
    Transaction,
    UnsignedTransaction,
    encode_transaction,
    serializable_unsigned_transaction_from_dict,
)
from eth_account.messages import defunct_hash_message
from eth_account.typed_transactions import TypedTransaction
from eth_keys import keys
from eth_utils import keccak, to_checksum_address

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

Signer = Callable[[bytes], tuple[int, int]]
"""Takes a 32-byte digest, returns raw ECDSA (r, s)."""


def address_from_point(point: bytes) -> str:
    """Checksummed address from an uncompressed SEC1 point (0x04 || X || Y)."""
    if len(point) != 65 or point[0] != 0x04:
        raise ValueError("expected a 65-byte uncompressed secp256k1 point")
    return to_checksum_address(keccak(point[1:])[-20:])


def normalize_s(s: int) -> int:
    """EIP-2: Ethereum rejects high-s signatures."""
    return SECP256K1_N - s if s > SECP256K1_N // 2 else s


def recovery_id(digest: bytes, r: int, s: int, point: bytes) -> int:
    """Find y-parity (0/1) such that (digest, r, s, y) recovers to ``point``."""
    expected = keys.PublicKey(point[1:])
    for y in (0, 1):
        try:
            sig = keys.Signature(vrs=(y, r, s))
            if sig.recover_public_key_from_msg_hash(digest) == expected:
                return y
        except Exception:  # noqa: BLE001, S112 - invalid candidate point
            continue
    raise ValueError("signature does not match the card public key")


def sign_digest(digest: bytes, signer: Signer, point: bytes) -> tuple[int, int, int]:
    """Return Ethereum-ready (y_parity, r, s) for ``digest``."""
    if len(digest) != 32:
        raise ValueError("digest must be 32 bytes")
    r, s = signer(digest)
    s = normalize_s(s)
    return recovery_id(digest, r, s, point), r, s


def sign_transaction(tx: Mapping[str, Any], signer: Signer, point: bytes) -> dict[str, Any]:
    """Sign a transaction dict (typed EIP-2718 or legacy EIP-155)."""
    tx = {k: v for k, v in tx.items() if k != "from"}
    unsigned = serializable_unsigned_transaction_from_dict(tx)
    digest = bytes(unsigned.hash())
    y, r, s = sign_digest(digest, signer, point)
    if isinstance(unsigned, TypedTransaction):
        v = y
    elif isinstance(unsigned, Transaction):  # EIP-155: chain id stored in v
        v = y + 35 + 2 * unsigned.v
    elif isinstance(unsigned, UnsignedTransaction):
        v = y + 27
    else:
        raise TypeError(f"unknown transaction type: {type(unsigned)}")
    raw = encode_transaction(unsigned, vrs=(v, r, s))
    return {"raw_transaction": "0x" + raw.hex(), "hash": "0x" + keccak(raw).hex(),
            "v": v, "r": hex(r), "s": hex(s)}


def sign_message(text: str, signer: Signer, point: bytes) -> str:
    """EIP-191 personal_sign; returns 65-byte r || s || v (v = 27/28) hex."""
    digest = bytes(defunct_hash_message(text=text))
    y, r, s = sign_digest(digest, signer, point)
    return "0x" + (r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + y])).hex()
