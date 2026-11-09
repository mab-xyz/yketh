"""Card wrapper tested with a fake OpenPGP session, plus opt-in hardware test."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from eth_account import Account
from yubikit.openpgp import OID, EcAttributes

from yketh import _attest, _card, _eth

TX = json.loads((Path(__file__).parent / "tx1559.json").read_text())


class FakeProtocol:
    def __init__(self, resp: bytes) -> None:
        self.resp, self.sent = resp, []

    def send_apdu(self, cla, ins, p1, p2, data):
        self.sent.append((cla, ins, p1, p2, data))
        return self.resp


def fake_card(resp: bytes = b"\x01" * 64, oid=OID.SECP256K1) -> _card.Card:
    session = SimpleNamespace(
        protocol=FakeProtocol(resp),
        get_algorithm_attributes=lambda ref: EcAttributes.create(ref, oid),
    )
    return _card.Card(session, 1)  # type: ignore[arg-type]


def test_sign_digest_sends_raw_pso_cds() -> None:
    card = fake_card()
    r, s = card.sign_digest(b"\xab" * 32)
    assert card.session.protocol.sent == [(0, 0x2A, 0x9E, 0x9A, b"\xab" * 32)]
    assert r == s == int.from_bytes(b"\x01" * 32, "big")


def test_sign_digest_rejects_non_digest() -> None:
    with pytest.raises(ValueError):
        fake_card().sign_digest(b"tx bytes, not a hash")


def test_sign_digest_rejects_wrong_curve() -> None:
    with pytest.raises(_card.CardError):
        fake_card(oid=OID.SECP256R1).sign_digest(b"\x00" * 32)


def test_open_card_none_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_card, "list_ccid_devices", list)
    with pytest.raises(_card.CardError, match="no YubiKey found"), _card.open_card():
        pass


def test_open_card_several_needs_serial(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_card, "list_ccid_devices", lambda: [object(), object()])
    with pytest.raises(_card.CardError, match="pass --serial"), _card.open_card():
        pass


def test_open_card_serial_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_card, "list_ccid_devices", lambda: [SimpleNamespace(s=1), SimpleNamespace(s=2)])
    monkeypatch.setattr(_card, "_serial_of", lambda d: d.s)
    with pytest.raises(_card.CardError, match="with serial 3"), _card.open_card(3):
        pass


@pytest.mark.hardware
def test_hardware_end_to_end() -> None:
    """Signs with the real card key (default PIN) without regenerating it."""
    with _card.open_card() as card:
        point = card.point()
        card.verify_pin("123456")
        res = _eth.sign_transaction(TX, card.sign_digest, point)
        leaf, att = card.attest("123456")
    addr = _eth.address_from_point(point)
    assert Account.recover_transaction(res["raw_transaction"]) == addr
    assert _attest.verify([leaf, att], addr).address == addr
