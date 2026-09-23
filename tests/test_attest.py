"""Offline attestation verification against a synthetic chain mimicking YubiKey's layout.

Extension encodings copy what a YubiKey 5 (fw 5.8.0) actually emits (DER INTEGER /
OCTET STRING inside each 1.3.6.1.4.1.41482.5.x extension).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from yketh import _attest, _card, _eth
from yketh.cli import main

SERIAL = 12345678
CREATED = 1_790_000_000
NOW = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _der_int(v: int) -> bytes:
    body = v.to_bytes((v.bit_length() + 8) // 8 or 1, "big")
    return bytes([0x02, len(body)]) + body


def _der_oct(b: bytes) -> bytes:
    return bytes([0x04, len(b)]) + b


def _cert(subject: str, issuer: str, pub, signer, ca: bool,
          exts: dict[str, bytes] | None = None) -> x509.Certificate:
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(NOW).not_valid_after(NOW + dt.timedelta(days=3650)))
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    for oid, raw in (exts or {}).items():
        b = b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), raw), False)
    return b.sign(signer, hashes.SHA256())


@dataclass
class Chain:
    leaf: x509.Certificate
    device: x509.Certificate
    roots: list[x509.Certificate]
    intermediates: list[x509.Certificate]
    address: str
    fingerprint: bytes

    @property
    def bundle(self) -> list[x509.Certificate]:
        return [self.leaf, self.device]

    def verify(self, certs=None, address=None) -> _attest.Attestation:
        return _attest.verify(self.bundle if certs is None else certs, address,
                              self.roots, self.intermediates)


def make_chain(key_source: int = 1) -> Chain:
    root_k, inter_k, dev_k = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    sig_k = ec.generate_private_key(ec.SECP256K1())
    root = _cert("Test Root", "Test Root", root_k.public_key(), root_k, True)
    inter = _cert("Test OPGP CA", "Test Root", inter_k.public_key(), root_k, True)
    device = _cert("Test Device", "Test OPGP CA", dev_k.public_key(), inter_k, True)
    point = _card.point_of(sig_k.public_key())
    fpr = _card.openpgp_v4_fingerprint(point, CREATED)
    y = _attest.YUBICO
    leaf = _cert("Test SIG", "Test Device", sig_k.public_key(), dev_k, False, {
        y + "2": _der_int(key_source),
        y + "3": _der_oct(bytes([5, 8, 0])),
        y + "4": _der_oct(fpr),
        y + "5": _der_oct(CREATED.to_bytes(4, "big")),
        y + "7": _der_int(SERIAL),
        y + "8": _der_oct(b"\x00"),
    })
    return Chain(leaf, device, [root], [inter], _eth.address_from_point(point), fpr)


@pytest.fixture(scope="module")
def chain() -> Chain:
    return make_chain()


def test_verify(chain: Chain) -> None:
    res = chain.verify(address=chain.address)
    assert res.address == chain.address
    assert res.serial == SERIAL
    assert res.firmware == "5.8.0"
    assert res.touch_policy == "OFF"
    assert res.fingerprint == chain.fingerprint.hex()
    assert res.chain == ["CN=Test SIG", "CN=Test Device", "CN=Test OPGP CA", "CN=Test Root"]


def test_imported_key_rejected() -> None:
    with pytest.raises(_attest.AttestationError, match="not 'generated on device'"):
        make_chain(key_source=0).verify()


def test_wrong_address(chain: Chain) -> None:
    with pytest.raises(_attest.AttestationError, match="not 0x"):
        chain.verify(address="0x" + "00" * 20)


def test_missing_device_cert(chain: Chain) -> None:
    with pytest.raises(_attest.AttestationError, match="no trusted issuer"):
        chain.verify(certs=[chain.leaf])


def test_untrusted_root(chain: Chain) -> None:
    """The bundled Yubico roots must not accept a chain from some other CA."""
    with pytest.raises(_attest.AttestationError):
        _attest.verify(chain.bundle)


def test_forged_leaf_rejected(chain: Chain) -> None:
    """Same names and extensions, but signed by an attacker key: must fail."""
    fake_k = ec.generate_private_key(ec.SECP256K1())
    b = (x509.CertificateBuilder().subject_name(chain.leaf.subject)
         .issuer_name(chain.leaf.issuer).public_key(fake_k.public_key())
         .serial_number(1).not_valid_before(NOW).not_valid_after(NOW + dt.timedelta(days=1)))
    for ext in chain.leaf.extensions:
        b = b.add_extension(ext.value, ext.critical)
    with pytest.raises(_attest.AttestationError):
        chain.verify(certs=[b.sign(fake_k, hashes.SHA256()), chain.device])


def test_bundled_cas_load() -> None:
    roots = _attest._load_pems(_attest.ROOT_FILES)
    assert "CN=Yubico Attestation Root 1" in [r.subject.rfc4514_string() for r in roots]


def test_cli_rejects_untrusted(chain: Chain, tmp_path: Path) -> None:
    f = tmp_path / "b.pem"
    f.write_bytes(b"".join(c.public_bytes(Encoding.PEM) for c in chain.bundle))
    with pytest.raises(SystemExit, match="no trusted issuer"):
        main(["verify-attestation", str(f)])
