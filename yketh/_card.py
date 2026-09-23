"""YubiKey OpenPGP applet access: secp256k1 key in the SIG slot, raw PSO:CDS signing."""

from __future__ import annotations

import hashlib
import struct
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from ykman.device import list_all_devices
from yubikit.core.smartcard import SmartCardConnection
from yubikit.openpgp import INS, KEY_REF, KEY_STATUS, OID, UIF, EcAttributes, OpenPgpSession

ALG_ECDSA = 19
SECP256K1_OID = bytes(OID.SECP256K1)


class CardError(Exception):
    """Card missing, wrong key type, or refused operation."""


@dataclass
class CardInfo:
    serial: int | None
    firmware: str
    sig_algorithm: str
    key_present: bool
    key_status: str
    sig_touch: str
    fingerprint: str


def point_of(key: object) -> bytes:
    """Uncompressed SEC1 point of a secp256k1 public key."""
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256k1":
        raise CardError(f"SIG key is not secp256k1: {key!r}")
    return key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def openpgp_v4_fingerprint(point: bytes, created: int) -> bytes:
    """RFC 4880 v4 fingerprint of an ECDSA secp256k1 public key packet."""
    mpi = struct.pack(">H", len(point) * 8 - (8 - point[0].bit_length())) + point
    body = (bytes([4]) + struct.pack(">I", created) + bytes([ALG_ECDSA, len(SECP256K1_OID)])
            + SECP256K1_OID + mpi)
    return hashlib.sha1(b"\x99" + struct.pack(">H", len(body)) + body).digest()


class Card:
    """Thin wrapper over an open OpenPGP session."""

    def __init__(self, session: OpenPgpSession, serial: int | None) -> None:
        self.session = session
        self.serial = serial

    def _is_k1(self) -> bool:
        attrs = self.session.get_algorithm_attributes(KEY_REF.SIG)
        return isinstance(attrs, EcAttributes) and bytes(attrs.oid) == SECP256K1_OID

    def info(self) -> CardInfo:
        s = self.session
        attrs = s.get_algorithm_attributes(KEY_REF.SIG)
        status = s.get_key_information().get(KEY_REF.SIG, KEY_STATUS.NONE)
        fpr = s.get_fingerprints().get(KEY_REF.SIG, b"")
        return CardInfo(
            serial=self.serial,
            firmware=str(s.version),
            sig_algorithm=(f"ECDSA {attrs.oid}" if isinstance(attrs, EcAttributes) else str(attrs)),
            key_present=status != KEY_STATUS.NONE,
            key_status=status.name,
            sig_touch=s.get_uif(KEY_REF.SIG).name,
            fingerprint=fpr.hex(),
        )

    def point(self) -> bytes:
        if not self._is_k1():
            raise CardError("SIG slot is not configured for secp256k1; run `yketh generate`")
        return point_of(self.session.get_public_key(KEY_REF.SIG))

    def generate(self, admin_pin: str) -> bytes:
        """Generate a fresh secp256k1 SIG key on the card (destroys the previous one)."""
        s = self.session
        s.verify_admin(admin_pin)
        point = point_of(s.generate_ec_key(KEY_REF.SIG, OID.SECP256K1))
        created = int(time.time())
        s.set_generation_time(KEY_REF.SIG, created)
        s.set_fingerprint(KEY_REF.SIG, openpgp_v4_fingerprint(point, created))
        return point

    def verify_pin(self, pin: str) -> None:
        self.session.verify_pin(pin)

    def sign_digest(self, digest: bytes) -> tuple[int, int]:
        """Raw ECDSA over a 32-byte digest via PSO:COMPUTE DIGITAL SIGNATURE."""
        if len(digest) != 32:
            raise ValueError("digest must be 32 bytes")
        if not self._is_k1():
            raise CardError("SIG slot is not configured for secp256k1")
        resp = self.session.protocol.send_apdu(0, INS.PSO, 0x9E, 0x9A, digest)
        if len(resp) != 64:
            raise CardError(f"unexpected signature length {len(resp)}")
        return int.from_bytes(resp[:32], "big"), int.from_bytes(resp[32:], "big")

    def attest(self, pin: str) -> tuple[x509.Certificate, x509.Certificate]:
        """Return (attestation cert for SIG, device ATT cert)."""
        self.session.verify_pin(pin)
        leaf = self.session.attest_key(KEY_REF.SIG)
        att = self.session.get_certificate(KEY_REF.ATT)
        return leaf, att

    def set_touch(self, admin_pin: str, uif: UIF) -> None:
        self.session.verify_admin(admin_pin)
        self.session.set_uif(KEY_REF.SIG, uif)


@contextmanager
def open_card(serial: int | None = None) -> Iterator[Card]:
    devices = [(d, i) for d, i in list_all_devices() if serial is None or i.serial == serial]
    if not devices:
        raise CardError("no YubiKey found" + (f" with serial {serial}" if serial else ""))
    if len(devices) > 1:
        raise CardError("several YubiKeys connected; pass --serial")
    device, info = devices[0]
    with device.open_connection(SmartCardConnection) as conn:
        yield Card(OpenPgpSession(conn), info.serial)
