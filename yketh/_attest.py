"""Offline verification of YubiKey OpenPGP attestation: proof the key was generated on-card.

Chain: attestation cert (SIG key) <- device ATT cert <- Yubico OPGP Attestation CA
       <- Yubico Attestation Intermediate <- Yubico Attestation Root 1
(or the legacy self-signed "Yubico OpenPGP Attestation CA" for fw < 5.7.4).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources

from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier

from ._card import point_of
from ._eth import address_from_point

YUBICO = "1.3.6.1.4.1.41482.5."
OID_KEY_SOURCE = ObjectIdentifier(YUBICO + "2")
OID_FIRMWARE = ObjectIdentifier(YUBICO + "3")
OID_FINGERPRINT = ObjectIdentifier(YUBICO + "4")
OID_GENERATION_DATE = ObjectIdentifier(YUBICO + "5")
OID_SERIAL = ObjectIdentifier(YUBICO + "7")
OID_UIF = ObjectIdentifier(YUBICO + "8")
OID_FORM_FACTOR = ObjectIdentifier(YUBICO + "9")

KEY_SOURCE_GENERATED = 0x01
UIF_NAMES = {0: "OFF", 1: "ON", 2: "FIXED", 3: "CACHED", 4: "CACHED_FIXED"}

ROOT_FILES = ("yubico-ca-1.pem", "yubico-opgp-ca-1.pem")
INTERMEDIATE_FILES = ("yubico-intermediate.pem",)


class AttestationError(Exception):
    """Attestation chain or content does not prove on-card generation."""


@dataclass
class Attestation:
    address: str
    key_source: str
    serial: int | None
    firmware: str | None
    touch_policy: str | None
    fingerprint: str | None
    chain: list[str] = field(default_factory=list)


def _load_pems(names: tuple[str, ...]) -> list[x509.Certificate]:
    pkg = resources.files("yketh") / "cas"
    certs: list[x509.Certificate] = []
    for n in names:
        certs += x509.load_pem_x509_certificates((pkg / n).read_bytes())
    return certs


def _raw(cert: x509.Certificate, oid: ObjectIdentifier) -> bytes | None:
    try:
        ext = cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None
    return bytes(getattr(ext, "value", b""))


def _int(data: bytes | None) -> int | None:
    if data is None:
        return None
    if len(data) >= 2 and data[0] in (0x02, 0x04) and data[1] == len(data) - 2:  # DER INT/OCTET
        data = data[2:]
    return int.from_bytes(data, "big")


def _build_chain(leaf: x509.Certificate, extra: list[x509.Certificate],
                 roots: list[x509.Certificate],
                 intermediates: list[x509.Certificate]) -> list[x509.Certificate]:
    pool = extra + intermediates
    chain = [leaf]
    for _ in range(8):
        cur = chain[-1]
        for root in roots:
            if cur.issuer == root.subject:
                try:
                    cur.verify_directly_issued_by(root)
                except Exception as e:
                    raise AttestationError(f"bad signature by {root.subject.rfc4514_string()}") from e
                return chain + ([root] if root != cur else [])
        parents = [c for c in pool if c.subject == cur.issuer and c != cur]
        for p in parents:
            try:
                cur.verify_directly_issued_by(p)
            except Exception:  # noqa: BLE001, S112 - try next candidate with same name
                continue
            chain.append(p)
            break
        else:
            raise AttestationError(f"no trusted issuer for {cur.subject.rfc4514_string()}")
    raise AttestationError("chain too long")


def verify(certs: list[x509.Certificate], address: str | None = None,
           roots: list[x509.Certificate] | None = None,
           intermediates: list[x509.Certificate] | None = None) -> Attestation:
    """Verify ``[attestation_cert, device_att_cert, ...]``; optionally pin the address.

    ``roots``/``intermediates`` default to the bundled Yubico CAs.
    """
    if not certs:
        raise AttestationError("empty bundle")
    leaf = certs[0]
    chain = _build_chain(leaf, certs[1:],
                         _load_pems(ROOT_FILES) if roots is None else roots,
                         _load_pems(INTERMEDIATE_FILES) if intermediates is None else intermediates)
    source = _int(_raw(leaf, OID_KEY_SOURCE))
    if source != KEY_SOURCE_GENERATED:
        raise AttestationError(f"key source is {source!r}, not 'generated on device' (0x01)")
    got = address_from_point(point_of(leaf.public_key()))
    if address is not None and got.lower() != address.lower():
        raise AttestationError(f"attested key is {got}, not {address}")
    fw = _raw(leaf, OID_FIRMWARE)
    uif = _int(_raw(leaf, OID_UIF))
    fpr = _raw(leaf, OID_FINGERPRINT)
    return Attestation(
        address=got,
        key_source="generated on device",
        serial=_int(_raw(leaf, OID_SERIAL)),
        firmware=".".join(str(b) for b in fw[-3:]) if fw else None,
        touch_policy=UIF_NAMES.get(uif, str(uif)) if uif is not None else None,
        fingerprint=fpr[-20:].hex() if fpr else None,
        chain=[c.subject.rfc4514_string() for c in chain],
    )
