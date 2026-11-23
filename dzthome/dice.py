"""Emulated DICE (Device Identifier Composition Engine) for DZT-Home devices.

A device has a unique device secret (UDS) and firmware. As in DICE:
  FWID  = SHA-256(firmware)
  CDI   = HMAC-SHA-256(UDS, FWID)            (Compound Device Identifier)
  DeviceID key = KDF(UDS)                    (stable, enrolled at the gateway)
  Alias key    = KDF(CDI)                    (changes whenever firmware changes)
  Alias cert   = Sign_DeviceID(alias_pub || FWID)
On real hardware the UDS is fused into the chip and only the immutable boot
stage can read it; here it is a random value held by the emulated device.
"""
import hashlib, hmac, os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CURVE = ec.SECP256R1()
N = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


def _derive_key(seed: bytes, label: bytes) -> ec.EllipticCurvePrivateKey:
    okm = HKDF(algorithm=hashes.SHA256(), length=48, salt=None, info=label).derive(seed)
    d = int.from_bytes(okm, "big") % (N - 1) + 1
    return ec.derive_private_key(d, CURVE)


def pub_bytes(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.X962,
                                         serialization.PublicFormat.CompressedPoint)


def load_pub(b: bytes):
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, b)


def fwid_of(firmware: bytes) -> str:
    return hashlib.sha256(firmware).hexdigest()


class DiceDevice:
    """Identity half of an emulated device (boot ROM + layer-0 behaviour)."""

    def __init__(self, uds: bytes | None = None):
        self._uds = uds or os.urandom(32)
        self.device_key = _derive_key(self._uds, b"DICE-DeviceID")
        self.firmware = b""
        self.fwid = ""
        self.alias_key = None
        self.alias_cert = b""

    def boot(self, firmware: bytes):
        """Measured boot: derive CDI and alias identity from the firmware."""
        self.firmware = firmware
        self.fwid = fwid_of(firmware)
        cdi = hmac.new(self._uds, bytes.fromhex(self.fwid), hashlib.sha256).digest()
        self.alias_key = _derive_key(cdi, b"DICE-Alias")
        self.alias_cert = self.device_key.sign(pub_bytes(self.alias_key) + bytes.fromhex(self.fwid),
                                               ec.ECDSA(hashes.SHA256()))

    @property
    def device_id(self) -> str:
        return hashlib.sha256(pub_bytes(self.device_key)).hexdigest()[:16]

    def attest(self, nonce: bytes, request: bytes) -> dict:
        sig = self.alias_key.sign(nonce + bytes.fromhex(self.fwid) + request, ec.ECDSA(hashes.SHA256()))
        return {"alias_pub": pub_bytes(self.alias_key).hex(), "alias_cert": self.alias_cert.hex(),
                "fwid": self.fwid, "sig": sig.hex()}


def verify_attestation(device_pub: bytes, ev: dict, nonce: bytes, request: bytes) -> bool:
    """Gateway-side check of the certificate chain and the signature."""
    from cryptography.exceptions import InvalidSignature
    try:
        alias_pub = bytes.fromhex(ev["alias_pub"])
        load_pub(device_pub).verify(bytes.fromhex(ev["alias_cert"]),
                                    alias_pub + bytes.fromhex(ev["fwid"]), ec.ECDSA(hashes.SHA256()))
        load_pub(alias_pub).verify(bytes.fromhex(ev["sig"]),
                                   nonce + bytes.fromhex(ev["fwid"]) + request, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False
