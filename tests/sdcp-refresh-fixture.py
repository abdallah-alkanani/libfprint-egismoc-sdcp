#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Regenerate the synthetic Egis SDCP nonce replay from its public recording.

Requires Python cryptography only when regenerating, not when running tests.
No hardware, private device keys, or network access is needed. The ECDH host
key and nonces are the existing public test values; the attestation is copied
from tests/egismoc/custom.pcapng. Both signatures are independently verified
before any output is written. KDF/MAC follow Microsoft's SDCP reference client.
"""

import hashlib
import hmac
from pathlib import Path
import re
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


root = Path(__file__).resolve().parent.parent
text = (root / "libfprint/fpi-sdcp-device.c").read_text()


def value(name):
    match = re.search(r"\btest_" + name + r"\[\]\s*=\s*\{(.*?)\}", text, re.S)
    assert match, name
    return bytes(int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", match[1]))


def kdf(key, label, context, length):
    return b"".join(
        hmac.digest(key, i.to_bytes(4, "big") + label + b"\0" + context
                    + (length * 8).to_bytes(4, "big"), "sha256")
        for i in range(1, (length + 31) // 32 + 1)
    )[:length]


def verify(key, signature, message):
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    key.verify(utils.encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))


capture = (root / "tests/egismoc/custom.pcapng").read_bytes()
assert hashlib.sha256(capture).hexdigest() in (
    "2d10da4c3cd57d6220b8c4bc2f8e1e011f55779b9cf3bb14ec44d01bf3fbf48d",
    "5de511b570ef3b3ab425d713e2e688e7a14e753bd8b9a71f2f897a61dca65ab8",
)
cert_offset = capture.index(bytes.fromhex("032730820323308202ca")) + 2
cert_bytes = capture[cert_offset:cert_offset + 807]
offset = cert_offset + len(cert_bytes)
names = ("device_public_key", "firmware_public_key", "firmware_hash",
         "model_signature", "device_signature")
vectors = {}
for name, size in zip(names, (65, 65, 32, 64, 64)):
    vectors[name] = capture[offset:offset + size]
    assert len(vectors[name]) == size
    offset += size

verify(x509.load_der_x509_certificate(cert_bytes).public_key(),
       vectors["model_signature"], vectors["device_public_key"])
verify(ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), vectors["device_public_key"]),
       vectors["device_signature"],
       b"\xc0\x01" + vectors["firmware_hash"] + vectors["firmware_public_key"])

host_key = ec.derive_private_key(int.from_bytes(value("host_private_key"), "big"), ec.SECP256R1())
# Update the two identification exchanges in the replay for a nonzero nonce.
# This is a synthetic transformation of the old recording, not a new hardware
# capture. Enrollment duplicate-check commands deliberately keep their zeros.
capture = bytearray(capture)
position = 0
identifying = False
pending = False
changed = 0
capture_secret = None
while position < len(capture):
    block_type, block_length = struct.unpack_from("<II", capture, position)
    assert block_length >= 12 and block_length % 4 == 0
    assert struct.unpack_from("<I", capture, position + block_length - 4)[0] == block_length
    if block_type == 6:  # Enhanced Packet Block, with a 64-byte usbmon header.
        packet_length = struct.unpack_from("<I", capture, position + 20)[0]
        start = position + 28 + 64
        end = position + 28 + packet_length
        packet = capture[start:end]
        if packet.startswith(b"SIGE") and cert_bytes in packet:
            cert_offset = packet.index(cert_bytes)
            assert cert_offset == 49
            fw_key = packet[cert_offset + len(cert_bytes) + 65:cert_offset + len(cert_bytes) + 130]
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(fw_key))
            capture_master = kdf(host_key.exchange(ec.ECDH(), peer), b"master secret",
                                 value("host_random") + packet[15:47], 32)
            capture_secret = kdf(capture_master, b"application keys", b"", 64)[:32]
            expected = hmac.digest(capture_secret, b"connect\0"
                                   + hashlib.sha256(packet[49:-34]).digest(), "sha256")
            assert hmac.compare_digest(expected, packet[-34:-2])
        if packet.startswith(b"EGIS"):
            if packet[10:] == bytes.fromhex("0000000450170101"):
                identifying = True
            elif packet[10:] == bytes.fromhex("0000000450170100"):
                identifying = False
            if identifying and packet[14:19] == bytes.fromhex("5017030000"):
                assert packet[21:53] in (bytes(32), value("identify_nonce"))
                packet[21:53] = value("identify_nonce")
                packet[8:10] = bytes(2)
                padded = packet + bytes(len(packet) % 2)
                checksum = 65535 - sum(x[0] for x in struct.iter_unpack(">H", padded)) % 65535
                packet[8:10] = checksum.to_bytes(2, "big")
                pending = True
        elif pending and packet.startswith(b"SIGE"):
            assert len(packet) == 80 and packet[-2:] == b"\x90\0"
            old = hmac.digest(capture_secret, b"identify\0" + bytes(32) + packet[46:78], "sha256")
            fresh = hmac.digest(capture_secret, b"identify\0" + value("identify_nonce")
                                + packet[46:78], "sha256")
            assert packet[14:46] in (old, fresh)
            packet[14:46] = fresh
            packet[8:10] = bytes(2)
            checksum = 65535 - sum(x[0] for x in struct.iter_unpack(">H", packet)) % 65535
            packet[8:10] = checksum.to_bytes(2, "big")
            changed += 1
            pending = False
        capture[start:end] = packet
    position += block_length
assert changed == 2 and not pending
(root / "tests/egismoc/custom.pcapng").write_bytes(capture)
print("Refreshed two synthetic nonce exchanges; capture SHA256:", hashlib.sha256(capture).hexdigest())
