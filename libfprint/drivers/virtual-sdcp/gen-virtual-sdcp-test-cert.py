#!/usr/bin/env python3
"""
Generate the virtual SDCP test PKI used by the virtual SDCP driver.

PKI structure:
  SDCP Virtual Test Root CA  (self-signed, CA:TRUE)
       └── SDCP Virtual Test Model  (signed by Root CA, CA:FALSE)

The Root CA certificate is written to the driver's own CA store directory
(drivers/virtual-sdcp/) so that it is compiled into the
virtual-sdcp driver's GResource and supplied at runtime via the
get_ca_store vfunc.  It is never part of the default SDCP CA store.
The model certificate's public key comes from
SecureDeviceConnectionProtocol/src/test/testkeys.c.

Usage:
    cd libfprint/drivers/virtual-sdcp/
    python3 gen-virtual-sdcp-test-cert.py
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicNumbers,
    SECP256R1,
)
import datetime
import pathlib
import sys

# ---------------------------------------------------------------------------
# Fixed test root CA key material (P-256, generated once for reproducibility)
# ---------------------------------------------------------------------------

ROOT_CA_PRIV_KEY = bytes.fromhex(
    "df341a190c038c7b36431201df64b26461033c228d202dd13567fdd61afd36b9"
)
ROOT_CA_PUB_KEY = bytes.fromhex(
    "04487c36f9a5dec90c85f4043669f725e60319a5995d92eb80d49210396f00c23"
    "c9a6a021b8e25ad4fe0d24018a41746bbb07b0c75c37a88d8a926269dc90f4f2a"
)

# ---------------------------------------------------------------------------
# Model key material from SecureDeviceConnectionProtocol/src/test/testkeys.c
# ---------------------------------------------------------------------------

MODEL_PRIV_KEY = bytes([
    0x54, 0x96, 0x11, 0x1c, 0x96, 0x5e, 0xf4, 0x1c,
    0x9c, 0xf9, 0x1e, 0x54, 0xb3, 0x8d, 0x71, 0x4b,
    0x4e, 0x7d, 0x7c, 0x48, 0x2d, 0xcb, 0x34, 0xa3,
    0xec, 0x5e, 0x72, 0x65, 0xcf, 0x6e, 0xc8, 0x00,
])

# Uncompressed P-256 point (0x04 || x || y)
MODEL_PUB_KEY = bytes([
    0x04,
    0xc5, 0xeb, 0x2c, 0x24, 0xde, 0x08, 0xa4, 0xdd,
    0x9c, 0xfd, 0x42, 0xc5, 0xbc, 0x56, 0x10, 0x27,
    0x7d, 0x49, 0x21, 0x11, 0xf1, 0x51, 0xbf, 0x33,
    0xad, 0x71, 0xad, 0x95, 0x25, 0x40, 0x1d, 0x00,
    0xd9, 0x32, 0x09, 0x76, 0xc3, 0xc8, 0x39, 0x80,
    0xfa, 0xb2, 0x79, 0xd0, 0x4d, 0x1f, 0xc9, 0xf4,
    0x19, 0x6d, 0xa4, 0xd6, 0x8a, 0x2f, 0x3b, 0x68,
    0x91, 0x18, 0x9a, 0xf2, 0x31, 0xbf, 0x50, 0x88,
])

# ---------------------------------------------------------------------------
# Build root CA (self-signed, goes into CA store)
# ---------------------------------------------------------------------------

def _ec_key_pair(priv_bytes, pub_bytes):
    x   = int.from_bytes(pub_bytes[1:33], 'big')
    y   = int.from_bytes(pub_bytes[33:65], 'big')
    pub = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()
    priv = EllipticCurvePrivateNumbers(
        int.from_bytes(priv_bytes, 'big'),
        EllipticCurvePublicNumbers(x, y, SECP256R1()),
    ).private_key()
    return priv, pub

root_priv, root_pub = _ec_key_pair(ROOT_CA_PRIV_KEY, ROOT_CA_PUB_KEY)

ROOT_CA_CN   = "SDCP Virtual Test Root CA"   # Must start with "SDCP Virtual" — see fpi-sdcp.c
root_ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ROOT_CA_CN)])

root_ca_cert = (
    x509.CertificateBuilder()
    .subject_name(root_ca_name)
    .issuer_name(root_ca_name)
    .public_key(root_pub)
    .serial_number(1)
    .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
    .not_valid_after(datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_pub), critical=False)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        ),
        critical=True,
    )
    .sign(root_priv, hashes.SHA256())
)

# ---------------------------------------------------------------------------
# Build model certificate (signed by root CA, contains testkeys.c model pubkey)
# ---------------------------------------------------------------------------

model_priv, model_pub = _ec_key_pair(MODEL_PRIV_KEY, MODEL_PUB_KEY)

MODEL_CN    = "SDCP Virtual Test Model"
model_name  = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, MODEL_CN)])

model_cert = (
    x509.CertificateBuilder()
    .subject_name(model_name)
    .issuer_name(root_ca_name)
    .public_key(model_pub)
    .serial_number(2)
    .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
    .not_valid_after(datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(model_pub), critical=False)
    .add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(root_pub), critical=False
    )
    .sign(root_priv, hashes.SHA256())
)

der = model_cert.public_bytes(serialization.Encoding.DER)

# ---------------------------------------------------------------------------
# Build expired model certificate (same root and model keys, past validity)
# ---------------------------------------------------------------------------

EXPIRED_MODEL_CN   = "SDCP Virtual Test Model Expired"
expired_model_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, EXPIRED_MODEL_CN)])

expired_model_cert = (
    x509.CertificateBuilder()
    .subject_name(expired_model_name)
    .issuer_name(root_ca_name)
    .public_key(model_pub)
    .serial_number(3)
    .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
    .not_valid_after(datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(model_pub), critical=False)
    .add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(root_pub), critical=False
    )
    .sign(root_priv, hashes.SHA256())
)

expired_der = expired_model_cert.public_bytes(serialization.Encoding.DER)

# ---------------------------------------------------------------------------
# Print C string literal for virtual-sdcp.h
# ---------------------------------------------------------------------------

hex_str = der.hex()
padding = " " * 47
chunks  = [f'"{hex_str[i:i+64]}"' for i in range(0, len(hex_str), 64)]
c_value = ("\n" + padding).join(chunks)

print("/* Paste into virtual-sdcp.h as model_certificate_hex: */")
print(f"static const gchar model_certificate_hex[]   = {c_value};")
print()

expired_hex_str = expired_der.hex()
expired_padding = " " * 52
expired_chunks  = [f'"{expired_hex_str[i:i+64]}"' for i in range(0, len(expired_hex_str), 64)]
expired_c_value = ("\n" + expired_padding).join(expired_chunks)

print("/* Paste into virtual-sdcp.h as expired_model_certificate_hex: */")
print(f"static const gchar expired_model_certificate_hex[] = {expired_c_value};")
print()

# ---------------------------------------------------------------------------
# Write root CA PEM to CA store; remove the old self-signed model CA if present
# ---------------------------------------------------------------------------

here = pathlib.Path(__file__).resolve().parent

root_ca_pem_path = here / f"{ROOT_CA_CN}.pem"
force_root_ca_regenerate = "--force-recreate-root-ca" in sys.argv

if root_ca_pem_path.exists() and not force_root_ca_regenerate:
    print(f"Root CA PEM already exists, not overwriting")
else:
    root_ca_pem_path.write_text(
        root_ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    )
    print(f"Root CA PEM written to: {root_ca_pem_path.relative_to(here.parent.parent)}")

old_model_ca = here / "SDCP Virtual Test Model CA.pem"
if old_model_ca.exists():
    old_model_ca.unlink()
    print(f"Removed old self-signed model CA: {old_model_ca.relative_to(here.parent.parent)}")
print()
print("Note: the Root CA PEM is compiled into the virtual-sdcp driver's GResource")
print("via drivers/virtual-sdcp/ and supplied at runtime through the")
print("get_ca_store vfunc.  It is never part of the default SDCP CA store.")
