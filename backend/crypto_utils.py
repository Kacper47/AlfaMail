"""Server-side checks on key material uploaded by clients.

The server performs NO encryption or decryption of messages: that happens in the
browser (see frontend/js/crypto.js). Here we only validate that what a client
uploads as a "public key" really is a sane RSA public key, so that nobody can
register garbage that would later break other users' clients.
"""
import base64
import binascii

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

MIN_RSA_BITS = 2048
MAX_RSA_BITS = 4096


def validate_rsa_spki(b64_der: str) -> None:
    """Raise ValueError unless `b64_der` is a base64 SPKI DER RSA key of acceptable size."""
    try:
        der = base64.b64decode(b64_der, validate=True)
        key = load_der_public_key(der)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise ValueError("not a valid public key") from exc

    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("public key must be RSA")
    if not (MIN_RSA_BITS <= key.key_size <= MAX_RSA_BITS):
        raise ValueError("RSA key size out of range")
