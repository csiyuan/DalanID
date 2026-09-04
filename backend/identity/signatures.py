"""
Signature suites for Context-Keys.

The original design signed Context-Keys with HMAC-SHA256 under a secret shared
between the relying party and the service. That gives authenticity and
integrity, but not non-repudiation: the verifying service holds the same secret
it verifies with, so it could mint a key and afterwards attribute it to the
relying party. In a national identity service this is the wrong property. The
operator of the disclosure log is precisely the party a citizen or a regulator
might need to hold to account, and a scheme in which the operator can forge a
relying party's request undermines the log's evidential value.

Ed25519 (Josefsson and Liusvaara, 2017) closes this. The relying party holds a
private key and signs locally; the service holds only the corresponding public
key and can verify but not produce a signature. A compromise of the service's
database therefore yields no ability to impersonate any relying party.

Both suites are supported, and the reason is migration rather than indecision:
an operational federation cannot re-key every participant simultaneously, so
parties move to Ed25519 individually while the rest continue on HMAC.

Algorithm confusion
-------------------
Supporting two suites introduces the vulnerability class that has repeatedly
affected JWT implementations: if the token states its own algorithm, an
attacker chooses it. The two classic forms are downgrade — presenting an HMAC
signature against a party registered for a public-key suite, where a naive
implementation verifies the HMAC using the *public* key as the shared secret,
which the attacker also knows — and the ``alg: none`` variant, where the token
declares that it is unsigned.

The defence here is structural rather than a special case: **the algorithm is a
property of the relying party's registration, not of the token**. The ``alg``
claim is recorded for diagnostics and never consulted when choosing a verifier.
A token claiming HMAC against an Ed25519-registered party is verified as
Ed25519, fails, and is refused.
"""

import hashlib
import hmac

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ED25519 = "ed25519"
HMAC_SHA256 = "hmac-sha256"

SUITES = (ED25519, HMAC_SHA256)

# Claim value advertised in the payload. Recorded, never trusted.
ALG_NAME = {ED25519: "EdDSA", HMAC_SHA256: "HS256"}


# ------------------------------------------------------------- key material

def generate_ed25519_keypair() -> tuple[str, str]:
    """Return ``(private_pem, public_pem)``.

    The service stores the private key only so that the demonstration can sign
    on a relying party's behalf. In deployment the private key never leaves the
    relying party and the service holds the public key alone.
    """
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return private_pem, public_pem


def load_private_key(pem: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Not an Ed25519 private key.")
    return key


def load_public_key(pem: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Not an Ed25519 public key.")
    return key


# ----------------------------------------------------------- sign / verify

def sign(suite: str, payload_b64: str, relying_party) -> bytes:
    """Produce a signature over the encoded payload."""
    message = payload_b64.encode("ascii")
    if suite == ED25519:
        return load_private_key(relying_party.private_key).sign(message)
    if suite == HMAC_SHA256:
        return hmac.new(
            relying_party.signing_secret.encode("utf-8"),
            message,
            hashlib.sha256,
        ).digest()
    raise ValueError(f"Unknown signature suite: {suite}")


def verify(suite: str, payload_b64: str, signature: bytes,
           relying_party) -> bool:
    """Check a signature under the suite the relying party is registered for.

    ``suite`` is supplied by the caller from the party's registration. It is
    never read from the token; see the module docstring.
    """
    message = payload_b64.encode("ascii")

    if suite == ED25519:
        if not relying_party.public_key:
            return False
        try:
            load_public_key(relying_party.public_key).verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False

    if suite == HMAC_SHA256:
        if not relying_party.signing_secret:
            return False
        expected = hmac.new(
            relying_party.signing_secret.encode("utf-8"),
            message,
            hashlib.sha256,
        ).digest()
        # Constant-time: a byte-wise comparison would leak, through response
        # timing, how much of a guessed signature was correct.
        return hmac.compare_digest(expected, signature)

    return False
