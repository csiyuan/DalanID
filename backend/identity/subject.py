"""
Subject access.

A tamper-evident record of every disclosure is worth little if the person the
disclosures are about cannot read it. Contextual integrity is a claim about
whether information flows match the norms of the context it was gathered in,
and the citizen is the only party positioned to notice when they do not. The
audit chain existed from the start; until this module, only operators could see
it.

Authentication reuses the same primitive as Context-Keys — HMAC-SHA256 over a
canonical payload — but with a separate secret held on the citizen record. The
separation is the point: a relying party must not be able to read a citizen's
audit trail, and a citizen must not be able to invoke a disclosure context.
Sharing one secret space would make both possible.

What this is not. A token here is bearer authentication over a demonstration
channel; a deployment would use the citizen's own authenticated session, and
the token would be short-lived and bound to that session. The mechanism is
sound, the enrolment story around it is out of scope for this project and is
recorded as such.
"""

import hashlib
import hmac
import json

from django.utils import timezone

from .keys import _b64decode, _b64encode
from .models import Citizen

TOKEN_TTL_SECONDS = 900

MISSING = "SUBJECT_TOKEN_MISSING"
MALFORMED = "SUBJECT_TOKEN_MALFORMED"
BAD_SIGNATURE = "SUBJECT_TOKEN_BAD_SIGNATURE"
EXPIRED = "SUBJECT_TOKEN_EXPIRED"
UNKNOWN = "SUBJECT_UNKNOWN"
MISMATCH = "SUBJECT_MISMATCH"

DETAIL = {
    MISSING: "No X-Subject-Token header was supplied.",
    MALFORMED: "The subject token is not a well-formed token.",
    BAD_SIGNATURE: "The subject token signature did not verify.",
    EXPIRED: "The subject token has expired.",
    UNKNOWN: "No such citizen record.",
    MISMATCH: "This token does not authorise access to that record.",
}


def _sign(payload_b64: str, secret: str) -> str:
    return _b64encode(
        hmac.new(
            secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256
        ).digest()
    )


def issue_subject_token(citizen: Citizen, ttl_seconds: int = TOKEN_TTL_SECONDS) -> str:
    """Mint a token authorising a citizen to read their own history."""
    now = int(timezone.now().timestamp())
    payload = _b64encode(
        json.dumps(
            {"sub": citizen.public_id, "iat": now, "exp": now + ttl_seconds},
            sort_keys=True, separators=(",", ":"),
        ).encode()
    )
    return f"{payload}.{_sign(payload, citizen.access_secret)}"


def verify_subject_token(raw_token: str | None, public_id: str):
    """Verify a subject token and confirm it names the record requested.

    Returns ``(citizen, reason)``. On success ``reason`` is empty.

    The final check matters most: a token valid for one citizen must not grant
    access to another's history. Verifying the signature without comparing the
    subject claim to the record being requested would turn any valid token into
    a master key.
    """
    if not raw_token:
        return None, MISSING

    parts = raw_token.split(".")
    if len(parts) != 2 or not all(parts):
        return None, MALFORMED

    payload_b64, signature = parts
    try:
        claims = json.loads(_b64decode(payload_b64))
    except (ValueError, TypeError):
        return None, MALFORMED
    if not isinstance(claims, dict) or "sub" not in claims or "exp" not in claims:
        return None, MALFORMED

    citizen = Citizen.objects.filter(public_id=claims["sub"]).first()
    if citizen is None or not citizen.access_secret:
        return None, UNKNOWN

    if not hmac.compare_digest(
        _sign(payload_b64, citizen.access_secret), signature
    ):
        return None, BAD_SIGNATURE

    try:
        if timezone.now().timestamp() >= int(claims["exp"]):
            return None, EXPIRED
    except (TypeError, ValueError):
        return None, MALFORMED

    if citizen.public_id != public_id:
        return None, MISMATCH

    return citizen, ""
