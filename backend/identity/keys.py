"""
Context-Key issuance and verification.

A Context-Key is the credential a relying party presents to request disclosure.
It is a compact two-part token::

    base64url(payload) . base64url(HMAC-SHA256(payload, rp_secret))

The payload binds three things together: which relying party is asking, which
context they are asking under, and when the key stops being valid. Because all
three are inside the signed region, none can be altered in transit without
invalidating the signature. This is what the browser prototype could not do:
there, the Context-Key was a plaintext string such as ``CTX-IMM-1A2B`` that
named a context but proved nothing about who was presenting it.

Verification is deliberately layered, and each layer has its own reason code so
that a refusal is diagnostic rather than a bare 401. The layers are, in order:

    1. structural    is this even a well-formed token?
    2. identity      is the named relying party registered and active?
    3. cryptographic does the signature verify under that party's secret?
    4. temporal      has the key expired?
    5. authorisation is the context live, and does this party hold a grant?

Ordering note. The relying party must be identified *before* the signature can
be checked, because the secret needed to verify the signature belongs to that
party. Identity is therefore read from an as-yet-unverified payload. This is
the same pattern as the ``kid`` header in JWS (RFC 7515) and is safe only
because the unverified value is used for exactly one purpose - selecting a
candidate secret - and nothing in the payload is trusted until step 3 passes.

Threat model. HMAC gives authenticity and integrity under a shared secret; it
does not give non-repudiation, since the verifying service holds the same
secret it verifies with and could therefore mint a key it later attributes to
the relying party. A production deployment would use asymmetric signatures
(Ed25519) so that only the relying party can sign. That limitation is stated
here because it is a real property of the design, not an oversight.
"""

import base64
import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from datetime import timezone as dt_timezone

from django.utils import timezone

from . import signatures
from .models import Context, Grant, RelyingParty, UsedKey

# Distinct refusal reasons. Each becomes a row in the evaluation's negative
# test table, so they are defined once here and referenced everywhere.
MISSING = "CTXKEY_MISSING"
MALFORMED = "CTXKEY_MALFORMED"
BAD_SIGNATURE = "CTXKEY_BAD_SIGNATURE"
EXPIRED = "CTXKEY_EXPIRED"
RP_UNKNOWN = "RP_UNKNOWN"
RP_INACTIVE = "RP_INACTIVE"
CONTEXT_UNKNOWN = "CONTEXT_UNKNOWN"
CONTEXT_INACTIVE = "CONTEXT_INACTIVE"
CONTEXT_NOT_GRANTED = "CONTEXT_NOT_GRANTED"
KEY_REPLAYED = "CTXKEY_REPLAYED"

REASON_DETAIL = {
    MISSING: "No X-Context-Key header was supplied.",
    MALFORMED: "The Context-Key is not a well-formed token.",
    BAD_SIGNATURE: "The Context-Key signature did not verify.",
    EXPIRED: "The Context-Key has expired.",
    RP_UNKNOWN: "The named relying party is not registered.",
    RP_INACTIVE: "The named relying party is not active.",
    CONTEXT_UNKNOWN: "The named context does not exist.",
    CONTEXT_INACTIVE: "The named context has been revoked.",
    CONTEXT_NOT_GRANTED: (
        "The relying party holds no active grant for this context."
    ),
    KEY_REPLAYED: "This Context-Key has already been used.",
}

DEFAULT_TTL_SECONDS = 300
MAX_TTL_SECONDS = 3600
MAX_KEY_LENGTH = 2048

# Reasons that must not be distinguishable from the outside.
#
# Refusing an unregistered party with RP_UNKNOWN while refusing a registered
# one with CTXKEY_BAD_SIGNATURE turns the endpoint into an oracle: an attacker
# submits garbage signatures against candidate names and learns which
# organisations hold accounts, without ever possessing a valid key. That is a
# disclosure about the federation rather than about a citizen, but it is a
# disclosure the system never agreed to make.
#
# The precise reason is still written to the audit log, where an operator can
# see it and an attacker cannot. Only the response is collapsed. Setting
# ``DALANID_VERBOSE_REFUSALS`` restores the specific code in responses, which
# is useful in development and for the evaluation harness, and wrong in
# deployment.
PUBLIC_REASON = {
    RP_UNKNOWN: BAD_SIGNATURE,
    RP_INACTIVE: BAD_SIGNATURE,
}


def _b64encode(raw: bytes) -> str:
    """URL-safe base64 without padding, so keys are header-safe."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    """Reverse of :func:`_b64encode`, restoring stripped padding."""
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _sign(payload_b64: str, secret: str) -> str:
    """HMAC signing helper, retained for the legacy suite and for tests."""
    return _b64encode(
        hmac.new(
            secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256
        ).digest()
    )


@dataclass
class KeyVerification:
    """Outcome of verifying a Context-Key.

    Carries the resolved relying party and context on success, and a reason
    code on failure. Callers branch on ``ok`` alone.
    """

    ok: bool
    reason: str = ""          # precise cause, written to the audit log
    public_reason: str = ""   # what the caller is told; may be coarser
    detail: str = ""
    relying_party: RelyingParty | None = None
    context: Context | None = None
    claims: dict = field(default_factory=dict)

    @classmethod
    def failure(cls, reason: str, claims: dict | None = None):
        from django.conf import settings

        if getattr(settings, "DALANID_VERBOSE_REFUSALS", False):
            public = reason
        else:
            public = PUBLIC_REASON.get(reason, reason)
        return cls(
            ok=False,
            reason=reason,
            public_reason=public,
            detail=REASON_DETAIL.get(public, "Refused."),
            claims=claims or {},
        )


def issue_context_key(
    relying_party: RelyingParty,
    context: Context,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> str:
    """Mint a Context-Key binding a relying party to a context until expiry.

    ``jti`` is a unique identifier per key. It is not consulted during
    verification in this implementation, but it gives every issued key a
    distinct identity, which is the hook a replay-prevention cache would use.
    """
    # A caller-supplied lifetime is untrusted input. Negative values would
    # mint a key that is already expired, and unbounded ones would defeat
    # expiry altogether, so the requested TTL is clamped to a sane window.
    try:
        ttl_seconds = int(ttl_seconds)
    except (TypeError, ValueError):
        ttl_seconds = DEFAULT_TTL_SECONDS
    ttl_seconds = max(1, min(ttl_seconds, MAX_TTL_SECONDS))

    now = timezone.now()
    payload = {
        "rp": relying_party.slug,
        "ctx": context.slug,
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + ttl_seconds,
        "jti": uuid.uuid4().hex,
    }
    suite = relying_party.algorithm
    payload["alg"] = signatures.ALG_NAME.get(suite, suite)
    payload_b64 = _b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    )
    signature = signatures.sign(suite, payload_b64, relying_party)
    return f"{payload_b64}.{_b64encode(signature)}"


def verify_context_key(raw_key: str | None) -> KeyVerification:
    """Verify a presented Context-Key through all five layers."""

    # Layer 1: structural.
    if not raw_key:
        return KeyVerification.failure(MISSING)

    # Reject oversized input before decoding it. A megabyte of base64 costs
    # real CPU to decode and would otherwise be free work for an attacker.
    if len(raw_key) > MAX_KEY_LENGTH:
        return KeyVerification.failure(MALFORMED)

    parts = raw_key.split(".")
    if len(parts) != 2 or not all(parts):
        return KeyVerification.failure(MALFORMED)

    payload_b64, signature_b64 = parts
    try:
        claims = json.loads(_b64decode(payload_b64))
    except (ValueError, TypeError, json.JSONDecodeError):
        return KeyVerification.failure(MALFORMED)

    if not isinstance(claims, dict):
        return KeyVerification.failure(MALFORMED)
    if not all(k in claims for k in ("rp", "ctx", "exp")):
        return KeyVerification.failure(MALFORMED)

    # Layer 2: identity. Read from the unverified payload solely to select a
    # candidate secret; see the module docstring on why this is safe.
    relying_party = RelyingParty.objects.filter(slug=claims["rp"]).first()
    if relying_party is None:
        return KeyVerification.failure(RP_UNKNOWN, claims)
    if not relying_party.is_active:
        return KeyVerification.failure(RP_INACTIVE, claims)

    # Layer 3: cryptographic.
    #
    # The suite comes from the relying party's registration, never from the
    # token's own `alg` claim. Reading it from the token is the algorithm
    # confusion vulnerability: an attacker registered under Ed25519 would
    # present an HMAC signature computed with the public key, which is not
    # secret, and a naive verifier would accept it.
    suite = relying_party.algorithm
    try:
        signature = _b64decode(signature_b64)
    except (ValueError, TypeError):
        return KeyVerification.failure(MALFORMED, claims)
    if not signatures.verify(suite, payload_b64, signature, relying_party):
        return KeyVerification.failure(BAD_SIGNATURE, claims)

    # Everything below this line is verified and may now be trusted.

    # Layer 4: temporal.
    try:
        expires_at = int(claims["exp"])
    except (TypeError, ValueError):
        return KeyVerification.failure(MALFORMED, claims)
    if timezone.now().timestamp() >= expires_at:
        return KeyVerification.failure(EXPIRED, claims)

    # Layer 5: authorisation. Checked against current database state rather
    # than the signed payload, so revoking a context or a grant takes effect
    # immediately for keys already in circulation.
    context = Context.objects.filter(slug=claims["ctx"]).first()
    if context is None:
        return KeyVerification.failure(CONTEXT_UNKNOWN, claims)
    if not context.is_active:
        return KeyVerification.failure(CONTEXT_INACTIVE, claims)

    grant = Grant.objects.filter(
        relying_party=relying_party, context=context, is_active=True
    ).first()
    if grant is None:
        return KeyVerification.failure(CONTEXT_NOT_GRANTED, claims)

    return KeyVerification(
        ok=True,
        relying_party=relying_party,
        context=context,
        claims=claims,
    )


def consume_context_key(raw_key: str | None) -> KeyVerification:
    """Verify a key and spend it, so it cannot be presented twice.

    Verification and consumption are separate functions on purpose.
    :func:`verify_context_key` is pure - it answers "is this key valid?" and
    can be called freely by tests, tooling or a future dry-run endpoint without
    side effects. Consumption adds the one irreversible step, claiming the
    key's ``jti``, and is what request handling actually calls.

    The claim happens only after every other layer has passed. Spending a key
    that was going to be refused anyway would let an attacker invalidate
    someone else's captured key by replaying it against a revoked context.
    """
    verification = verify_context_key(raw_key)
    if not verification.ok:
        return verification

    claims = verification.claims
    jti = claims.get("jti")
    if not jti:
        # Keys minted before replay protection existed carry no jti. Refusing
        # them outright is safer than silently exempting them from the check.
        return KeyVerification.failure(MALFORMED, claims)

    expires_at = datetime.fromtimestamp(int(claims["exp"]), tz=dt_timezone.utc)
    if not UsedKey.claim(jti, expires_at, verification.relying_party.slug):
        return KeyVerification.failure(KEY_REPLAYED, claims)

    return verification
