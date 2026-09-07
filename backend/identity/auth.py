"""
Citizen authentication for subject access.

Before this module, ``POST /subject/token`` accepted a citizen's public
identifier and returned a token granting full read access to that citizen's
disclosure history. Anyone who could guess an identifier could read the audit
trail of the person it belonged to - which inverted the purpose of the endpoint
entirely. Subject access exists to give the citizen oversight; as implemented
it gave everyone oversight of the citizen.

Authentication is two-factor and two-step:

    POST /auth/login   {citizen, password}   -> challenge token
    POST /auth/verify  {challenge, code}     -> subject token

The split is deliberate. A single-call design that takes password and code
together cannot distinguish "wrong password" from "wrong code" without leaking
which was wrong, and cannot enforce that the second factor is presented within
a short window of the first. The challenge token is signed, carries a two
minute expiry, and is useless on its own.

TOTP is implemented here from RFC 6238 rather than taken from a library. It is
roughly thirty lines and the mechanism - an HMAC over a time counter, reduced
to six digits by dynamic truncation - is worth being explicit about in a
project whose subject is verification.

Threat model and its limits. Passwords are stored only as hashes, the second
factor is single-use within its window, comparison is constant-time, and
repeated failures lock the account. What this does not defend against is a
compromised device, or an attacker who controls the channel: the resulting
subject token is a bearer credential, so anyone holding it has access for its
lifetime. Binding the token to a device or session is out of scope.
"""

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time

from django.contrib.auth.hashers import check_password, make_password
from django.utils import timezone

from .keys import _b64decode, _b64encode
from .models import Citizen, UsedTotpCode

CHALLENGE_TTL_SECONDS = 120
TOTP_STEP_SECONDS = 30
TOTP_DIGITS = 6
# One step either side, so a clock a few seconds out does not lock a citizen
# out of their own record. Wider windows trade security for tolerance.
TOTP_DRIFT_STEPS = 1

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 900

# Reasons. As with Context-Keys, the precise cause is audited while the caller
# receives a deliberately uninformative one: distinguishing "no such citizen"
# from "wrong password" would let an attacker enumerate registered citizens.
BAD_CREDENTIALS = "AUTH_BAD_CREDENTIALS"
LOCKED = "AUTH_LOCKED"
CHALLENGE_INVALID = "AUTH_CHALLENGE_INVALID"
CHALLENGE_EXPIRED = "AUTH_CHALLENGE_EXPIRED"
BAD_CODE = "AUTH_BAD_CODE"
CODE_REUSED = "AUTH_CODE_REUSED"
NOT_ENROLLED = "AUTH_NOT_ENROLLED"

DETAIL = {
    BAD_CREDENTIALS: "Those credentials were not accepted.",
    LOCKED: "This account is temporarily locked. Try again later.",
    CHALLENGE_INVALID: "The login challenge is not valid.",
    CHALLENGE_EXPIRED: "The login challenge has expired. Start again.",
    BAD_CODE: "That verification code was not accepted.",
    CODE_REUSED: "That verification code has already been used.",
    NOT_ENROLLED: "This citizen has no second factor enrolled.",
}

PUBLIC_DETAIL_FOR = {
    # Everything that could distinguish a real citizen from an invented one
    # collapses to the same answer.
    NOT_ENROLLED: BAD_CREDENTIALS,
}


# --------------------------------------------------------------------- TOTP

def new_totp_secret() -> str:
    """A base32 secret, the format authenticator applications expect."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _totp_at(secret_b32: str, time_step: int) -> str:
    """One TOTP value, per RFC 6238 / RFC 4226.

    The counter is the number of elapsed time steps, packed big-endian into
    eight bytes. HMAC-SHA1 of that counter is reduced to a number by dynamic
    truncation: the low nibble of the final byte selects an offset, four bytes
    are read from there, the top bit is masked off to avoid sign ambiguity
    across implementations, and the result is taken modulo 10^digits.
    """
    padding = "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(secret_b32 + padding, casefold=True)
    counter = struct.pack(">Q", time_step)
    digest = hmac.new(key, counter, hashlib.sha1).digest()

    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


def current_totp(secret_b32: str, at: float | None = None) -> str:
    """The code a correctly configured authenticator would show right now."""
    return _totp_at(secret_b32, int((at or time.time()) // TOTP_STEP_SECONDS))


def verify_totp(secret_b32: str, code: str, at: float | None = None):
    """Check a code across the accepted drift window.

    Returns ``(ok, time_step)``. The time step is returned so the caller can
    record the code as spent against the exact window it matched.
    """
    # str.isdigit() is true for Unicode digit forms other than 0-9, which
    # compare_digest then refuses; and a JSON number arrives as int, which
    # has no .strip(). Both reached the comparison and raised.
    if not isinstance(code, str):
        return False, None
    code = code.strip()
    if not code.isascii() or not code.isdigit():
        return False, None
    now_step = int((at or time.time()) // TOTP_STEP_SECONDS)
    for delta in range(-TOTP_DRIFT_STEPS, TOTP_DRIFT_STEPS + 1):
        step = now_step + delta
        # Constant-time comparison: a naive equality check on a six-digit
        # string leaks, through timing, how many leading digits were correct.
        if hmac.compare_digest(_totp_at(secret_b32, step), code):
            return True, step
    return False, None


def provisioning_uri(citizen: Citizen, issuer: str = "DalanID") -> str:
    """otpauth:// URI, which an authenticator app consumes as a QR code."""
    return (
        f"otpauth://totp/{issuer}:{citizen.public_id}"
        f"?secret={citizen.totp_secret}&issuer={issuer}"
        f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECONDS}"
    )


# --------------------------------------------------------------- enrolment

def enrol(citizen: Citizen, password: str) -> str:
    """Set a citizen's password and issue a second-factor secret."""
    citizen.password_hash = make_password(password)
    citizen.totp_secret = new_totp_secret()
    citizen.failed_attempts = 0
    citizen.locked_until = None
    if not citizen.access_secret:
        citizen.access_secret = Citizen.new_secret()
    citizen.save()
    return citizen.totp_secret


# --------------------------------------------------------- challenge tokens

def _challenge_secret(citizen: Citizen) -> str:
    """Derived from the access secret, so a challenge cannot be reused as a
    subject token even if the signing scheme is otherwise identical."""
    return "challenge:" + citizen.access_secret


def issue_challenge(citizen: Citizen) -> str:
    now = int(timezone.now().timestamp())
    payload = _b64encode(
        json.dumps(
            {"sub": citizen.public_id, "iat": now,
             "exp": now + CHALLENGE_TTL_SECONDS, "nonce": secrets.token_hex(8)},
            sort_keys=True, separators=(",", ":"),
        ).encode()
    )
    signature = _b64encode(
        hmac.new(_challenge_secret(citizen).encode(),
                 payload.encode("ascii"), hashlib.sha256).digest()
    )
    return f"{payload}.{signature}"


def verify_challenge(raw: str | None):
    """Returns ``(citizen, reason)``; reason is empty on success."""
    if not raw or raw.count(".") != 1:
        return None, CHALLENGE_INVALID
    payload, signature = raw.split(".")
    try:
        claims = json.loads(_b64decode(payload))
    except (ValueError, TypeError):
        return None, CHALLENGE_INVALID
    if not isinstance(claims, dict) or "sub" not in claims or "exp" not in claims:
        return None, CHALLENGE_INVALID

    citizen = Citizen.objects.filter(public_id=claims["sub"]).first()
    if citizen is None or not citizen.access_secret:
        return None, CHALLENGE_INVALID

    expected = _b64encode(
        hmac.new(_challenge_secret(citizen).encode(),
                 payload.encode("ascii"), hashlib.sha256).digest()
    )
    # Bytes, for the reason given in subject.verify_subject_token: a
    # non-ASCII signature would otherwise raise rather than compare.
    if not hmac.compare_digest(expected.encode("utf-8"),
                               signature.encode("utf-8")):
        return None, CHALLENGE_INVALID
    try:
        if timezone.now().timestamp() >= int(claims["exp"]):
            return None, CHALLENGE_EXPIRED
    except (TypeError, ValueError):
        return None, CHALLENGE_INVALID

    return citizen, ""


# ------------------------------------------------------------- login steps

def _register_failure(citizen: Citizen):
    citizen.failed_attempts += 1
    if citizen.failed_attempts >= MAX_FAILED_ATTEMPTS:
        citizen.locked_until = timezone.now() + timezone.timedelta(
            seconds=LOCKOUT_SECONDS
        )
    citizen.save(update_fields=["failed_attempts", "locked_until"])


def _clear_failures(citizen: Citizen):
    if citizen.failed_attempts or citizen.locked_until:
        citizen.failed_attempts = 0
        citizen.locked_until = None
        citizen.save(update_fields=["failed_attempts", "locked_until"])


def begin_login(public_id: str, password: str):
    """First factor. Returns ``(challenge, reason)``.

    A password check runs even when the citizen does not exist, so the response
    time does not reveal whether the identifier is registered.
    """
    citizen = Citizen.objects.filter(public_id=public_id or "").first()

    if citizen is None:
        make_password(password or "")  # equalise timing
        return None, BAD_CREDENTIALS
    if citizen.is_locked:
        return None, LOCKED
    if not citizen.password_hash:
        return None, NOT_ENROLLED
    if not check_password(password or "", citizen.password_hash):
        _register_failure(citizen)
        return None, BAD_CREDENTIALS

    return issue_challenge(citizen), ""


def complete_login(challenge: str, code: str):
    """Second factor. Returns ``(citizen, reason)``."""
    citizen, reason = verify_challenge(challenge)
    if citizen is None:
        return None, reason
    if citizen.is_locked:
        return None, LOCKED
    if not citizen.totp_secret:
        return None, NOT_ENROLLED

    ok, step = verify_totp(citizen.totp_secret, code or "")
    if not ok:
        _register_failure(citizen)
        return None, BAD_CODE

    if not UsedTotpCode.claim(citizen, code.strip(), step):
        return None, CODE_REUSED

    _clear_failures(citizen)
    return citizen, ""


def public_reason(reason: str) -> str:
    return PUBLIC_DETAIL_FOR.get(reason, reason)
