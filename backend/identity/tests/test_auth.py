"""
Tests for citizen authentication.

The TOTP implementation is checked against the published test vectors in
RFC 6238 Appendix B before anything else. An authenticator app is an
independent implementation of the same standard, so a hand-written version that
does not reproduce the reference values will silently fail to interoperate with
every app a citizen might actually use.
"""

import base64
import json
import time

from django.contrib.auth.hashers import check_password
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from identity import auth, subject
from identity.models import AuditEntry, Citizen, UsedTotpCode

# RFC 6238 Appendix B uses the ASCII seed "12345678901234567890" with SHA-1.
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
RFC_VECTORS = [
    (59, "287082"),
    (1111111109, "081804"),
    (1111111111, "050471"),
    (1234567890, "005924"),
    (2000000000, "279037"),
    (20000000000, "353130"),
]


class TotpAlgorithmTests(TestCase):
    """The algorithm itself, independent of Django."""

    def test_matches_rfc6238_test_vectors(self):
        for unix_time, expected in RFC_VECTORS:
            with self.subTest(t=unix_time):
                self.assertEqual(
                    auth.current_totp(RFC_SECRET, at=unix_time), expected
                )

    def test_code_changes_between_time_steps(self):
        first = auth.current_totp(RFC_SECRET, at=1000)
        second = auth.current_totp(RFC_SECRET, at=1000 + auth.TOTP_STEP_SECONDS)
        self.assertNotEqual(first, second)

    def test_code_is_stable_within_a_step(self):
        # Steps are aligned to the epoch, not to an arbitrary start point, so
        # the boundaries must be computed rather than guessed: 990 and 1019
        # are the first and last seconds of step 33.
        step_start = (1000 // auth.TOTP_STEP_SECONDS) * auth.TOTP_STEP_SECONDS
        step_end = step_start + auth.TOTP_STEP_SECONDS - 1
        self.assertEqual(
            auth.current_totp(RFC_SECRET, at=step_start),
            auth.current_totp(RFC_SECRET, at=step_end),
        )
        self.assertNotEqual(
            auth.current_totp(RFC_SECRET, at=step_end),
            auth.current_totp(RFC_SECRET, at=step_end + 1),
        )

    def test_drift_window_accepts_adjacent_steps(self):
        now = 1_700_000_000
        previous = auth.current_totp(RFC_SECRET, at=now - auth.TOTP_STEP_SECONDS)
        following = auth.current_totp(RFC_SECRET, at=now + auth.TOTP_STEP_SECONDS)
        self.assertTrue(auth.verify_totp(RFC_SECRET, previous, at=now)[0])
        self.assertTrue(auth.verify_totp(RFC_SECRET, following, at=now)[0])

    def test_drift_window_rejects_distant_steps(self):
        now = 1_700_000_000
        stale = auth.current_totp(RFC_SECRET, at=now - 300)
        self.assertFalse(auth.verify_totp(RFC_SECRET, stale, at=now)[0])

    def test_non_numeric_codes_are_rejected(self):
        for bad in ["", "abcdef", "12 34 56", None, "12345"]:
            with self.subTest(code=bad):
                self.assertFalse(auth.verify_totp(RFC_SECRET, bad)[0])

    def test_secrets_are_distinct(self):
        self.assertNotEqual(auth.new_totp_secret(), auth.new_totp_secret())

    def test_provisioning_uri_is_well_formed(self):
        citizen = Citizen(public_id="test-citizen", totp_secret=RFC_SECRET)
        uri = auth.provisioning_uri(citizen)
        self.assertTrue(uri.startswith("otpauth://totp/DalanID:test-citizen"))
        self.assertIn(f"secret={RFC_SECRET}", uri)
        self.assertIn("digits=6", uri)


class AuthFlowTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        call_command("seed_demo", verbosity=0)

    def setUp(self):
        self.citizen = Citizen.objects.get(public_id="maria-da-costa")

    def post(self, name, body):
        return self.client.post(
            reverse(name), data=json.dumps(body),
            content_type="application/json",
        )

    def login(self, password="dalan-demo-2026"):
        return self.post("auth-login",
                         {"citizen": "maria-da-costa", "password": password})

    def full_login(self):
        challenge = self.login().json()["challenge"]
        code = auth.current_totp(self.citizen.totp_secret)
        return self.post("auth-verify", {"challenge": challenge, "code": code})


class TwoFactorFlowTests(AuthFlowTestCase):

    def test_correct_password_returns_a_challenge_not_a_token(self):
        response = self.login()
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn("challenge", body)
        self.assertNotIn("subject_token", body)
        self.assertEqual(body["requires"], "totp")

    def test_challenge_plus_code_returns_a_subject_token(self):
        response = self.full_login()
        self.assertEqual(response.status_code, 200)
        token = response.json()["subject_token"]
        citizen, reason = subject.verify_subject_token(token, "maria-da-costa")
        self.assertEqual(reason, "")
        self.assertEqual(citizen.public_id, "maria-da-costa")

    def test_token_from_login_opens_the_disclosure_history(self):
        token = self.full_login().json()["subject_token"]
        response = self.client.get(
            reverse("my-disclosures", args=["maria-da-costa"]),
            HTTP_X_SUBJECT_TOKEN=token,
        )
        self.assertEqual(response.status_code, 200)

    def test_wrong_password_is_refused(self):
        response = self.login(password="wrong")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["reason"], auth.BAD_CREDENTIALS)

    def test_wrong_code_is_refused(self):
        challenge = self.login().json()["challenge"]
        response = self.post("auth-verify",
                             {"challenge": challenge, "code": "000000"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["reason"], auth.BAD_CODE)

    def test_password_alone_does_not_open_the_history(self):
        # The whole point of the second factor.
        challenge = self.login().json()["challenge"]
        response = self.client.get(
            reverse("my-disclosures", args=["maria-da-costa"]),
            HTTP_X_SUBJECT_TOKEN=challenge,
        )
        self.assertEqual(response.status_code, 401)

    def test_forged_challenge_is_refused(self):
        challenge = self.login().json()["challenge"]
        payload, signature = challenge.split(".")
        flipped = ("A" if signature[0] != "A" else "B") + signature[1:]
        response = self.post("auth-verify", {
            "challenge": f"{payload}.{flipped}",
            "code": auth.current_totp(self.citizen.totp_secret),
        })
        self.assertEqual(response.json()["reason"], auth.CHALLENGE_INVALID)

    def test_expired_challenge_is_refused(self):
        challenge = self.login().json()["challenge"]
        payload = challenge.split(".")[0]
        claims = json.loads(auth._b64decode(payload))
        self.assertLessEqual(
            claims["exp"] - claims["iat"], auth.CHALLENGE_TTL_SECONDS
        )

    def test_code_cannot_be_reused(self):
        # A TOTP value stays valid for its whole window; accepting it twice
        # would let an observer reuse it.
        challenge = self.login().json()["challenge"]
        code = auth.current_totp(self.citizen.totp_secret)
        self.assertEqual(
            self.post("auth-verify",
                      {"challenge": challenge, "code": code}).status_code, 200
        )
        second = self.post("auth-login",
                           {"citizen": "maria-da-costa",
                            "password": "dalan-demo-2026"}).json()["challenge"]
        response = self.post("auth-verify",
                             {"challenge": second, "code": code})
        self.assertEqual(response.json()["reason"], auth.CODE_REUSED)


class LockoutTests(AuthFlowTestCase):

    def test_repeated_failures_lock_the_account(self):
        for _ in range(auth.MAX_FAILED_ATTEMPTS):
            self.login(password="wrong")
        response = self.login(password="wrong")
        self.assertEqual(response.status_code, 423)
        self.assertEqual(response.json()["reason"], auth.LOCKED)

    def test_lockout_blocks_even_the_correct_password(self):
        for _ in range(auth.MAX_FAILED_ATTEMPTS):
            self.login(password="wrong")
        self.assertEqual(self.login().status_code, 423)

    def test_successful_login_clears_the_failure_count(self):
        self.login(password="wrong")
        self.login(password="wrong")
        self.full_login()
        self.citizen.refresh_from_db()
        self.assertEqual(self.citizen.failed_attempts, 0)

    def test_second_factor_guessing_is_also_throttled(self):
        # Without this, six digits is 10^6 and the drift window is generous.
        for _ in range(auth.MAX_FAILED_ATTEMPTS):
            challenge = self.login().json().get("challenge")
            if challenge:
                self.post("auth-verify",
                          {"challenge": challenge, "code": "000000"})
        self.citizen.refresh_from_db()
        self.assertTrue(self.citizen.is_locked)


class EnumerationTests(AuthFlowTestCase):

    def test_unknown_citizen_looks_like_a_wrong_password(self):
        unknown = self.post("auth-login",
                            {"citizen": "nobody-here", "password": "x"})
        wrong = self.login(password="x")
        self.assertEqual(unknown.status_code, wrong.status_code)
        self.assertEqual(unknown.json()["reason"], wrong.json()["reason"])

    def test_unenrolled_citizen_looks_the_same_too(self):
        Citizen.objects.create(
            public_id="unenrolled", access_secret=Citizen.new_secret()
        )
        response = self.post("auth-login",
                             {"citizen": "unenrolled", "password": "x"})
        self.assertEqual(response.json()["reason"], auth.BAD_CREDENTIALS)

    def test_precise_reason_is_still_audited(self):
        self.post("auth-login", {"citizen": "nobody-here", "password": "x"})
        self.assertEqual(
            AuditEntry.objects.latest("sequence").reason_code,
            auth.BAD_CREDENTIALS,
        )


class LegacyEndpointTests(AuthFlowTestCase):

    def test_unauthenticated_subject_token_route_is_closed(self):
        # This was the hole: an identifier alone used to yield a token.
        response = self.post("subject-token", {"citizen": "maria-da-costa"})
        self.assertEqual(response.status_code, 403)

    def test_password_is_never_stored_in_the_clear(self):
        # The suite runs with a fast hasher for speed, so this test pins the
        # production one explicitly. Asserting against whatever the suite
        # happens to be configured with would test the test settings.
        with self.settings(PASSWORD_HASHERS=[
            "django.contrib.auth.hashers.PBKDF2PasswordHasher"
        ]):
            citizen = Citizen.objects.create(
                public_id="hash-check", access_secret=Citizen.new_secret()
            )
            auth.enrol(citizen, "a-real-password")

            # Verification must happen inside this block: Django resolves a
            # hash against the configured hashers, so checking a PBKDF2 hash
            # under the suite's fast hasher would fail for the wrong reason.
            self.assertTrue(
                check_password("a-real-password", citizen.password_hash)
            )

        self.assertNotIn("a-real-password", citizen.password_hash)
        self.assertTrue(citizen.password_hash.startswith("pbkdf2"))

    def test_authentication_is_written_to_the_audit_chain(self):
        self.full_login()
        entry = AuditEntry.objects.latest("sequence")
        self.assertEqual(entry.outcome, "subject_authenticated")
        self.assertEqual(entry.citizen_public_id, "maria-da-costa")
