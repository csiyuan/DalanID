"""
Tests for replay prevention and subject access.

These cover the two gaps that remained after the administrative surface was
finished: a captured key could be presented repeatedly until it expired, and
the person the disclosure log is about had no way to read it.
"""

import json
import threading

from django.core.management import call_command
from django.db import connection
from django.test import TestCase, TransactionTestCase
from django.urls import reverse

from identity import keys, subject
from identity.models import (
    AuditEntry, Citizen, Context, RelyingParty, UsedKey,
)


class ReplayTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        call_command("seed_demo", verbosity=0)

    def get(self, key):
        return self.client.get(
            reverse("contextual-profile", args=["maria-da-costa"]),
            HTTP_X_CONTEXT_KEY=key,
        )

    def fresh_key(self):
        return keys.issue_context_key(
            RelyingParty.objects.get(slug="border-authority"),
            Context.objects.get(slug="immigration"),
        )


class ReplayPreventionTests(ReplayTestCase):

    def test_a_key_works_exactly_once(self):
        key = self.fresh_key()
        self.assertEqual(self.get(key).status_code, 200)

        second = self.get(key)
        self.assertEqual(second.status_code, 401)
        self.assertEqual(second.json()["reason"], keys.KEY_REPLAYED)

    def test_replay_is_recorded_in_the_audit_chain(self):
        key = self.fresh_key()
        self.get(key)
        self.get(key)
        entry = AuditEntry.objects.latest("sequence")
        self.assertEqual(entry.outcome, "refused")
        self.assertEqual(entry.reason_code, keys.KEY_REPLAYED)

    def test_distinct_keys_for_the_same_context_both_work(self):
        # Single-use must not mean single-request-per-context.
        self.assertEqual(self.get(self.fresh_key()).status_code, 200)
        self.assertEqual(self.get(self.fresh_key()).status_code, 200)

    def test_a_refused_key_is_not_spent(self):
        # Otherwise replaying a doomed key against a revoked context would
        # burn the jti and invalidate the legitimate holder's key.
        vendor = RelyingParty.objects.get(slug="unaffiliated-vendor")
        key = keys.issue_context_key(
            vendor, Context.objects.get(slug="immigration")
        )
        self.get(key)
        self.assertEqual(UsedKey.objects.count(), 0)

    def test_verification_alone_has_no_side_effects(self):
        # verify_context_key must stay pure so tooling can use it freely.
        key = self.fresh_key()
        self.assertTrue(keys.verify_context_key(key).ok)
        self.assertTrue(keys.verify_context_key(key).ok)
        self.assertEqual(UsedKey.objects.count(), 0)
        self.assertEqual(self.get(key).status_code, 200)

    def test_pruning_drops_only_expired_records(self):
        self.get(self.fresh_key())
        self.assertEqual(UsedKey.objects.count(), 1)
        self.assertEqual(UsedKey.prune(), 0)

        UsedKey.objects.update(expires_at="2020-01-01T00:00:00Z")
        self.assertEqual(UsedKey.prune(), 1)


class ConcurrentReplayTests(TransactionTestCase):
    """Two simultaneous presentations of one key: exactly one may win."""

    def setUp(self):
        call_command("seed_demo", verbosity=0)

    def test_simultaneous_replay_admits_only_one(self):
        key = keys.issue_context_key(
            RelyingParty.objects.get(slug="border-authority"),
            Context.objects.get(slug="immigration"),
        )
        results = []

        def present():
            try:
                results.append(keys.consume_context_key(key).ok)
            finally:
                connection.close()

        threads = [threading.Thread(target=present) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(results.count(True), 1, results)
        self.assertEqual(results.count(False), 7)


class SubjectAccessTests(ReplayTestCase):

    def token(self, public_id="maria-da-costa"):
        return subject.issue_subject_token(
            Citizen.objects.get(public_id=public_id)
        )

    def disclosures(self, token, public_id="maria-da-costa"):
        headers = {"HTTP_X_SUBJECT_TOKEN": token} if token else {}
        return self.client.get(
            reverse("my-disclosures", args=[public_id]), **headers
        )

    def test_citizen_can_read_their_own_history(self):
        self.get(self.fresh_key())
        response = self.disclosures(self.token())
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["citizen"], "maria-da-costa")
        self.assertGreaterEqual(body["total"], 1)
        self.assertEqual(
            body["disclosures"][0]["relying_party"], "border-authority"
        )

    def test_history_includes_refused_attempts(self):
        # Knowing who tried is as much the citizen's business as who succeeded.
        vendor = RelyingParty.objects.get(slug="unaffiliated-vendor")
        self.get(keys.issue_context_key(
            vendor, Context.objects.get(slug="immigration")
        ))
        outcomes = [
            d["outcome"] for d in self.disclosures(self.token()).json()["disclosures"]
        ]
        self.assertIn("refused", outcomes)

    def test_history_reports_log_integrity(self):
        self.get(self.fresh_key())
        body = self.disclosures(self.token()).json()
        self.assertTrue(body["log_integrity"]["intact"])

    def test_tampering_is_visible_to_the_citizen(self):
        self.get(self.fresh_key())
        entry = AuditEntry.objects.latest("sequence")
        entry.context_slug = "banking"
        entry.save()
        body = self.disclosures(self.token()).json()
        self.assertFalse(body["log_integrity"]["intact"])

    def test_no_token_is_refused(self):
        response = self.disclosures(None)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["reason"], subject.MISSING)

    def test_forged_token_is_refused(self):
        payload, signature = self.token().split(".")
        flipped = ("A" if signature[0] != "A" else "B") + signature[1:]
        response = self.disclosures(f"{payload}.{flipped}")
        self.assertEqual(response.json()["reason"], subject.BAD_SIGNATURE)

    def test_a_token_for_one_citizen_does_not_open_another(self):
        other = Citizen.objects.create(
            public_id="joao-pereira", access_secret=Citizen.new_secret()
        )
        response = self.disclosures(self.token(), public_id=other.public_id)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["reason"], subject.MISMATCH)

    def test_a_context_key_does_not_grant_subject_access(self):
        # Relying-party credentials and subject credentials are separate
        # namespaces; neither may be used in the other's place.
        response = self.disclosures(self.fresh_key())
        self.assertEqual(response.status_code, 401)
        self.assertIn(
            response.json()["reason"], {subject.UNKNOWN, subject.MALFORMED}
        )

    def test_subject_token_cannot_be_used_as_a_context_key(self):
        response = self.get(self.token())
        self.assertEqual(response.status_code, 401)

    def test_expired_subject_token_is_refused(self):
        citizen = Citizen.objects.get(public_id="maria-da-costa")
        payload = keys._b64encode(
            json.dumps(
                {"sub": citizen.public_id, "iat": 1000, "exp": 2000},
                sort_keys=True, separators=(",", ":"),
            ).encode()
        )
        token = f"{payload}.{subject._sign(payload, citizen.access_secret)}"
        self.assertEqual(
            self.disclosures(token).json()["reason"], subject.EXPIRED
        )
