"""
Verification tests for Context-Keys.

Each negative case here corresponds to one reason code in
:mod:`identity.keys`, and together they form the security results table in the
evaluation chapter. The point of testing refusals individually rather than
asserting a blanket 401 is that it demonstrates the system distinguishes
*between* failure modes, which is what makes the audit log diagnostic.
"""

import base64
import json
import threading

from django.core.management import call_command
from django.db import connection
from django.test import TestCase, TransactionTestCase
from django.urls import reverse
from django.utils import timezone

from identity import keys, signatures
from identity.models import (
    Attribute, AuditEntry, Context, Grant, RelyingParty,
)


class ContextKeyTestCase(TestCase):
    """Shared fixture: the seeded demonstration dataset."""

    @classmethod
    def setUpTestData(cls):
        call_command("seed_demo", verbosity=0)

    def url(self, public_id="maria-da-costa"):
        return reverse("contextual-profile", args=[public_id])

    def get(self, key, public_id="maria-da-costa"):
        headers = {"HTTP_X_CONTEXT_KEY": key} if key is not None else {}
        return self.client.get(self.url(public_id), **headers)

    def url_for(self, public_id):
        return reverse("contextual-profile", args=[public_id])

    def valid_key(self, rp_slug="border-authority", ctx_slug="immigration"):
        return keys.issue_context_key(
            RelyingParty.objects.get(slug=rp_slug),
            Context.objects.get(slug=ctx_slug),
        )


class HappyPathTests(ContextKeyTestCase):

    def test_valid_key_returns_200(self):
        response = self.get(self.valid_key())
        self.assertEqual(response.status_code, 200)

    def test_valid_key_discloses_only_permitted_fields(self):
        response = self.get(self.valid_key())
        disclosed = set(response.json()["disclosed"])
        self.assertEqual(disclosed, {"legal_name", "passport", "dob"})

    def test_withheld_count_covers_the_rest_of_the_schema(self):
        body = self.get(self.valid_key()).json()
        self.assertEqual(body["fields_permitted"], 3)
        self.assertEqual(body["fields_withheld"], 5)
        self.assertEqual(body["schema_size"], 8)

    def test_each_context_discloses_its_own_field_set(self):
        # Expected sets are written out here rather than read back from the
        # seeded contexts, so the assertion is independent of the data under
        # test. This is the self-referential-oracle weakness the preliminary
        # report acknowledged, corrected.
        expected = {
            "immigration": {"legal_name", "passport", "dob"},
            "public_health": {"legal_name", "dob", "vaccination"},
            "banking": {"legal_name", "tax_id", "dob"},
            "insurance": {"dob", "risk"},
            "public_service": {"vid_token"},
            "social": {"nickname"},
        }
        holders = {
            "immigration": "border-authority",
            "public_health": "ministry-health",
            "banking": "banco-nacional",
            "insurance": "seguros-dili",
            "public_service": "ministry-health",
            "social": "rede-social",
        }
        for ctx_slug, fields in expected.items():
            with self.subTest(context=ctx_slug):
                key = self.valid_key(holders[ctx_slug], ctx_slug)
                body = self.get(key).json()
                self.assertEqual(set(body["disclosed"]), fields)


class DerivedAttributeTests(ContextKeyTestCase):

    def test_dob_is_disclosed_as_a_band_not_a_date(self):
        body = self.get(self.valid_key()).json()
        self.assertNotIn("1996", body["disclosed"]["dob"])
        self.assertIn("dob", body["derived_fields"])

    def test_insurance_receives_no_identifying_field(self):
        key = self.valid_key("seguros-dili", "insurance")
        disclosed = self.get(key).json()["disclosed"]
        self.assertNotIn("legal_name", disclosed)
        self.assertNotIn("passport", disclosed)


class RefusalTests(ContextKeyTestCase):
    """One test per reason code."""

    def assertRefused(self, response, reason):
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["reason"], reason)

    def test_missing_key(self):
        self.assertRefused(self.get(None), keys.MISSING)

    def test_malformed_key_not_two_parts(self):
        self.assertRefused(self.get("not-a-token"), keys.MALFORMED)

    def test_malformed_key_undecodable_payload(self):
        self.assertRefused(self.get("!!!!.!!!!"), keys.MALFORMED)

    def test_malformed_key_missing_claims(self):
        payload = keys._b64encode(json.dumps({"rp": "border-authority"}).encode())
        self.assertRefused(self.get(f"{payload}.sig"), keys.MALFORMED)

    def test_tampered_signature(self):
        payload, signature = self.valid_key().split(".")
        flipped = ("A" if signature[0] != "A" else "B") + signature[1:]
        self.assertRefused(self.get(f"{payload}.{flipped}"), keys.BAD_SIGNATURE)

    def test_tampered_payload_invalidates_signature(self):
        # An attacker rewrites the context claim to reach a richer field set.
        payload, signature = self.valid_key(
            "rede-social", "social"
        ).split(".")
        claims = json.loads(keys._b64decode(payload))
        claims["ctx"] = "immigration"
        forged = keys._b64encode(
            json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
        )
        self.assertRefused(self.get(f"{forged}.{signature}"),
                           keys.BAD_SIGNATURE)

    def test_expired_key(self):
        # Issuance clamps the lifetime to a positive window, so an expired key
        # cannot be minted through the normal path. This builds one directly:
        # the payload carries a past expiry and is signed correctly, which is
        # exactly what a captured key looks like after its window closes.
        party = RelyingParty.objects.get(slug="border-authority")
        payload = keys._b64encode(
            json.dumps(
                {
                    "rp": party.slug,
                    "ctx": "immigration",
                    "iat": int(timezone.now().timestamp()) - 600,
                    "exp": int(timezone.now().timestamp()) - 60,
                    "jti": "expired-key-under-test",
                },
                sort_keys=True, separators=(",", ":"),
            ).encode()
        )
        # Sign under the suite the party is actually registered for, rather
        # than assuming HMAC: the point of this test is expiry, not signing.
        signature = keys._b64encode(
            signatures.sign(party.algorithm, payload, party)
        )
        self.assertRefused(f"{payload}.{signature}" and
                           self.get(f"{payload}.{signature}"), keys.EXPIRED)

    def test_negative_ttl_does_not_mint_a_pre_expired_key(self):
        key = keys.issue_context_key(
            RelyingParty.objects.get(slug="border-authority"),
            Context.objects.get(slug="immigration"),
            ttl_seconds=-1,
        )
        self.assertEqual(self.get(key).status_code, 200)

    def test_oversized_key_is_rejected_without_decoding(self):
        self.assertRefused(self.get("A" * 10000), keys.MALFORMED)

    def test_unknown_relying_party(self):
        payload = keys._b64encode(
            json.dumps(
                {"rp": "ghost-agency", "ctx": "immigration",
                 "exp": int(timezone.now().timestamp()) + 300},
                sort_keys=True, separators=(",", ":"),
            ).encode()
        )
        self.assertRefused(self.get(f"{payload}.sig"), keys.RP_UNKNOWN)

    def test_deactivated_relying_party(self):
        key = self.valid_key()
        RelyingParty.objects.filter(slug="border-authority").update(
            is_active=False
        )
        self.assertRefused(self.get(key), keys.RP_INACTIVE)

    def test_revoked_context_rejects_keys_already_issued(self):
        key = self.valid_key()
        Context.objects.filter(slug="immigration").update(is_active=False)
        self.assertRefused(self.get(key), keys.CONTEXT_INACTIVE)

    def test_relying_party_without_grant(self):
        # A registered party signs a perfectly valid key for a context it was
        # never authorised to invoke.
        vendor = RelyingParty.objects.get(slug="unaffiliated-vendor")
        key = keys.issue_context_key(
            vendor, Context.objects.get(slug="immigration")
        )
        self.assertRefused(self.get(key), keys.CONTEXT_NOT_GRANTED)

    def test_revoked_grant_takes_effect_immediately(self):
        key = self.valid_key()
        Grant.objects.filter(
            relying_party__slug="border-authority",
            context__slug="immigration",
        ).update(is_active=False)
        self.assertRefused(self.get(key), keys.CONTEXT_NOT_GRANTED)

    def test_one_partys_key_does_not_verify_under_another(self):
        # Confirms secrets are per-party, so compromising one does not let an
        # attacker impersonate the rest.
        bank = RelyingParty.objects.get(slug="banco-nacional")
        payload, _ = keys.issue_context_key(
            bank, Context.objects.get(slug="banking")
        ).split(".")
        other = RelyingParty.objects.get(slug="border-authority")
        forged = keys._b64encode(
            signatures.sign(other.algorithm, payload, other)
        )
        self.assertRefused(self.get(f"{payload}.{forged}"), keys.BAD_SIGNATURE)


class AuditChainTests(ContextKeyTestCase):

    def test_disclosure_is_logged(self):
        self.get(self.valid_key())
        entry = AuditEntry.objects.latest("sequence")
        self.assertEqual(entry.outcome, "disclosed")
        self.assertEqual(entry.relying_party_slug, "border-authority")

    def test_refusal_is_also_logged(self):
        self.get("not-a-token")
        entry = AuditEntry.objects.latest("sequence")
        self.assertEqual(entry.outcome, "refused")
        self.assertEqual(entry.reason_code, keys.MALFORMED)

    def test_chain_is_intact_after_many_requests(self):
        for _ in range(5):
            self.get(self.valid_key())
        ok, broken_at, _ = AuditEntry.verify_chain()
        self.assertTrue(ok)
        self.assertIsNone(broken_at)

    def test_editing_a_historical_entry_breaks_the_chain(self):
        for _ in range(5):
            self.get(self.valid_key())
        third = AuditEntry.objects.get(sequence=3)
        third.disclosed_codes = ["legal_name"]
        third.save()

        ok, broken_at, detail = AuditEntry.verify_chain()
        self.assertFalse(ok)
        self.assertEqual(broken_at, 3)
        self.assertEqual(detail, "entry contents altered")

    def test_verify_endpoint_reports_tampering(self):
        self.get(self.valid_key())
        entry = AuditEntry.objects.latest("sequence")
        entry.context_slug = "banking"
        entry.save()

        response = self.client.get(reverse("audit-verify"))
        self.assertEqual(response.status_code, 409)
        self.assertFalse(response.json()["intact"])


class ConcurrencyTests(TransactionTestCase):
    """The audit chain must stay single-threaded in effect, not just in theory.

    Appending is serial by construction — an entry hashes its predecessor — so
    concurrent disclosure requests contend for the head of the chain. These
    tests use TransactionTestCase rather than TestCase because the threads need
    to see each other's committed writes, which a test-wide transaction would
    prevent.
    """

    def setUp(self):
        call_command("seed_demo", verbosity=0)

    def test_concurrent_appends_do_not_collide(self):
        party = RelyingParty.objects.get(slug="border-authority")
        context = Context.objects.get(slug="immigration")
        failures = []

        def append():
            try:
                AuditEntry.record(
                    relying_party_slug=party.slug,
                    context_slug=context.slug,
                    citizen_public_id="maria-da-costa",
                    disclosed_codes=["legal_name"],
                    withheld_count=7,
                    outcome="disclosed",
                )
            except Exception as error:  # noqa: BLE001 - recorded for assert
                failures.append(error)
            finally:
                connection.close()

        threads = [threading.Thread(target=append) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(failures, [], f"appends failed: {failures}")
        self.assertEqual(AuditEntry.objects.count(), 12)

    def test_chain_survives_concurrent_appends(self):
        party = RelyingParty.objects.get(slug="border-authority")

        def append():
            try:
                AuditEntry.record(
                    relying_party_slug=party.slug,
                    context_slug="immigration",
                    disclosed_codes=[],
                    withheld_count=8,
                    outcome="disclosed",
                )
            finally:
                connection.close()

        threads = [threading.Thread(target=append) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        ok, broken_at, detail = AuditEntry.verify_chain()
        self.assertTrue(ok, f"chain broken at {broken_at}: {detail}")

    def test_sequences_are_contiguous_with_no_forks(self):
        def append():
            try:
                AuditEntry.record(
                    relying_party_slug="border-authority",
                    context_slug="immigration",
                    disclosed_codes=[],
                    withheld_count=8,
                    outcome="disclosed",
                )
            finally:
                connection.close()

        threads = [threading.Thread(target=append) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        sequences = list(
            AuditEntry.objects.order_by("sequence").values_list(
                "sequence", flat=True
            )
        )
        self.assertEqual(sequences, list(range(1, 11)))

        # No two entries may claim the same predecessor: that would be a fork.
        previous = list(
            AuditEntry.objects.exclude(previous_hash="").values_list(
                "previous_hash", flat=True
            )
        )
        self.assertEqual(len(previous), len(set(previous)))


class InformationLeakTests(ContextKeyTestCase):
    """Refusals must not tell an attacker more than they already know."""

    def test_unregistered_and_registered_parties_look_identical(self):
        # With verbose refusals off, submitting a bad signature against a
        # candidate organisation name must produce the same answer whether or
        # not that organisation is registered. Otherwise the endpoint is a
        # membership oracle for the federation.
        def refuse_for(rp_slug):
            payload = keys._b64encode(
                json.dumps(
                    {"rp": rp_slug, "ctx": "immigration",
                     "exp": int(timezone.now().timestamp()) + 300},
                    sort_keys=True, separators=(",", ":"),
                ).encode()
            )
            response = self.get(f"{payload}.deadbeef")
            return response.status_code, response.json()["reason"]

        with self.settings(DALANID_VERBOSE_REFUSALS=False):
            registered = refuse_for("banco-nacional")
            unregistered = refuse_for("acme-holdings-ltd")
        self.assertEqual(registered, unregistered)
        self.assertEqual(registered[1], keys.BAD_SIGNATURE)

    def test_deactivated_party_is_indistinguishable_too(self):
        RelyingParty.objects.filter(slug="banco-nacional").update(
            is_active=False
        )
        payload = keys._b64encode(
            json.dumps(
                {"rp": "banco-nacional", "ctx": "immigration",
                 "exp": int(timezone.now().timestamp()) + 300},
                sort_keys=True, separators=(",", ":"),
            ).encode()
        )
        with self.settings(DALANID_VERBOSE_REFUSALS=False):
            response = self.get(f"{payload}.deadbeef")
        self.assertEqual(response.json()["reason"], keys.BAD_SIGNATURE)

    def test_audit_log_still_records_the_precise_reason(self):
        # Collapsing the response must not blind the operator. The specific
        # cause is what makes the log useful for detecting an enumeration
        # sweep in the first place.
        payload = keys._b64encode(
            json.dumps(
                {"rp": "acme-holdings-ltd", "ctx": "immigration",
                 "exp": int(timezone.now().timestamp()) + 300},
                sort_keys=True, separators=(",", ":"),
            ).encode()
        )
        with self.settings(DALANID_VERBOSE_REFUSALS=False):
            response = self.get(f"{payload}.deadbeef")
        self.assertEqual(response.json()["reason"], keys.BAD_SIGNATURE)
        self.assertEqual(
            AuditEntry.objects.latest("sequence").reason_code, keys.RP_UNKNOWN
        )


class CitizenProbeTests(ContextKeyTestCase):

    def test_unknown_citizen_returns_404(self):
        response = self.get(self.valid_key(), public_id="nobody-here")
        self.assertEqual(response.status_code, 404)

    def test_unknown_citizen_is_written_to_the_audit_chain(self):
        # Probing for valid identifiers is an attack on the citizen namespace.
        # It must leave a trace even though no data was released.
        self.get(self.valid_key(), public_id="nobody-here")
        entry = AuditEntry.objects.latest("sequence")
        self.assertEqual(entry.outcome, "refused")
        self.assertEqual(entry.reason_code, "CITIZEN_UNKNOWN")
        self.assertEqual(entry.citizen_public_id, "nobody-here")
        self.assertEqual(entry.disclosed_codes, [])
