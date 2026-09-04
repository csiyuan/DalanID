"""
Tests for the administrative surface.

Two properties are under test. First, that creating a context requires both a
valid administrative Context-Key and the role — either alone must fail. Second,
that extensibility cannot be turned into a privilege escalation: the caps in
:mod:`identity.serializers` must stop an authorised party from defining a
context broad enough to reconstruct the unprotected record.
"""

import json

from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse

from identity import keys
from identity.models import (
    AuditEntry, Context, Grant, RelyingParty,
)


class AdminTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        call_command("seed_demo", verbosity=0)

    def admin_key(self, rp_slug="ministry-health"):
        return keys.issue_context_key(
            RelyingParty.objects.get(slug=rp_slug),
            Context.objects.get(slug="context-administration"),
        )

    def post(self, url, body, key):
        headers = {"HTTP_X_CONTEXT_KEY": key} if key else {}
        return self.client.post(
            url, data=json.dumps(body),
            content_type="application/json", **headers
        )

    def create_context(self, body, key=None):
        return self.post(
            reverse("context-create"), body, key or self.admin_key()
        )


class ContextCreationTests(AdminTestCase):

    VALID = {
        "slug": "pharmacy",
        "name": "Pharmacy Dispensing",
        "purpose": "Verifying entitlement to dispense prescribed medicines.",
        "attributes": ["legal_name", "vid_token"],
    }

    def test_authorised_party_can_create_a_context(self):
        response = self.create_context(self.VALID)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            set(response.json()["permitted"]), {"legal_name", "vid_token"}
        )
        self.assertTrue(Context.objects.filter(slug="pharmacy").exists())

    def test_created_context_records_its_author(self):
        self.create_context(self.VALID)
        context = Context.objects.get(slug="pharmacy")
        self.assertEqual(context.created_by.slug, "ministry-health")

    def test_creation_is_written_to_the_audit_chain(self):
        self.create_context(self.VALID)
        entry = AuditEntry.objects.latest("sequence")
        self.assertEqual(entry.outcome, "context_created")
        self.assertEqual(entry.context_slug, "pharmacy")

    def test_creation_does_not_confer_use(self):
        # The defining party gets no grant, so it cannot immediately read
        # through the context it just created.
        self.create_context(self.VALID)
        context = Context.objects.get(slug="pharmacy")
        party = RelyingParty.objects.get(slug="ministry-health")
        self.assertFalse(
            Grant.objects.filter(
                relying_party=party, context=context
            ).exists()
        )

        key = keys.issue_context_key(party, context)
        response = self.client.get(
            reverse("contextual-profile", args=["maria-da-costa"]),
            HTTP_X_CONTEXT_KEY=key,
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["reason"], keys.CONTEXT_NOT_GRANTED)

    def test_new_context_works_once_a_grant_is_issued(self):
        self.create_context(self.VALID)
        response = self.post(
            reverse("grant-create", args=["pharmacy"]),
            {"relying_party": "ministry-health"},
            self.admin_key(),
        )
        self.assertEqual(response.status_code, 201)

        party = RelyingParty.objects.get(slug="ministry-health")
        key = keys.issue_context_key(
            party, Context.objects.get(slug="pharmacy")
        )
        body = self.client.get(
            reverse("contextual-profile", args=["maria-da-costa"]),
            HTTP_X_CONTEXT_KEY=key,
        ).json()
        self.assertEqual(
            set(body["disclosed"]), {"legal_name", "vid_token"}
        )


class CreationAuthorisationTests(AdminTestCase):

    def test_party_without_the_role_is_refused(self):
        # banco-nacional holds a valid key for its own context but no
        # administrative grant and no role.
        key = keys.issue_context_key(
            RelyingParty.objects.get(slug="banco-nacional"),
            Context.objects.get(slug="banking"),
        )
        response = self.create_context(
            ContextCreationTests.VALID, key=key
        )
        self.assertEqual(response.status_code, 403)

    def test_no_key_at_all_is_refused(self):
        response = self.post(
            reverse("context-create"), ContextCreationTests.VALID, None
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["reason"], keys.MISSING)

    def test_role_alone_without_a_valid_key_is_refused(self):
        # ministry-health has the role, but presents a forged key.
        payload, signature = self.admin_key().split(".")
        flipped = ("A" if signature[0] != "A" else "B") + signature[1:]
        response = self.create_context(
            ContextCreationTests.VALID, key=f"{payload}.{flipped}"
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["reason"], keys.BAD_SIGNATURE)


class CreationValidationTests(AdminTestCase):

    def test_field_cap_blocks_reconstructing_the_full_record(self):
        response = self.create_context({
            "slug": "everything",
            "name": "Everything",
            "purpose": "An attempt to obtain the entire citizen record.",
            "attributes": ["legal_name", "passport", "tax_id", "dob",
                           "vaccination", "risk", "vid_token", "nickname"],
        })
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Context.objects.filter(slug="everything").exists())

    def test_sensitivity_ceiling_blocks_narrow_but_invasive_contexts(self):
        # Four fields, inside the count cap, but summed sensitivity 16 > 12.
        response = self.create_context({
            "slug": "invasive",
            "name": "Invasive",
            "purpose": "A small number of highly sensitive attributes.",
            "attributes": ["passport", "tax_id", "vaccination", "legal_name"],
        })
        self.assertEqual(response.status_code, 400)

    def test_purpose_is_mandatory(self):
        response = self.create_context({
            "slug": "unstated",
            "name": "Unstated",
            "purpose": "n/a",
            "attributes": ["nickname"],
        })
        self.assertEqual(response.status_code, 400)

    def test_unknown_attributes_are_refused(self):
        response = self.create_context({
            "slug": "phantom",
            "name": "Phantom",
            "purpose": "Requests an attribute that is not in the schema.",
            "attributes": ["nickname", "blood_type"],
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("blood_type", str(response.json()["detail"]))

    def test_duplicate_slug_is_refused(self):
        response = self.create_context({
            "slug": "banking",
            "name": "Banking Again",
            "purpose": "Attempts to shadow an existing context slug.",
            "attributes": ["nickname"],
        })
        self.assertEqual(response.status_code, 400)

    def test_rejected_creation_leaves_no_partial_context(self):
        self.create_context({
            "slug": "everything",
            "name": "Everything",
            "purpose": "An attempt to obtain the entire citizen record.",
            "attributes": ["legal_name", "passport", "tax_id", "dob",
                           "vaccination", "risk", "vid_token", "nickname"],
        })
        self.assertEqual(Context.objects.filter(slug="everything").count(), 0)


class KeyIssuanceTests(AdminTestCase):

    def test_issued_key_verifies(self):
        response = self.client.post(
            reverse("key-issue"),
            data=json.dumps({"relying_party": "border-authority",
                             "context": "immigration"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        verification = keys.verify_context_key(
            response.json()["context_key"]
        )
        self.assertTrue(verification.ok)

    def test_unknown_party_is_refused(self):
        response = self.client.post(
            reverse("key-issue"),
            data=json.dumps({"relying_party": "ghost",
                             "context": "immigration"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_issuance_can_be_disabled(self):
        with self.settings(DALANID_ALLOW_KEY_ISSUANCE=False):
            response = self.client.post(
                reverse("key-issue"),
                data=json.dumps({"relying_party": "border-authority",
                                 "context": "immigration"}),
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 403)
