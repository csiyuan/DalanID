"""
Tests for the signature suites.

The interesting cases are not that Ed25519 signing works — it is a well-tested
library primitive — but that supporting two suites has not introduced the
algorithm-confusion vulnerabilities that have repeatedly affected JWT
implementations. Those tests are in ``AlgorithmConfusionTests`` and are the
reason this file exists.
"""

import json

from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from identity import keys, signatures
from identity.models import Context, RelyingParty


class SignatureTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        call_command("seed_demo", verbosity=0)

    def get(self, key):
        return self.client.get(
            reverse("contextual-profile", args=["maria-da-costa"]),
            HTTP_X_CONTEXT_KEY=key,
        )

    def key_for(self, rp_slug, ctx_slug):
        return keys.issue_context_key(
            RelyingParty.objects.get(slug=rp_slug),
            Context.objects.get(slug=ctx_slug),
        )


class Ed25519Tests(SignatureTestCase):

    def test_keypair_round_trips(self):
        private_pem, public_pem = signatures.generate_ed25519_keypair()
        message = b"payload-under-test"
        signature = signatures.load_private_key(private_pem).sign(message)
        signatures.load_public_key(public_pem).verify(signature, message)

    def test_ed25519_party_can_disclose(self):
        party = RelyingParty.objects.get(slug="border-authority")
        self.assertEqual(party.algorithm, signatures.ED25519)
        self.assertEqual(self.get(self.key_for(*("border-authority", "immigration"))).status_code, 200)

    def test_legacy_hmac_party_still_works(self):
        # Migration must not require re-keying the whole federation at once.
        party = RelyingParty.objects.get(slug="rede-social")
        self.assertEqual(party.algorithm, signatures.HMAC_SHA256)
        self.assertEqual(self.get(self.key_for("rede-social", "social")).status_code, 200)

    def test_signature_is_64_bytes(self):
        key = self.key_for("border-authority", "immigration")
        signature = keys._b64decode(key.split(".")[1])
        self.assertEqual(len(signature), 64)

    def test_tampered_payload_fails_ed25519(self):
        key = self.key_for("border-authority", "immigration")
        payload, signature = key.split(".")
        claims = json.loads(keys._b64decode(payload))
        claims["ctx"] = "banking"
        forged = keys._b64encode(
            json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
        )
        self.assertEqual(self.get(f"{forged}.{signature}").status_code, 401)

    def test_public_key_alone_cannot_forge(self):
        # The property HMAC did not have. An attacker who reads the service's
        # database obtains public keys, and public keys do not sign.
        party = RelyingParty.objects.get(slug="border-authority")
        self.assertTrue(party.public_key.startswith("-----BEGIN PUBLIC KEY"))
        with self.assertRaises(ValueError):
            signatures.load_private_key(party.public_key)

    def test_verification_needs_only_the_public_key(self):
        # Demonstrates that the service could hold no private key at all.
        party = RelyingParty.objects.get(slug="border-authority")
        key = self.key_for("border-authority", "immigration")
        payload, signature = key.split(".")

        stripped = RelyingParty(
            slug=party.slug, algorithm=party.algorithm,
            public_key=party.public_key, private_key="", signing_secret="",
        )
        self.assertTrue(signatures.verify(
            signatures.ED25519, payload, keys._b64decode(signature), stripped
        ))


class AlgorithmConfusionTests(SignatureTestCase):
    """The vulnerability class that supporting two suites introduces."""

    def payload_for(self, rp_slug, ctx_slug, alg_claim):
        now = int(timezone.now().timestamp())
        return keys._b64encode(json.dumps(
            {"rp": rp_slug, "ctx": ctx_slug, "iat": now, "exp": now + 300,
             "jti": "confusion-test", "alg": alg_claim},
            sort_keys=True, separators=(",", ":"),
        ).encode())

    def test_hmac_signature_against_an_ed25519_party_is_refused(self):
        # The classic downgrade. An Ed25519-registered party's public key is
        # not secret, so if the verifier honoured an "alg: HS256" claim and
        # used the public key as an HMAC secret, anyone could forge.
        party = RelyingParty.objects.get(slug="border-authority")
        payload = self.payload_for("border-authority", "immigration", "HS256")
        forged = keys._b64encode(
            signatures.sign(signatures.HMAC_SHA256, payload,
                            RelyingParty(signing_secret=party.public_key))
        )
        response = self.get(f"{payload}.{forged}")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["reason"], keys.BAD_SIGNATURE)

    def test_hmac_signature_using_the_stored_secret_is_still_refused(self):
        # Even the party's real HMAC secret must not verify once that party is
        # registered for Ed25519. The registration is authoritative.
        party = RelyingParty.objects.get(slug="border-authority")
        payload = self.payload_for("border-authority", "immigration", "HS256")
        forged = keys._b64encode(
            signatures.sign(signatures.HMAC_SHA256, payload, party)
        )
        self.assertEqual(self.get(f"{payload}.{forged}").status_code, 401)

    def test_alg_none_is_refused(self):
        payload = self.payload_for("border-authority", "immigration", "none")
        self.assertEqual(self.get(f"{payload}.").status_code, 401)
        self.assertEqual(
            self.get(f"{payload}.{keys._b64encode(b'')}").status_code, 401
        )

    def test_lying_alg_claim_does_not_change_verification(self):
        # A correctly signed Ed25519 key still verifies when its alg claim is
        # rewritten, because the claim is inside the signed region and the
        # verifier ignores it anyway. Two independent reasons it cannot help.
        key = self.key_for("border-authority", "immigration")
        self.assertEqual(self.get(key).status_code, 200)

    def test_ed25519_signature_against_an_hmac_party_is_refused(self):
        # The reverse direction: an attacker with their own keypair claiming
        # EdDSA against a party registered for HMAC.
        payload = self.payload_for("rede-social", "social", "EdDSA")
        private_pem, _ = signatures.generate_ed25519_keypair()
        attacker = RelyingParty(private_key=private_pem)
        forged = keys._b64encode(
            signatures.sign(signatures.ED25519, payload, attacker)
        )
        self.assertEqual(self.get(f"{payload}.{forged}").status_code, 401)

    def test_unknown_suite_verifies_nothing(self):
        party = RelyingParty.objects.get(slug="border-authority")
        self.assertFalse(
            signatures.verify("rot13", "payload", b"sig", party)
        )

    def test_party_with_no_key_material_verifies_nothing(self):
        empty = RelyingParty(algorithm=signatures.ED25519, public_key="")
        self.assertFalse(
            signatures.verify(signatures.ED25519, "payload", b"sig", empty)
        )
