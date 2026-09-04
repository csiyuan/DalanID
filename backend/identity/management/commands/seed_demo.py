"""
Seed the demonstration dataset.

The attributes, contexts and citizen record here are ported directly from the
``FIELDS`` and ``CONTEXTS`` constants in the browser prototype, so the API and
the existing interface describe the same world and the figures in the report
remain comparable across chapters.

All personal data is synthetic. "Maria da Costa" is an invented person and
every value attached to her is fabricated.

Two changes from the prototype are deliberate. The ``dob`` attribute now
carries an ``age_band`` derivation, so no context receives a raw birth date;
and relying parties, grants and per-party signing secrets exist here with no
counterpart in the prototype, because the prototype had no notion of *who* was
asking.
"""

from django.core.management.base import BaseCommand
from django.db import transaction

from identity.signatures import generate_ed25519_keypair
from identity.models import (
    Attribute,
    Citizen,
    CitizenAttribute,
    Context,
    ContextAttribute,
    Grant,
    RelyingParty,
)

# code, label, sensitivity, derivation
ATTRIBUTES = [
    ("legal_name", "Legal name", 3, Attribute.Derivation.NONE),
    ("passport", "Passport and biometrics", 5, Attribute.Derivation.NONE),
    ("tax_id", "Tax identifier", 4, Attribute.Derivation.NONE),
    ("dob", "Date of birth", 3, Attribute.Derivation.AGE_BAND),
    ("vaccination", "Vaccination record", 4, Attribute.Derivation.NONE),
    ("risk", "Risk metadata", 3, Attribute.Derivation.NONE),
    ("vid_token", "Verified identity token", 1, Attribute.Derivation.NONE),
    ("nickname", "Nickname and avatar", 1, Attribute.Derivation.NONE),
]

# slug, name, tier, purpose, permitted attribute codes
CONTEXTS = [
    ("immigration", "Immigration", "Critical",
     "Border control and travel document verification.",
     ["legal_name", "passport", "dob"]),
    ("public_health", "Public Health", "Standard",
     "Immunisation status for public health administration.",
     ["legal_name", "dob", "vaccination"]),
    ("banking", "Banking and KYC", "High",
     "Customer due diligence for regulated financial services.",
     ["legal_name", "tax_id", "dob"]),
    ("insurance", "Insurance", "Variable",
     "Actuarial assessment without identification of the applicant.",
     ["dob", "risk"]),
    ("public_service", "Public Service", "Minimal",
     "Proof of entitlement for subsidised transport.",
     ["vid_token"]),
    ("social", "Social Persona", "Public",
     "Pseudonymous presentation in consumer services.",
     ["nickname"]),
    # Administration is itself a context, so the same verification path that
    # guards disclosure also guards the creation of new contexts. It permits
    # no citizen attributes: holding it discloses nothing about anybody.
    ("context-administration", "Context Administration", "Administrative",
     "Registration of new disclosure contexts and authorisation of "
     "relying parties.",
     []),
]

# slug, name, may create contexts, granted context slugs, signature suite.
# Most parties are registered for Ed25519; one is deliberately left on the
# legacy HMAC suite so the migration path is exercised rather than asserted.
RELYING_PARTIES = [
    ("border-authority", "Timor-Leste Border Authority", False,
     ["immigration"], "ed25519"),
    ("ministry-health", "Ministry of Health", True,
     ["public_health", "public_service", "context-administration"], "ed25519"),
    ("banco-nacional", "Banco Nacional de Timor-Leste", False,
     ["banking"], "ed25519"),
    ("seguros-dili", "Seguros Dili", False, ["insurance"], "ed25519"),
    ("rede-social", "Rede Social", False, ["social"], "hmac-sha256"),
    # Registered but holds no grants. Used to test that a valid signature is
    # not by itself sufficient authority.
    ("unaffiliated-vendor", "Unaffiliated Vendor", False, [], "ed25519"),
]

CITIZEN_ID = "maria-da-costa"
# Demonstration credential. A deployment would enrol citizens out of band.
DEMO_PASSWORD = "dalan-demo-2026"
CITIZEN_VALUES = {
    "legal_name": "Maria da Costa",
    "passport": "TL-4471829",
    "tax_id": "TIN 88-2231-09",
    "dob": "1996-03-14",
    "vaccination": "COVID-19 (x3), Yellow Fever",
    "risk": "Risk tier B, no claims history",
    "vid_token": "VID-TOKEN-7F3A2B",
    "nickname": "Mari",
}


class Command(BaseCommand):
    help = "Load the synthetic demonstration dataset."

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset",
            action="store_true",
            help="Delete existing domain data before seeding.",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        if options["reset"]:
            for model in (
                ContextAttribute, Grant, CitizenAttribute,
                Context, RelyingParty, Citizen, Attribute,
            ):
                model.objects.all().delete()
            self.stdout.write("Existing domain data cleared.")

        attributes = {}
        for code, label, sensitivity, derivation in ATTRIBUTES:
            attribute, _ = Attribute.objects.update_or_create(
                code=code,
                defaults={
                    "label": label,
                    "sensitivity": sensitivity,
                    "derivation": derivation,
                },
            )
            attributes[code] = attribute

        contexts = {}
        for slug, name, tier, purpose, permitted in CONTEXTS:
            context, _ = Context.objects.update_or_create(
                slug=slug,
                defaults={"name": name, "tier": tier, "purpose": purpose,
                          "is_active": True},
            )
            ContextAttribute.objects.filter(context=context).delete()
            for code in permitted:
                ContextAttribute.objects.create(
                    context=context, attribute=attributes[code]
                )
            contexts[slug] = context

        for slug, name, may_create, granted, algorithm in RELYING_PARTIES:
            private_pem, public_pem = generate_ed25519_keypair()
            party, created = RelyingParty.objects.get_or_create(
                slug=slug,
                defaults={
                    "name": name,
                    "algorithm": algorithm,
                    "public_key": public_pem,
                    "private_key": private_pem,
                    "signing_secret": RelyingParty.new_secret(),
                    "can_create_contexts": may_create,
                },
            )
            if not created:
                party.name = name
                party.algorithm = algorithm
                party.can_create_contexts = may_create
                party.is_active = True
                if not party.public_key:
                    party.private_key, party.public_key = (
                        private_pem, public_pem
                    )
                if not party.signing_secret:
                    party.signing_secret = RelyingParty.new_secret()
                party.save()
            Grant.objects.filter(relying_party=party).delete()
            for context_slug in granted:
                Grant.objects.create(
                    relying_party=party, context=contexts[context_slug]
                )

        citizen, _ = Citizen.objects.get_or_create(
            public_id=CITIZEN_ID,
            defaults={"access_secret": Citizen.new_secret()},
        )
        if not citizen.access_secret:
            citizen.access_secret = Citizen.new_secret()
            citizen.save()
        for code, value in CITIZEN_VALUES.items():
            CitizenAttribute.objects.update_or_create(
                citizen=citizen,
                attribute=attributes[code],
                defaults={"value": value},
            )

        from identity.auth import enrol, current_totp
        totp_secret = enrol(citizen, DEMO_PASSWORD)
        self.stdout.write(
            f"Citizen login: {CITIZEN_ID} / {DEMO_PASSWORD}\n"
            f"  TOTP secret: {totp_secret}\n"
            f"  code now   : {current_totp(totp_secret)}"
        )

        self.stdout.write(
            self.style.SUCCESS(
                f"Seeded {len(ATTRIBUTES)} attributes, {len(CONTEXTS)} "
                f"contexts, {len(RELYING_PARTIES)} relying parties, "
                f"1 citizen."
            )
        )
