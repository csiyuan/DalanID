"""
Domain models for DalanID.

The central design commitment is that *contexts are data, not code*. A context
is a row in a table with a set of permitted attributes attached to it, so new
disclosure contexts can be introduced by an authorised relying party at runtime
without redeploying the service. Nothing in this module hardcodes which fields
Immigration or Public Health may see.

Model overview
--------------
Attribute          one disclosable field in the citizen schema
Context            a named purpose for disclosure (Immigration, Banking, ...)
ContextAttribute   through-table: which attributes a context may see
RelyingParty       an organisation that may request disclosure
Grant              through-table: which contexts an RP is authorised to invoke
Citizen            the subject of disclosure
CitizenAttribute   one attribute value held for one citizen
AuditEntry         hash-linked, tamper-evident record of every disclosure
"""

import hashlib
import json
import random
import time
import uuid

from django.db import (
    IntegrityError,
    OperationalError,
    models,
    transaction,
)
from django.utils import timezone


class Attribute(models.Model):
    """One disclosable field in the citizen schema.

    ``derivation`` marks attributes that must never be released in raw form.
    An attribute with derivation ``age_band`` is stored as a date of birth but
    disclosed as a coarse band, which is data minimisation applied *within* a
    field rather than only between fields.
    """

    class Derivation(models.TextChoices):
        NONE = "none", "Disclose raw value"
        AGE_BAND = "age_band", "Disclose age band only"
        YEAR_ONLY = "year_only", "Disclose year only"
        PRESENCE = "presence", "Disclose presence, not content"

    code = models.SlugField(max_length=64, unique=True)
    label = models.CharField(max_length=128)
    sensitivity = models.PositiveSmallIntegerField(
        default=1,
        help_text="1 (low) to 5 (high). Used for reporting, not enforcement.",
    )
    derivation = models.CharField(
        max_length=16, choices=Derivation.choices, default=Derivation.NONE
    )

    class Meta:
        ordering = ["code"]

    def __str__(self):
        return self.code


class Context(models.Model):
    """A named purpose for disclosure.

    ``is_active`` is a soft revocation switch: revoking a context must reject
    keys already issued against it, which is why verification checks the
    database rather than trusting the signed token alone.
    """

    slug = models.SlugField(max_length=64, unique=True)
    name = models.CharField(max_length=128)
    tier = models.CharField(max_length=32, default="Standard")
    purpose = models.TextField(
        blank=True,
        help_text="The stated purpose this context exists to serve. Recorded "
        "so that disclosure can be audited against declared purpose.",
    )
    attributes = models.ManyToManyField(
        Attribute, through="ContextAttribute", related_name="contexts"
    )
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        "RelyingParty",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="contexts_created",
    )
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["slug"]

    def __str__(self):
        return self.slug

    def permitted_codes(self):
        """Attribute codes this context may see, in schema order."""
        return list(
            self.attributes.order_by("code").values_list("code", flat=True)
        )


class ContextAttribute(models.Model):
    """Join row granting one context sight of one attribute."""

    context = models.ForeignKey(Context, on_delete=models.CASCADE)
    attribute = models.ForeignKey(Attribute, on_delete=models.CASCADE)

    class Meta:
        unique_together = [("context", "attribute")]

    def __str__(self):
        return f"{self.context.slug}:{self.attribute.code}"


class RelyingParty(models.Model):
    """An organisation permitted to request disclosure.

    Each RP holds its own signing secret. Compromise of one RP's secret
    therefore cannot be used to forge keys attributed to another, and an RP can
    be rotated or deactivated without affecting the rest of the federation.
    """

    slug = models.SlugField(max_length=64, unique=True)
    name = models.CharField(max_length=128)

    # Which signature suite this party is registered for. Verification reads
    # the algorithm from here and never from the presented token, which is
    # what prevents algorithm-confusion attacks. See identity/signatures.py.
    algorithm = models.CharField(max_length=16, default="ed25519")

    # Ed25519. The private key is stored only so the demonstration can sign on
    # a party's behalf; in deployment the service holds the public key alone.
    public_key = models.TextField(blank=True)
    private_key = models.TextField(blank=True)

    # HMAC-SHA256, retained for parties not yet migrated.
    signing_secret = models.CharField(max_length=128, blank=True)

    can_create_contexts = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    grants = models.ManyToManyField(
        Context, through="Grant", related_name="relying_parties"
    )
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["slug"]
        verbose_name_plural = "relying parties"

    def __str__(self):
        return self.slug

    @staticmethod
    def new_secret():
        return uuid.uuid4().hex + uuid.uuid4().hex


class Grant(models.Model):
    """Authorisation for one relying party to invoke one context.

    This is the model that answers the supervisor's question: possessing a
    valid signature is not sufficient. The RP must also hold a live grant for
    the context named in the key.
    """

    relying_party = models.ForeignKey(RelyingParty, on_delete=models.CASCADE)
    context = models.ForeignKey(Context, on_delete=models.CASCADE)
    is_active = models.BooleanField(default=True)
    granted_at = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = [("relying_party", "context")]

    def __str__(self):
        return f"{self.relying_party.slug}->{self.context.slug}"


class Citizen(models.Model):
    """The subject of disclosure.

    ``access_secret`` lets the citizen authenticate to read their own
    disclosure history. It is deliberately separate from every relying party
    secret: the subject of the data is not a relying party, and must not be
    able to invoke a disclosure context, nor a relying party able to read the
    subject's audit trail.
    """

    public_id = models.SlugField(max_length=64, unique=True)
    access_secret = models.CharField(max_length=128, blank=True)

    # Credentials for subject access. The password is stored only as a hash
    # produced by Django's configured hasher (PBKDF2 by default), so the
    # service never holds a recoverable password. The TOTP secret must be
    # stored recoverably because verification requires re-deriving the code,
    # which is why it is a shared secret rather than a hash.
    password_hash = models.CharField(max_length=256, blank=True)
    totp_secret = models.CharField(max_length=64, blank=True)

    # Throttling state. Without this, a six-digit second factor is guessable
    # in the time its window allows.
    failed_attempts = models.PositiveSmallIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["public_id"]

    def __str__(self):
        return self.public_id

    @staticmethod
    def new_secret():
        return uuid.uuid4().hex + uuid.uuid4().hex

    @property
    def is_locked(self):
        return bool(self.locked_until and timezone.now() < self.locked_until)

    def values_map(self):
        """All held values as ``{attribute_code: raw_value}``."""
        return {
            row.attribute.code: row.value
            for row in self.attribute_values.select_related("attribute")
        }


class CitizenAttribute(models.Model):
    """One attribute value held for one citizen."""

    citizen = models.ForeignKey(
        Citizen, on_delete=models.CASCADE, related_name="attribute_values"
    )
    attribute = models.ForeignKey(Attribute, on_delete=models.CASCADE)
    value = models.CharField(max_length=256)

    class Meta:
        unique_together = [("citizen", "attribute")]

    def __str__(self):
        return f"{self.citizen.public_id}:{self.attribute.code}"


class AuditEntry(models.Model):
    """Tamper-evident record of a disclosure decision.

    Each row stores the hash of the row before it, so the log forms a chain.
    Editing or deleting any historical row breaks every hash after it, which
    makes silent revision of the disclosure history detectable.

    Refused requests are logged as well as successful ones: a record of who
    *tried* to obtain data is as much a part of contextual integrity as a
    record of who received it.
    """

    # Bounded retries when a concurrent writer wins the race for the head.
    APPEND_RETRIES = 12

    sequence = models.PositiveIntegerField(unique=True)
    occurred_at = models.DateTimeField(default=timezone.now)
    relying_party_slug = models.CharField(max_length=64, blank=True)
    context_slug = models.CharField(max_length=64, blank=True)
    citizen_public_id = models.CharField(max_length=64, blank=True)
    disclosed_codes = models.JSONField(default=list)
    withheld_count = models.PositiveSmallIntegerField(default=0)
    outcome = models.CharField(max_length=32, default="disclosed")
    reason_code = models.CharField(max_length=48, blank=True)
    previous_hash = models.CharField(max_length=64, blank=True)
    entry_hash = models.CharField(max_length=64)

    class Meta:
        ordering = ["sequence"]
        verbose_name_plural = "audit entries"

    def __str__(self):
        return f"#{self.sequence} {self.outcome}"

    def payload(self):
        """Canonical, order-stable representation used for hashing.

        ``sort_keys`` and a fixed separator matter: the hash must be
        reproducible by an independent verifier, so the serialisation cannot
        depend on dict ordering or on Python's default spacing.
        """
        return json.dumps(
            {
                "sequence": self.sequence,
                "occurred_at": self.occurred_at.isoformat(),
                "relying_party": self.relying_party_slug,
                "context": self.context_slug,
                "citizen": self.citizen_public_id,
                "disclosed": sorted(self.disclosed_codes),
                "withheld": self.withheld_count,
                "outcome": self.outcome,
                "reason": self.reason_code,
                "previous_hash": self.previous_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def compute_hash(self):
        return hashlib.sha256(self.payload().encode("utf-8")).hexdigest()

    @classmethod
    def record(cls, **fields):
        """Append an entry, linking it to the current head of the chain.

        Appending is inherently serial: an entry cannot be hashed until the
        hash of its predecessor is known. A naive read-then-write loses that
        under concurrency — two simultaneous requests both read the same head,
        both compute sequence n+1, and the second violates the uniqueness
        constraint. Worse than the error is what it implies: if the constraint
        were absent, two entries would claim the same predecessor and the chain
        would silently fork.

        The append therefore runs inside a transaction that locks the current
        head with ``select_for_update``. On databases that honour row locks
        this serialises writers outright. SQLite ignores the lock and instead
        serialises on its own write lock, which can still surface as a lost
        race, so a bounded retry follows: on a uniqueness violation the entry
        is recomputed against the new head rather than abandoned.
        """
        last_error = None
        for attempt in range(cls.APPEND_RETRIES):
            try:
                with transaction.atomic():
                    head = (
                        cls.objects.select_for_update()
                        .order_by("-sequence")
                        .first()
                    )
                    entry = cls(
                        sequence=(head.sequence + 1) if head else 1,
                        previous_hash=head.entry_hash if head else "",
                        **fields,
                    )
                    entry.entry_hash = entry.compute_hash()
                    entry.save()
                    return entry
            except (IntegrityError, OperationalError) as error:
                # IntegrityError: another writer took this sequence number.
                # OperationalError: the table was locked before we got there.
                # Both mean the same thing operationally — we lost the race —
                # so both are retried against the new head. Backoff is
                # randomised so retrying writers do not re-collide in step.
                last_error = error
                time.sleep(random.uniform(0.01, 0.05) * (attempt + 1))
                continue
        raise IntegrityError(
            "Could not append to the audit chain after "
            f"{cls.APPEND_RETRIES} attempts: {last_error}"
        )

    @classmethod
    def verify_chain(cls):
        """Walk the chain and report the first broken link.

        Returns ``(ok, broken_sequence, detail)``. Detecting *where* the chain
        breaks is what makes the log useful evidence rather than a bare
        pass/fail.
        """
        previous_hash = ""
        for entry in cls.objects.order_by("sequence"):
            if entry.previous_hash != previous_hash:
                return False, entry.sequence, "previous_hash mismatch"
            if entry.entry_hash != entry.compute_hash():
                return False, entry.sequence, "entry contents altered"
            previous_hash = entry.entry_hash
        return True, None, "chain intact"


class UsedKey(models.Model):
    """A Context-Key that has already been presented.

    Signing and expiry together prove a key was issued by a particular party
    and is still inside its window. Neither prevents the same key being
    presented twice. An attacker who captures one in transit can replay it for
    the remainder of its lifetime and receive the same disclosure.

    Recording the ``jti`` at the moment of use makes keys single-use: the first
    presentation succeeds, every later one is refused. The stored row can be
    discarded once the key would have expired anyway, so the table stays
    bounded by the issuance rate times the maximum lifetime rather than growing
    without limit.
    """

    CLAIM_RETRIES = 8

    jti = models.CharField(max_length=64, unique=True)
    relying_party_slug = models.CharField(max_length=64, blank=True)
    used_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()

    class Meta:
        ordering = ["-used_at"]
        indexes = [models.Index(fields=["expires_at"])]

    def __str__(self):
        return self.jti

    @classmethod
    def claim(cls, jti: str, expires_at, relying_party_slug: str = "") -> bool:
        """Record a key as used. Returns False if it was already claimed.

        The uniqueness constraint does the work rather than a read-then-write
        check, so two simultaneous presentations of the same key cannot both
        pass: the database admits exactly one.

        Two database errors can arise here and they mean opposite things.
        ``IntegrityError`` means the row already exists — the key really was
        spent, and the caller must be refused. ``OperationalError`` means the
        table was locked and this writer never got to try; refusing on that
        would reject a legitimate first presentation because the server was
        briefly busy. Only the former is a refusal; the latter is retried.
        """
        for attempt in range(cls.CLAIM_RETRIES):
            try:
                with transaction.atomic():
                    cls.objects.create(
                        jti=jti,
                        expires_at=expires_at,
                        relying_party_slug=relying_party_slug[:64],
                    )
                return True
            except IntegrityError:
                return False
            except OperationalError:
                time.sleep(random.uniform(0.01, 0.04) * (attempt + 1))
                continue
        # Exhausted retries without ever reaching the constraint. Fail closed:
        # an unverifiable claim is treated as a replay rather than waved
        # through, because admitting a possible replay is the worse error.
        return False

    @classmethod
    def prune(cls) -> int:
        """Drop records for keys that have expired on their own."""
        deleted, _ = cls.objects.filter(
            expires_at__lt=timezone.now()
        ).delete()
        return deleted


class UsedTotpCode(models.Model):
    """A second-factor code that has already been accepted.

    A TOTP code stays valid for its whole time step, so without this an
    attacker who observes a code — over the shoulder, or in a log — can reuse
    it for the remainder of that window. Recording accepted codes per citizen
    makes each one single-use, which is what RFC 6238 section 5.2 requires of
    a verifier.
    """

    citizen = models.ForeignKey(
        Citizen, on_delete=models.CASCADE, related_name="used_totp_codes"
    )
    code = models.CharField(max_length=8)
    time_step = models.BigIntegerField()
    used_at = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = [("citizen", "time_step", "code")]
        ordering = ["-used_at"]

    def __str__(self):
        return f"{self.citizen.public_id}:{self.time_step}"

    @classmethod
    def claim(cls, citizen, code, time_step) -> bool:
        """Record a code as spent. False if it was already used."""
        try:
            with transaction.atomic():
                cls.objects.create(
                    citizen=citizen, code=code, time_step=time_step
                )
            return True
        except IntegrityError:
            return False
