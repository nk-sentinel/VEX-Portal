"""The portal's persisted schema.

This schema exists to answer one question, indefinitely: why was a finding
cleared, by whom, on what evidence, and when does it lapse. Every rule below
serves that.

Portability. A server database must stay a connection-string change away.
Every enum is stored as a string (``native_enum=False``) rather than a native
database ENUM type, every JSON column uses the generic ``sqlalchemy.JSON``
rather than ``JSONB``, and there are no array columns — a list is a JSON
column (an ordered array of scalars) or, where it needs its own identity and
timestamps, a child table. No column carries a dialect-specific server
default.

IDs and timestamps are generated in Python, not by the database: UUID4 ids
via ``default_factory=lambda: str(uuid4())`` and timezone-aware timestamps via
``default_factory=lambda: datetime.now(UTC)``. ``Base`` mixes in
``MappedAsDataclass`` specifically so those factories run at object
construction time rather than only at flush — a determination's ``created_at``
must be inspectable before it is ever added to a session, not just after a
round trip to the database.

A finding's identity is ``(assessment_id, cve, purl)``, enforced by a unique
constraint on ``finding`` — never the Nexus IQ violation id, which changes on
every re-scan. ``violation_id_snapshot`` records what that id was at
assessment time; it is evidence of the assessment's context, never identity.

Vocabulary: every name in this module says determination, assessment, or Not
Affected — with one deliberate exception. ``iq_determination_link.
policy_waiver_id`` keeps the literal field name the Nexus IQ API returns; it
lives behind the adapter boundary and is the only column that borrows IQ's
own term rather than the portal's.

The audit log is append-only. ``audit_entry`` rows can be inserted but never
updated or deleted — enforced by a ``before_flush`` event below, in code
rather than by convention, because the value of an audit trail is entirely
that nobody can quietly change what it says happened.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from sqlalchemy import JSON, DateTime, ForeignKey, MetaData, TypeDecorator, UniqueConstraint, event
from sqlalchemy import Enum as SAEnum
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    MappedAsDataclass,
    Session,
    mapped_column,
)

from app.domain.determination import Confidence, EvidenceTier, Justification, State

# Alembic autogenerate needs stable, predictable constraint names to diff
# migrations reliably; SQLAlchemy leaves them unnamed (and DB-generated,
# hence unstable) unless a naming convention is supplied.
_NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Role(StrEnum):
    """A capability-granting role a user may hold.

    Six roles, matching the RBAC table in ``docs/design/ui-spec.md``.
    ``app/services/authorization.py`` maps these onto capabilities — the
    call site checks a capability, never a role directly, so a role change
    there is a mapping edit, not a code change.
    """

    REQUESTER = "requester"
    REVIEWER = "reviewer"
    APPROVER = "approver"
    AUDITOR = "auditor"
    RISK_MANAGER = "risk_manager"
    ADMIN = "admin"


class AssessmentState(StrEnum):
    """Where an assessment sits in its review lifecycle."""

    DRAFT = "draft"
    ADMISSION = "admission"
    ADMISSION_FAILED = "admission_failed"
    ANALYSING = "analysing"
    NEEDS_REVIEW = "needs_review"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    EXPIRED = "expired"


class FindingOutcome(StrEnum):
    """Where one finding landed, at the finding-record's granularity.

    This is deliberately not ``app.domain.determination.State`` reused
    outright: a finding can also be ``NEEDS_REVIEW`` (routed to a human,
    nothing decided yet) or ``RISK_ACCEPTANCE_REQUIRED`` (no fix is
    available — CLAUDE.md rule 5 — handled by the app team out of band, and
    never a ``NOT_AFFECTED`` determination). Neither has a ``State`` member;
    ``State`` describes a *determination's* VEX analysis state, which is a
    narrower concept than a finding's routing status. Where the two concepts
    do overlap, the string values are kept identical on purpose
    (``not_affected`` / ``affected``) so the vocabulary never drifts for the
    outcomes they share.

    Two vocabularies at different layers with no explicit bridge drift
    silently — that is how holes opened on the previous branch. See
    :meth:`to_vex_state` for the pinned, tested bridge between them.
    """

    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    NEEDS_REVIEW = "needs_review"
    RISK_ACCEPTANCE_REQUIRED = "risk_acceptance_required"

    def to_vex_state(self) -> State | None:
        """The VEX state this outcome exports as, or None if it is not a determination.

        RISK_ACCEPTANCE_REQUIRED has no VEX counterpart on purpose: no fix
        exists, the app team takes it to their risk manager, and the IQ
        violation stays open. Mapping it to a VEX state would export a
        hand-off as a resolution.
        """
        return {
            FindingOutcome.NOT_AFFECTED: State.NOT_AFFECTED,
            FindingOutcome.AFFECTED: State.AFFECTED,
            FindingOutcome.NEEDS_REVIEW: State.UNDER_INVESTIGATION,
            FindingOutcome.RISK_ACCEPTANCE_REQUIRED: None,
        }[self]


class UtcDateTime(TypeDecorator[datetime]):
    """A timestamp that is always timezone-aware UTC, on every dialect.

    SQLite has no native timezone type, so a plain ``DateTime`` silently drops
    the offset on the way in and hands back a naive value. These columns are
    the audit trail — a timestamp that does not say when it happened is not
    much of a record — and ``expires_at`` is compared against an aware
    ``now``, so a naive value there is a ``TypeError`` waiting in the expiry
    path.

    Naive input is rejected rather than assumed to be UTC: guessing would
    make a wrong timestamp look authoritative.

    ``impl = DateTime`` means the compiled column type — and therefore the
    schema a migration creates — is unchanged (still ``DATETIME``/
    ``TIMESTAMP``); only the Python-level bind/result processing differs, so
    this is not schema drift relative to the existing ``0001_initial``
    migration.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime rejected; timestamps must carry a timezone")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class Base(MappedAsDataclass, DeclarativeBase, kw_only=True):
    """Declarative base for the portal schema.

    Two deliberate departures from the brief's illustrative
    ``declarative_base()`` call, both explained in the task report:

    * A SQLAlchemy 2.0 class-based ``Base`` (``DeclarativeBase``) is used
      instead of the legacy 1.x factory function, per this task's
      instruction to follow 2.0 declarative conventions.
    * ``MappedAsDataclass`` is mixed in (with ``kw_only=True`` so every
      column can be given a default without regard to declaration order)
      so that Python-side defaults — UUIDs, timestamps — are evaluated
      eagerly in the generated ``__init__``, not only when a flush occurs.
      Plain ``mapped_column(default=...)`` only runs at flush time; without
      this, a freshly constructed, never-flushed row would have
      ``created_at is None``.
    """

    metadata = MetaData(naming_convention=_NAMING_CONVENTION)

    type_annotation_map = {
        AssessmentState: SAEnum(AssessmentState, native_enum=False, length=32),
        FindingOutcome: SAEnum(FindingOutcome, native_enum=False, length=32),
        State: SAEnum(State, native_enum=False, length=32),
        Justification: SAEnum(Justification, native_enum=False, length=48),
        EvidenceTier: SAEnum(EvidenceTier, native_enum=False, length=16),
        Confidence: SAEnum(Confidence, native_enum=False, length=32),
        dict[str, Any]: JSON,
        list[str]: JSON,
        #: Every timestamp column in this schema (`created_at`, `expires_at`,
        #: ...) goes through `UtcDateTime` via this one entry, rather than
        #: each `mapped_column()` needing to say so individually — there is
        #: no correct reason for a timestamp in this schema to be anything
        #: other than timezone-aware UTC.
        datetime: UtcDateTime(),
    }


def _uuid4() -> str:
    return str(uuid4())


def _now() -> datetime:
    return datetime.now(UTC)


class User(Base, kw_only=True):
    """A local, database-backed account.

    This is the LOCAL auth provider's identity store only
    (``app/auth/local.py``) — for shadowlab and break-glass use. An
    LDAP/AD-authenticated user is never a row here: their identity is just
    the authenticated username, and their roles come live from group
    membership on every login (``app/auth/ldap.py``), never persisted
    locally, so there is nothing here to drift from AD's own group
    membership.

    ``password_hash`` is excluded from the generated ``__repr__``
    (``repr=False`` below). ``MappedAsDataclass`` would otherwise include
    every column in ``__repr__`` by default, and a hash in a log line, a
    stack trace, or a debugger session is exactly the kind of secret this
    schema promises never to surface.

    ``roles_json`` follows this file's own convention for JSON-backed
    columns (``detail_json``, ``evidence_refs_json``, ...): a list of
    ``Role`` values, stored as their string form.
    """

    __tablename__ = "user"

    id: Mapped[str] = mapped_column(primary_key=True, default_factory=_uuid4)
    username: Mapped[str] = mapped_column(unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(repr=False)
    roles_json: Mapped[list[str]] = mapped_column(JSON, default_factory=list)

    created_at: Mapped[datetime] = mapped_column(default_factory=_now)


class Assessment(Base, kw_only=True):
    """One review of one application at one scanned commit/artifact.

    Keyed on ``application_id`` + ``report_id``, never on a Nexus IQ
    violation id — violation ids are reassigned on every re-scan, so keying
    on them would fragment a single case's history across scans.
    """

    __tablename__ = "assessment"

    id: Mapped[str] = mapped_column(primary_key=True, default_factory=_uuid4)

    application_id: Mapped[str] = mapped_column()
    report_id: Mapped[str] = mapped_column()
    scan_id: Mapped[str | None] = mapped_column(default=None)
    commit_sha: Mapped[str | None] = mapped_column(default=None)
    repository_url: Mapped[str | None] = mapped_column(default=None)
    artifact_ref: Mapped[str | None] = mapped_column(default=None)

    state: Mapped[AssessmentState] = mapped_column(default=AssessmentState.DRAFT)
    requester: Mapped[str] = mapped_column()

    #: The requester's own words on why the assessment is needed — the
    #: intake form's "Why is this needed?" box. Free text, and NOT a VEX
    #: justification: a VEX justification explains why one vulnerability
    #: does not apply and belongs on a Finding. Reviewer context only; the
    #: rule engine never reads it.
    requester_note: Mapped[str | None] = mapped_column(default=None)

    created_at: Mapped[datetime] = mapped_column(default_factory=_now)
    submitted_at: Mapped[datetime | None] = mapped_column(default=None)

    #: Set when a NOT_AFFECTED determination is committed against this
    #: assessment. Determinations expire at 7 days and are never
    #: auto-renewed (CLAUDE.md rule 4).
    expires_at: Mapped[datetime | None] = mapped_column(default=None)


class Finding(Base, kw_only=True):
    """One (assessment, CVE, purl) case.

    The unique constraint below — not the Nexus IQ violation id — is this
    row's identity. ``violation_id_snapshot`` records what the IQ violation
    id was at assessment time; it is evidence of context, never identity.
    """

    __tablename__ = "finding"
    __table_args__ = (UniqueConstraint("assessment_id", "cve", "purl"),)

    id: Mapped[str] = mapped_column(primary_key=True, default_factory=_uuid4)

    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessment.id", ondelete="CASCADE"), index=True
    )
    cve: Mapped[str] = mapped_column()
    purl: Mapped[str] = mapped_column()

    policy_id: Mapped[str | None] = mapped_column(default=None)
    #: What the Nexus IQ violation id was when this finding was assessed.
    #: Evidence of the assessment's context, never the finding's identity.
    violation_id_snapshot: Mapped[str | None] = mapped_column(default=None)
    threat_level: Mapped[int | None] = mapped_column(default=None)

    outcome: Mapped[FindingOutcome | None] = mapped_column(default=None)
    justification: Mapped[Justification | None] = mapped_column(default=None)
    tier: Mapped[EvidenceTier | None] = mapped_column(default=None)
    confidence: Mapped[Confidence | None] = mapped_column(default=None)
    decided_by: Mapped[str | None] = mapped_column(default=None)
    decided_at: Mapped[datetime | None] = mapped_column(default=None)


class Evidence(Base, kw_only=True):
    """A snapshotted extract backing a finding (or an assessment-wide fact).

    ``source_ref`` points at ELK or an artifact digest for provenance, but
    the extract itself is stored here — an audit trail that depends on
    another team's retention policy is not a trail.
    """

    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(primary_key=True, default_factory=_uuid4)

    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessment.id", ondelete="CASCADE"), index=True
    )
    #: Nullable: some evidence is assessment-wide (e.g. artifact inventory)
    #: rather than tied to one finding.
    finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("finding.id"), default=None, index=True
    )

    collector: Mapped[str] = mapped_column()
    key: Mapped[str] = mapped_column()
    value_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    source_ref: Mapped[str | None] = mapped_column(default=None)
    collected_at: Mapped[datetime] = mapped_column(default_factory=_now)


class CveProfile(Base, kw_only=True):
    """An org-wide, app-independent cache of a CVE's intrinsic properties.

    Keyed on the CVE id itself — deliberately not scoped to an assessment or
    application, since intrinsic properties (CVSS vector, EPSS, KEV) do not
    vary by the application being reviewed.
    """

    __tablename__ = "cve_profile"

    cve: Mapped[str] = mapped_column(primary_key=True)
    intrinsic_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    model_version: Mapped[str | None] = mapped_column(default=None)
    computed_at: Mapped[datetime] = mapped_column(default_factory=_now)


class RuleResult(Base, kw_only=True):
    """One rule's verdict against one finding. One row per rule that ran."""

    __tablename__ = "rule_result"

    id: Mapped[str] = mapped_column(primary_key=True, default_factory=_uuid4)

    finding_id: Mapped[str] = mapped_column(
        ForeignKey("finding.id", ondelete="CASCADE"), index=True
    )
    rule_id: Mapped[str] = mapped_column()
    rule_version: Mapped[str] = mapped_column()
    #: A best-effort mapping onto the VEX-state vocabulary — NOT an
    #: equivalent encoding of the rule's actual verdict, despite this
    #: column's name suggesting otherwise. ``app.rules.engine.RuleEvaluation.verdict``
    #: is a ``RuleVerdict`` (SATISFIED/NOT_SATISFIED/INAPPLICABLE/
    #: UNANSWERABLE — a rule's judgement about its own condition), a
    #: different, 4-valued vocabulary at a different layer than this
    #: column's 3-valued ``State`` (a finding's VEX disposition); only
    #: SATISFIED-with-a-clearing-justification maps onto this column
    #: unambiguously. **The authoritative value is
    #: ``detail_json["rule_verdict"]``, written by every caller that
    #: persists a row here** (``app/services/determination.py``'s
    #: ``_bridge_rule_verdict_to_state`` / ``_persist_rule_results``) —
    #: trust that field, not this one, when the actual ``RuleVerdict``
    #: matters. This column exists so simple VEX-state queries/filters stay
    #: possible without joining out to JSON; it is a lossy projection of the
    #: real verdict, not a second copy of it.
    verdict: Mapped[State] = mapped_column()
    tier: Mapped[EvidenceTier] = mapped_column()
    detail_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)


class AiVerdict(Base, kw_only=True):
    """One AI adjudicator pass against one finding."""

    __tablename__ = "ai_verdict"

    id: Mapped[str] = mapped_column(primary_key=True, default_factory=_uuid4)

    finding_id: Mapped[str] = mapped_column(
        ForeignKey("finding.id", ondelete="CASCADE"), index=True
    )
    model_id: Mapped[str] = mapped_column()
    prompt_version: Mapped[str] = mapped_column()

    state: Mapped[State] = mapped_column()
    justification: Mapped[Justification | None] = mapped_column(default=None)
    confidence: Mapped[Confidence] = mapped_column()

    evidence_refs_json: Mapped[list[str]] = mapped_column(JSON, default_factory=list)
    missing_evidence_json: Mapped[list[str]] = mapped_column(JSON, default_factory=list)

    #: Records the second-pass, independent confirmation check (e.g. the
    #: model/prompt version that ran it), required before a Tier 2 (STRONG)
    #: signal may auto-determine.
    refuted_by: Mapped[str | None] = mapped_column(default=None)

    created_at: Mapped[datetime] = mapped_column(default_factory=_now)


class IqDeterminationLink(Base, kw_only=True):
    """Links a finding to the Nexus IQ suppression it produced.

    ``policy_waiver_id`` is the ONLY column in this schema that keeps IQ's
    own field name rather than the portal's vocabulary — kept as-is because
    it is the literal identifier the IQ API returns, and it lives behind the
    adapter boundary.
    """

    __tablename__ = "iq_determination_link"

    id: Mapped[str] = mapped_column(primary_key=True, default_factory=_uuid4)

    finding_id: Mapped[str] = mapped_column(
        ForeignKey("finding.id", ondelete="CASCADE"), index=True
    )
    policy_waiver_id: Mapped[str] = mapped_column()
    #: Determinations expire at 7 days and are never auto-renewed (CLAUDE.md
    #: rule 4) — required, not optional, since a link without an expiry
    #: would silently violate that rule.
    expiry: Mapped[datetime] = mapped_column()

    created_at: Mapped[datetime] = mapped_column(default_factory=_now)
    revoked_at: Mapped[datetime | None] = mapped_column(default=None)


class AuditEntry(Base, kw_only=True):
    """An append-only record of who did what, and why.

    Insert-only: see ``_block_audit_mutation`` below. An audit row that can
    be edited after the fact is not an audit trail.
    """

    __tablename__ = "audit_entry"

    id: Mapped[str] = mapped_column(primary_key=True, default_factory=_uuid4)

    actor: Mapped[str] = mapped_column()
    action: Mapped[str] = mapped_column()
    subject_type: Mapped[str | None] = mapped_column(default=None)
    subject_id: Mapped[str | None] = mapped_column(default=None)
    detail_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)

    created_at: Mapped[datetime] = mapped_column(default_factory=_now)


class RuleConfig(Base, kw_only=True):
    """Admin-set overrides for one registered rule's auto-determination
    behaviour and thresholds (``docs/design/ui-spec.md`` screen 9, "Rules &
    Thresholds").

    No row for a rule means "the rule's built-in default applies" — this
    table holds overrides only, so a rule freshly added to
    ``app/rules/registry.py`` needs no backfill here.

    **Tier 3 rules must never carry ``auto_determination_enabled=True``.**
    Tier 3 (ESCALATION) evidence can never justify a clear (CLAUDE.md rule
    2), so "auto-determination" has no meaning for it — a Tier 3 rule has no
    toggle at all, absent rather than disabled (task-6 brief). That
    invariant is enforced at the API boundary (``app/api/admin.py``), not by
    a CHECK constraint here: validating "which rule ids are Tier 3" needs
    the rule registry (``app/rules/registry.py``), and this module must not
    import it — ``app/rules/engine.py`` already imports *from* this module
    (``FindingOutcome``), so a reverse import would be a cycle.
    """

    __tablename__ = "rule_config"

    rule_id: Mapped[str] = mapped_column(primary_key=True)

    #: Only meaningful for a Tier 1/2 rule id — see class docstring. Whether
    #: this rule's own SATISFIED-with-justification result may propose
    #: clearing a finding automatically.
    auto_determination_enabled: Mapped[bool] = mapped_column(default=True)

    #: The minimum agreement rate (0-1) this rule must hold against human
    #: review before it auto-suspends ("A rule below its agreement bar shows
    #: as auto-suspended"). None = no bar configured.
    agreement_bar: Mapped[float | None] = mapped_column(default=None)

    #: Rule-specific threshold overrides, e.g. ``{"epss_hard_block": 0.1}``
    #: for ``t3-epss`` — generic JSON rather than a dedicated column per
    #: rule, so a new threshold-bearing rule needs no migration.
    thresholds_json: Mapped[dict[str, Any]] = mapped_column(JSON, default_factory=dict)

    updated_at: Mapped[datetime] = mapped_column(default_factory=_now)
    updated_by: Mapped[str | None] = mapped_column(default=None)


@event.listens_for(Session, "before_flush")
def _block_audit_mutation(session: Session, _ctx: object, _instances: object) -> None:
    """An audit row that can be edited is not an audit trail.

    Enforced in the ORM rather than by reviewer discipline, because the whole
    value of the log is that nobody can quietly change what it says happened.
    """
    for obj in session.dirty:
        if isinstance(obj, AuditEntry) and session.is_modified(obj):
            raise PermissionError("audit_entry rows are append-only and cannot be modified")
    for obj in session.deleted:
        if isinstance(obj, AuditEntry):
            raise PermissionError("audit_entry rows are append-only and cannot be deleted")
