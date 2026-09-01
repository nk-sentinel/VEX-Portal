"""Tests for the adjudication service (``app/services/adjudication.py``).

Most cases use a stub ``Adjudicator`` so each behaviour (abstention, the
refute pass, disagreement, a malformed response) is exercised deterministically
without depending on a live fake producing a specific sequence of responses.
One round trip against the live fakes (``fakes/iq`` + ``fakes/bedrock``)
proves the whole chain works over real HTTP.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.factory import get_adjudicator, get_iq_client
from app.adapters.protocols import AiVerdictDto, FindingRef, VulnDetail
from app.config import AdapterMode, Settings
from app.domain.determination import Confidence, Justification, State
from app.evidence.pack import ComponentEvidence, EvidencePack
from app.provenance.fingerprint import FingerprintResult, Verdict
from app.repos.models import CveProfile
from app.services.adjudication import (
    AdjudicationResult,
    MalformedVerdict,
    adjudicate_finding,
)
from tests.adapters.support import BEDROCK_BASE_URL, IQ_BASE_URL, require_reachable

PACK = EvidencePack(
    provenance=FingerprintResult(
        verdict=Verdict.MATCH,
        matched=7,
        report_total=7,
        unmatched_report_hashes=[],
        unmatched_artifact_hashes=[],
        surplus_ratio=0.0,
        ratio=1.0,
    ),
    components=[
        ComponentEvidence(
            cve="CVE-2024-0001",
            class_paths=["com/example/Vulnerable.class"],
            class_present=True,
            referenced=False,
            reference_scan_conclusive=True,
        )
    ],
)

FINDING = FindingRef(application_id="app-1", cve="CVE-2024-0001", purl="pkg:maven/x/y@1.0?type=jar")

_VULN = VulnDetail(
    cve="CVE-2024-0001",
    cvss_vector=None,
    cvss_score=None,
    epss_score=None,
    is_kev=False,
    cwe_ids=[],
    affected_version_range=None,
    root_causes=["com/example/Vulnerable.class"],
)

_CLEAR = AiVerdictDto(
    state=State.NOT_AFFECTED,
    justification=Justification.CODE_NOT_PRESENT,
    confidence=Confidence.HIGH,
    evidence_refs=["class_absent:CVE-2024-0001:com/example/Vulnerable.class"],
    missing_evidence=[],
)

_REJECT = AiVerdictDto(
    state=State.AFFECTED,
    justification=None,
    confidence=Confidence.HIGH,
    evidence_refs=["referenced:CVE-2024-0001:com/example/App.class"],
    missing_evidence=[],
)

_ABSTAIN = AiVerdictDto(
    state=State.UNDER_INVESTIGATION,
    justification=None,
    confidence=Confidence.INSUFFICIENT,
    evidence_refs=[],
    missing_evidence=["conclusive reference scan"],
)


class _StubIq:
    """A minimal, Protocol-conforming IqClient — only ``vulnerability`` is
    exercised by adjudication (the CVE-intrinsic cache)."""

    def __init__(self, vuln: VulnDetail = _VULN) -> None:
        self._vuln = vuln
        self.calls = 0

    async def applications_for_user(self, user_token: str):  # pragma: no cover - unused
        raise NotImplementedError

    async def report(self, application_id: str, report_id: str):  # pragma: no cover - unused
        raise NotImplementedError

    async def vulnerability(self, vuln_id: str, component_purl: str | None) -> VulnDetail:
        self.calls += 1
        return self._vuln

    async def remediation(self, application_id: str, purl: str):  # pragma: no cover - unused
        raise NotImplementedError

    async def source_control(self, application_id: str):  # pragma: no cover - unused
        raise NotImplementedError

    async def create_determination(self, finding, options):  # pragma: no cover - unused
        raise NotImplementedError

    async def revoke_determination(self, link_id: str) -> None:  # pragma: no cover - unused
        raise NotImplementedError


class _SequenceAdjudicator:
    """Returns each verdict in ``verdicts`` in order, repeating the last one
    once exhausted. Records how many times it was called."""

    def __init__(self, *verdicts: AiVerdictDto) -> None:
        self._verdicts = list(verdicts)
        self.calls = 0

    async def adjudicate(self, pack: EvidencePack, finding: FindingRef) -> AiVerdictDto:
        self.calls += 1
        index = min(self.calls - 1, len(self._verdicts) - 1)
        return self._verdicts[index]


async def test_a_valid_verdict_parses(session: AsyncSession) -> None:
    iq = _StubIq()
    adjudicator = _SequenceAdjudicator(_REJECT)

    result = await adjudicate_finding(
        PACK, FINDING, adjudicator=adjudicator, iq=iq, session=session
    )

    assert isinstance(result, AdjudicationResult)
    assert result.verdict.state is State.AFFECTED
    assert result.requires_review is False
    assert result.refute_verdict is None
    assert adjudicator.calls == 1


async def test_malformed_verdict_with_no_justification_raises(session: AsyncSession) -> None:
    unjustified = replace(_CLEAR, justification=None)
    adjudicator = _SequenceAdjudicator(unjustified)

    with pytest.raises(MalformedVerdict, match="no justification"):
        await adjudicate_finding(
            PACK, FINDING, adjudicator=adjudicator, iq=_StubIq(), session=session
        )


async def test_malformed_verdict_with_tier3_only_justification_raises(
    session: AsyncSession,
) -> None:
    """Tier 3 evidence may never clear a finding — an adjudicator proposing
    not_affected on a perimeter/mitigating-control justification must be
    rejected, not accepted, even though it is a structurally valid
    ``AiVerdictDto``."""
    unsafe = replace(_CLEAR, justification=Justification.PROTECTED_AT_PERIMETER)
    adjudicator = _SequenceAdjudicator(unsafe)

    with pytest.raises(MalformedVerdict, match="may not justify"):
        await adjudicate_finding(
            PACK, FINDING, adjudicator=adjudicator, iq=_StubIq(), session=session
        )


async def test_malformed_verdict_with_no_evidence_refs_raises(session: AsyncSession) -> None:
    empty_evidence = replace(_CLEAR, evidence_refs=[])
    adjudicator = _SequenceAdjudicator(empty_evidence)

    with pytest.raises(MalformedVerdict, match="no evidence references"):
        await adjudicate_finding(
            PACK, FINDING, adjudicator=adjudicator, iq=_StubIq(), session=session
        )


async def test_abstention_routes_to_review_with_no_refute_pass(session: AsyncSession) -> None:
    adjudicator = _SequenceAdjudicator(_ABSTAIN)

    result = await adjudicate_finding(
        PACK, FINDING, adjudicator=adjudicator, iq=_StubIq(), session=session
    )

    assert result.requires_review is True
    assert result.refute_verdict is None
    assert adjudicator.calls == 1


async def test_refute_pass_runs_on_a_proposed_clear(session: AsyncSession) -> None:
    adjudicator = _SequenceAdjudicator(_CLEAR, _CLEAR)

    result = await adjudicate_finding(
        PACK, FINDING, adjudicator=adjudicator, iq=_StubIq(), session=session
    )

    assert adjudicator.calls == 2
    assert result.refute_verdict is not None
    assert result.requires_review is False


async def test_refute_pass_does_not_run_on_a_reject(session: AsyncSession) -> None:
    adjudicator = _SequenceAdjudicator(_REJECT)

    result = await adjudicate_finding(
        PACK, FINDING, adjudicator=adjudicator, iq=_StubIq(), session=session
    )

    assert adjudicator.calls == 1
    assert result.refute_verdict is None


async def test_refute_disagreement_routes_to_review(session: AsyncSession) -> None:
    adjudicator = _SequenceAdjudicator(_CLEAR, _REJECT)

    result = await adjudicate_finding(
        PACK, FINDING, adjudicator=adjudicator, iq=_StubIq(), session=session
    )

    assert adjudicator.calls == 2
    assert result.refute_verdict is not None
    assert result.refute_verdict.state is State.AFFECTED
    assert result.requires_review is True
    # The primary verdict is preserved even though it was disputed — the
    # determination service decides what to do with a disagreement, this
    # service only flags it.
    assert result.verdict.state is State.NOT_AFFECTED


async def test_refute_abstention_also_counts_as_disagreement(session: AsyncSession) -> None:
    adjudicator = _SequenceAdjudicator(_CLEAR, _ABSTAIN)

    result = await adjudicate_finding(
        PACK, FINDING, adjudicator=adjudicator, iq=_StubIq(), session=session
    )

    assert result.requires_review is True


async def test_cve_intrinsic_cache_is_used_on_a_second_call_for_the_same_cve(
    session: AsyncSession,
) -> None:
    iq = _StubIq()
    adjudicator = _SequenceAdjudicator(_REJECT)

    other_finding = FindingRef(
        application_id="app-2", cve=FINDING.cve, purl="pkg:maven/other/z@2.0?type=jar"
    )

    await adjudicate_finding(PACK, FINDING, adjudicator=adjudicator, iq=iq, session=session)
    await adjudicate_finding(PACK, other_finding, adjudicator=adjudicator, iq=iq, session=session)

    assert iq.calls == 1

    cached = await session.get(CveProfile, FINDING.cve)
    assert cached is not None
    assert cached.intrinsic_json["cve"] == FINDING.cve


async def test_adjudication_round_trips_against_live_fakes(session: AsyncSession) -> None:
    """The clearly-not-affected sample CVE (CVE-2015-6420) over real HTTP:
    fake Bedrock's canned verdict, the CVE-intrinsic cache backed by fake
    IQ's vuln lookup, and the refute pass (fake Bedrock returns the same
    canned verdict for both calls, so the refute agrees).
    """
    require_reachable(IQ_BASE_URL)
    require_reachable(BEDROCK_BASE_URL)

    settings = Settings(
        adapter_mode=AdapterMode.FAKE,
        iq_service_user="svc",
        iq_service_token=SecretStr("iq-tok"),
    )
    iq = get_iq_client(settings)
    adjudicator = get_adjudicator(settings)

    finding = FindingRef(
        application_id="4f6d8a2c9b1e4a7f8c3d2b1a0f9e8d7c",
        cve="CVE-2015-6420",
        purl="pkg:maven/commons-collections/commons-collections@3.2.1?type=jar",
    )
    pack = EvidencePack(
        provenance=FingerprintResult(
            verdict=Verdict.MATCH,
            matched=7,
            report_total=7,
            unmatched_report_hashes=[],
            unmatched_artifact_hashes=[],
            surplus_ratio=0.0,
            ratio=1.0,
        ),
        components=[
            ComponentEvidence(
                cve="CVE-2015-6420",
                class_paths=["org/apache/commons/collections/functors/InvokerTransformer.class"],
                class_present=False,
                referenced=False,
                reference_scan_conclusive=True,
            )
        ],
    )

    result = await adjudicate_finding(
        pack, finding, adjudicator=adjudicator, iq=iq, session=session
    )

    assert result.verdict.state is State.NOT_AFFECTED
    assert result.requires_review is False
    assert result.vuln_detail.cve == "CVE-2015-6420"
