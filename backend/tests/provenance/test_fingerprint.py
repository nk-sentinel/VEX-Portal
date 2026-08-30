import hashlib

from app.artifact.inventory import inspect_archive
from app.provenance.fingerprint import Verdict, compare
from tests.artifact.factories import make_jar, make_spring_boot_jar


def _inventory(library_payloads: dict[str, bytes]):
    return inspect_archive(make_spring_boot_jar(app_classes={}, libraries=library_payloads))


def _libs(count: int) -> dict[str, bytes]:
    return {f"lib-{i}.jar": make_jar({f"pkg/C{i}.class": bytes([i])}) for i in range(count)}


def test_identical_component_sets_match():
    payloads = _libs(10)
    inventory = _inventory(payloads)
    report = {hashlib.sha1(p).hexdigest() for p in payloads.values()}

    result = compare(report, inventory)

    assert result.verdict is Verdict.MATCH
    assert result.matched == 10
    assert result.ratio == 1.0


def test_completely_different_artifact_is_a_mismatch():
    inventory = _inventory(_libs(10))
    # Hashes of payloads that appear nowhere in the artifact.
    report = {hashlib.sha1(f"other-{i}".encode()).hexdigest() for i in range(10)}

    result = compare(report, inventory)

    assert result.verdict is Verdict.MISMATCH
    assert result.matched == 0


def test_small_divergence_still_matches_within_threshold():
    # A rebuild can legitimately differ by a component or two — a timestamped
    # jar, a reproducibility gap. The threshold accommodates that without
    # accepting a different application.
    payloads = _libs(100)
    inventory = _inventory(payloads)
    hashes = [hashlib.sha1(p).hexdigest() for p in payloads.values()]
    report = set(hashes[:97]) | {hashlib.sha1(b"extra-1").hexdigest()}

    result = compare(report, inventory)

    assert result.verdict is Verdict.MATCH
    assert result.matched == 97


def test_divergence_beyond_threshold_is_a_mismatch():
    payloads = _libs(100)
    inventory = _inventory(payloads)
    hashes = [hashlib.sha1(p).hexdigest() for p in payloads.values()]
    report = set(hashes[:50]) | {hashlib.sha1(f"e{i}".encode()).hexdigest() for i in range(50)}

    assert compare(report, inventory).verdict is Verdict.MISMATCH


def test_too_few_components_is_insufficient_rather_than_a_match():
    # Two components matching two components is not evidence of anything. A
    # MATCH here would admit an unrelated artifact on a coincidence.
    payloads = _libs(2)
    inventory = _inventory(payloads)
    report = {hashlib.sha1(p).hexdigest() for p in payloads.values()}

    result = compare(report, inventory)

    assert result.verdict is Verdict.INSUFFICIENT_DATA


def test_empty_report_is_insufficient():
    assert compare(set(), _inventory(_libs(10))).verdict is Verdict.INSUFFICIENT_DATA


def test_unmatched_hashes_are_reported_for_the_reviewer():
    payloads = _libs(10)
    inventory = _inventory(payloads)
    missing = hashlib.sha1(b"not-in-artifact").hexdigest()
    report = {hashlib.sha1(p).hexdigest() for p in payloads.values()} | {missing}

    result = compare(report, inventory)

    assert missing in result.unmatched_report_hashes


def test_summary_is_human_readable():
    payloads = _libs(10)
    inventory = _inventory(payloads)
    report = {hashlib.sha1(p).hexdigest() for p in payloads.values()}
    assert "10/10" in compare(report, inventory).summary()


def test_ratio_exactly_at_threshold_matches():
    # The comparison is inclusive. Nothing currently pins this, so a refactor
    # to a strict > would flip the boundary silently.
    payloads = _libs(100)
    inventory = _inventory(payloads)
    hashes = [hashlib.sha1(p, usedforsecurity=False).hexdigest() for p in payloads.values()]
    report = set(hashes[:95]) | {hashlib.sha1(f"e{i}".encode(), usedforsecurity=False).hexdigest()
                                 for i in range(5)}

    result = compare(report, inventory)

    assert result.ratio == 0.95
    assert result.verdict is Verdict.MATCH


def test_artifact_containing_unaccounted_components_is_a_mismatch():
    # The attacker-controlled direction: keep a scanned build's components and
    # add unscanned ones. Covering the whole report must not be sufficient.
    reported = _libs(20)
    extras = {
        f"extra-{i}.jar": make_jar({f"x/E{i}.class": bytes([i]) * (i + 3)}) for i in range(200)
    }
    inventory = _inventory({**reported, **extras})
    report = {hashlib.sha1(p, usedforsecurity=False).hexdigest() for p in reported.values()}

    result = compare(report, inventory)

    assert result.matched == 20
    assert result.ratio == 1.0
    assert result.verdict is Verdict.MISMATCH
    assert len(result.unmatched_artifact_hashes) == 200


def test_small_surplus_is_tolerated():
    # A scanner does not always identify every bundled JAR, so a little
    # surplus must not fail an otherwise clean match.
    reported = _libs(100)
    inventory = _inventory({**reported, "unidentified.jar": make_jar({"u/U.class": b"u" * 32})})
    report = {hashlib.sha1(p, usedforsecurity=False).hexdigest() for p in reported.values()}

    assert compare(report, inventory).verdict is Verdict.MATCH


def test_summary_reports_surplus_when_present():
    reported = _libs(10)
    extras = {
        f"x{i}.jar": make_jar({f"z/Z{i}.class": bytes([i]) * (i + 5)}) for i in range(10)
    }
    inventory = _inventory({**reported, **extras})
    report = {hashlib.sha1(p, usedforsecurity=False).hexdigest() for p in reported.values()}

    assert "not in the report" in compare(report, inventory).summary()
