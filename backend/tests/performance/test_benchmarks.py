"""Performance benchmarks.

These assert wall-clock budgets rather than measuring for a report. A
determination is made while a reviewer waits, and the evidence engine runs
before anything else can happen, so a regression here is felt directly.

Budgets are deliberately loose — 4x the observed time on a modest machine — so
they catch algorithmic regressions (an accidental O(n^2), a re-opened archive
per lookup) without failing on a busy CI box.
"""

import time

import pytest

from app.artifact.inventory import inspect_archive
from app.artifact.presence import contains_class
from app.artifact.references import scan_references
from app.evidence.pack import build_pack
from tests.artifact.factories import make_class_file, make_jar, make_spring_boot_jar

TARGET = "org/apache/commons/text/StringSubstitutor.class"


@pytest.fixture(scope="module")
def large_artifact() -> bytes:
    """A fat JAR of realistic enterprise shape: 300 libraries, 2,000 app classes."""
    libraries = {
        f"lib-{i}.jar": make_jar({f"org/vendor{i}/Class{j}.class": bytes([j % 256]) * 64
                                  for j in range(10)})
        for i in range(300)
    }
    libraries["commons-text-1.9.jar"] = make_jar({TARGET: b"x" * 512})
    app_classes = {
        f"com/example/pkg{i // 100}/Service{i}.class": make_class_file(
            [f"com/example/Dep{i % 50}", "java/lang/String"]
        )
        for i in range(2000)
    }
    return make_spring_boot_jar(app_classes=app_classes, libraries=libraries)


def test_inventory_of_large_artifact(large_artifact: bytes):
    start = time.perf_counter()
    inventory = inspect_archive(large_artifact)
    elapsed = time.perf_counter() - start

    assert len(inventory.libraries) == 301
    assert len(inventory.app_classes) == 2000
    assert elapsed < 20.0, f"inventory took {elapsed:.2f}s"


def test_reference_scan_of_large_artifact(large_artifact: bytes):
    inventory = inspect_archive(large_artifact)
    start = time.perf_counter()
    scan = scan_references(inventory)
    elapsed = time.perf_counter() - start

    assert scan.classes_scanned == 2000
    assert elapsed < 10.0, f"reference scan took {elapsed:.2f}s"


def test_presence_check_of_large_artifact(large_artifact: bytes):
    start = time.perf_counter()
    assert contains_class(large_artifact, TARGET) is True
    elapsed = time.perf_counter() - start
    assert elapsed < 20.0, f"presence check took {elapsed:.2f}s"


def test_build_pack_does_not_rescan_per_finding(large_artifact: bytes):
    """The guard against the obvious regression.

    A naive build_pack calls contains_class once per class path, re-opening and
    re-walking the whole archive each time. With 40 findings that is 40 full
    walks of a 300-library JAR. Twenty findings must not cost twenty times one.
    """
    one = {"CVE-0001": [TARGET]}
    twenty = {f"CVE-{i:04d}": [TARGET] for i in range(20)}

    start = time.perf_counter()
    build_pack(large_artifact, set(), one)
    single = time.perf_counter() - start

    start = time.perf_counter()
    build_pack(large_artifact, set(), twenty)
    many = time.perf_counter() - start

    assert many < single * 5, (
        f"20 findings took {many:.2f}s vs {single:.2f}s for one — "
        "build_pack is re-walking the archive per finding"
    )
