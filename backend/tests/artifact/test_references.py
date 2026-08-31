from app.artifact.inventory import inspect_archive
from app.artifact.references import scan_references
from tests.artifact.factories import make_class_file, make_spring_boot_jar

VULNERABLE = "org/apache/commons/text/StringSubstitutor"


def _inventory_with(app_classes: dict[str, bytes]):
    return inspect_archive(make_spring_boot_jar(app_classes=app_classes, libraries={}))


def test_collects_references_from_application_bytecode():
    inventory = _inventory_with({"com/example/App.class": make_class_file([VULNERABLE])})
    scan = scan_references(inventory)
    assert scan.references(VULNERABLE) is True
    assert scan.classes_scanned == 1


def test_reports_no_reference_when_the_class_is_never_touched():
    inventory = _inventory_with(
        {"com/example/App.class": make_class_file(["java/lang/String"])}
    )
    scan = scan_references(inventory)
    assert scan.references(VULNERABLE) is False


def test_accepts_the_dotted_and_suffixed_forms():
    inventory = _inventory_with({"com/example/App.class": make_class_file([VULNERABLE])})
    scan = scan_references(inventory)
    assert scan.references("org.apache.commons.text.StringSubstitutor") is True
    assert scan.references(f"{VULNERABLE}.class") is True


def test_detects_reflection_escape_hatch():
    # Class.forName reaches classes that never appear in a constant pool, so
    # "no reference found" stops being evidence of non-use.
    inventory = _inventory_with(
        {"com/example/App.class": make_class_file(["java/lang/Class", "java/lang/String"])}
    )
    scan = scan_references(inventory)
    assert any(hatch.kind == "reflection" for hatch in scan.escape_hatches)
    assert scan.is_conclusive() is False


def test_detects_service_loader_escape_hatch():
    inventory = _inventory_with(
        {"com/example/App.class": make_class_file(["java/util/ServiceLoader"])}
    )
    scan = scan_references(inventory)
    assert any(hatch.kind == "service_loader" for hatch in scan.escape_hatches)
    assert scan.is_conclusive() is False


def test_detects_spring_component_scanning():
    inventory = _inventory_with(
        {
            "com/example/App.class": make_class_file(
                ["org/springframework/context/annotation/ComponentScan"]
            )
        }
    )
    scan = scan_references(inventory)
    assert any(hatch.kind == "component_scan" for hatch in scan.escape_hatches)


def test_scan_is_conclusive_when_no_escape_hatch_is_present():
    inventory = _inventory_with(
        {"com/example/App.class": make_class_file(["java/lang/String"])}
    )
    assert scan_references(inventory).is_conclusive() is True


def test_scan_of_zero_classes_is_not_conclusive():
    # Scanning nothing is not evidence of anything. Without this, a scan that
    # saw no classes at all — no escape hatches, no unreadable classes — was
    # vacuously "conclusive", which is indistinguishable from an exhaustive
    # scan that genuinely found no reference.
    inventory = _inventory_with({})
    scan = scan_references(inventory)
    assert scan.classes_scanned == 0
    assert scan.escape_hatches == []
    assert scan.unreadable_classes == []
    assert scan.is_conclusive() is False


def test_unreadable_class_is_recorded_and_makes_the_scan_inconclusive():
    # A class we could not parse might be the one that references the target.
    # Silently skipping it would understate the references and could clear a
    # finding on incomplete evidence.
    inventory = _inventory_with(
        {
            "com/example/Good.class": make_class_file(["java/lang/String"]),
            "com/example/Bad.class": b"not a class file",
        }
    )
    scan = scan_references(inventory)
    assert scan.unreadable_classes == ["com/example/Bad.class"]
    assert scan.is_conclusive() is False
    assert scan.classes_scanned == 1
