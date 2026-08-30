"""Tier 2 evidence: what the application's own bytecode actually references.

Reads the constant pool of every class the application compiled and collects
the classes they name. If the vulnerable class never appears, the application
does not statically reference it.

That is evidence, not proof. Reflection, ``ServiceLoader``, Spring component
scanning and other dynamic dispatch all reach classes that never appear in a
constant pool. This module therefore also detects those escape hatches, and
:meth:`ReferenceScan.is_conclusive` reports whether the absence of a reference
can be trusted. A scan that is not conclusive must route to human review rather
than clear a finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.artifact.classfile import referenced_classes
from app.artifact.errors import ArtifactError
from app.artifact.inventory import Inventory
from app.artifact.presence import normalize_class_path

#: Classes whose presence in a constant pool indicates the application can
#: reach code that static analysis cannot see. Mapped to the escape hatch kind
#: reported to the reviewer.
_ESCAPE_HATCH_MARKERS: dict[str, str] = {
    "java/lang/Class": "reflection",
    "java/lang/reflect/Method": "reflection",
    "java/lang/reflect/Constructor": "reflection",
    "java/util/ServiceLoader": "service_loader",
    "org/springframework/context/annotation/ComponentScan": "component_scan",
    "org/springframework/context/annotation/Import": "component_scan",
    "javax/naming/InitialContext": "jndi",
    "javax/naming/Context": "jndi",
    "org/springframework/expression/spel/standard/SpelExpressionParser": "spel",
}


@dataclass(frozen=True, slots=True)
class EscapeHatch:
    """A construct that lets the application reach code static analysis misses."""

    kind: str
    location: str


@dataclass(frozen=True, slots=True)
class ReferenceScan:
    """The result of reading every application class's constant pool."""

    referenced: set[str] = field(default_factory=set)
    escape_hatches: list[EscapeHatch] = field(default_factory=list)
    classes_scanned: int = 0

    #: Classes that could not be parsed. Any entry here means the scan did not
    #: see everything, so absence of a reference proves nothing.
    unreadable_classes: list[str] = field(default_factory=list)

    def references(self, class_path: str) -> bool:
        """Whether the application statically references ``class_path``."""
        return normalize_class_path(class_path).removesuffix(".class") in self.referenced

    def is_conclusive(self) -> bool:
        """Whether absence of a reference can be trusted as evidence.

        False when any dynamic-dispatch escape hatch was found, or when any
        class could not be read. In both cases the application may reach code
        this scan did not observe.
        """
        return not self.escape_hatches and not self.unreadable_classes


def scan_references(inventory: Inventory) -> ReferenceScan:
    """Read every application class in ``inventory`` and collect its references.

    Only the application's own classes are read. A bundled library referencing
    a vulnerable class says nothing about whether the application does, so
    including library classes would inflate the reference set and destroy the
    evidence's value.
    """
    referenced: set[str] = set()
    hatches: list[EscapeHatch] = []
    unreadable: list[str] = []
    scanned = 0

    for path, payload in sorted(inventory.app_classes.items()):
        try:
            names = referenced_classes(payload)
        except ArtifactError:
            unreadable.append(path)
            continue

        scanned += 1
        referenced |= names
        hatches.extend(
            EscapeHatch(kind=_ESCAPE_HATCH_MARKERS[name], location=path)
            for name in sorted(names)
            if name in _ESCAPE_HATCH_MARKERS
        )

    return ReferenceScan(
        referenced=referenced,
        escape_hatches=hatches,
        classes_scanned=scanned,
        unreadable_classes=unreadable,
    )
