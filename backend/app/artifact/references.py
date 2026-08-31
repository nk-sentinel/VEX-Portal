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
from app.artifact.presence import candidate_class_paths

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
        """Whether the application statically references ``class_path``.

        A dotted ``class_path`` is ambiguous between a top-level class and a
        nested class (see :func:`app.artifact.presence.candidate_class_paths`
        for why nothing in the string settles it). Every plausible form is
        checked, and this reports ``False`` only if none of them was
        referenced — the same reasoning presence.py applies to a raw dotted
        report path against a ``$``-stored nested class.
        """
        return any(
            candidate.removesuffix(".class") in self.referenced
            for candidate in candidate_class_paths(class_path)
        )

    def is_conclusive(self) -> bool:
        """Whether absence of a reference can be trusted as evidence.

        False when any dynamic-dispatch escape hatch was found, when any class
        could not be read, or when nothing was scanned at all. A scan of zero
        classes is not evidence that a class is unreferenced — it is evidence
        that nothing was examined, which a layout-detection bug (an inert
        empty directory entry flipping the archive to a layout whose class
        prefix matches nothing real) can produce with a clean escape-hatch and
        unreadable-classes record.
        """
        return self.classes_scanned > 0 and not self.escape_hatches and not self.unreadable_classes


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
