"""Failures raised while inspecting artifacts.

These exist so that "I could not read this" is never silently reported as
"the class is not present". The first is a bug or a corrupt input; the second
is Tier 1 proof that clears a finding. Collapsing them would manufacture proof
out of a parse failure.
"""


class ArtifactError(Exception):
    """Base for every failure raised while inspecting an artifact."""


class MalformedArtifact(ArtifactError):
    """The artifact could not be read as the archive type it claims to be."""


class NotAClassFile(ArtifactError):
    """The bytes given are not a Java class file."""


class MalformedClassFile(ArtifactError):
    """The class file header parsed but its constant pool did not."""
