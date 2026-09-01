"""Pydantic request/response shapes for the API layer.

Deliberately separate from ``app/repos/models.py`` (the persisted schema):
a response shape is what a screen needs, not what a table happens to store,
and the two are allowed to diverge. See each module's own docstring for the
screen(s) it serves — every shape here traces back to a specific screen in
``docs/design/ui-spec.md``, never to a table shape alone.

**The Nexus IQ term for the suppression mechanism behind a Not Affected
determination is off-limits in this package, full stop.** This package is
user- and screen-facing; see the project CLAUDE.md and ``docs/naming.md``
for the vocabulary rule and why it matters.
"""

from __future__ import annotations
