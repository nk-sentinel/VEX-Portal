"""Pydantic request/response shapes for the API layer.

Deliberately separate from ``app/repos/models.py`` (the persisted schema):
a response shape is what a screen needs, not what a table happens to store,
and the two are allowed to diverge. See each module's own docstring for the
screen(s) it serves — every shape here traces back to a specific screen in
``docs/design/ui-spec.md``, never to a table shape alone.

**"Waiver" never appears here.** This package is user- and screen-facing;
see the project CLAUDE.md and ``docs/naming.md``.
"""

from __future__ import annotations
