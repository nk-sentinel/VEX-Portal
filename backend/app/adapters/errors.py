"""The typed failure taxonomy every real adapter client raises.

Nothing outside ``app/adapters/`` should ever need to import ``httpx`` or
``boto3`` to understand why a call to an external system failed — these three
exception types, plus the status code carried on
:class:`UpstreamResponseError`, are the entire vocabulary a caller needs. A
5xx, a connection failure and a timeout are each a *different* type here on
purpose, so a caller that wants to (for example) retry a timeout but not a
5xx can do so with an ``except`` clause rather than string-matching a message.

**No secret ever reaches one of these.** Every constructor here takes only
primitives — an HTTP method, a path with no query string, a status code —
never a ``httpx.Request``/``httpx.Response`` or a ``botocore`` exception
object. A token lives in the ``Authorization`` header (or, for Bedrock, in
AWS SigV4 signing material); neither is ever read back out of a request to
build a message, so no exception message, ``repr()``, or log record produced
by an adapter can carry one — even on a failure path, even by a future editor
reusing ``str(response.request)`` for a "helpful" error message.
"""

from __future__ import annotations


class AdapterError(Exception):
    """Base class for every error a real adapter client raises."""


class UpstreamTimeout(AdapterError):
    """The upstream system did not answer inside the configured timeout, even
    after the bounded retry."""


class UpstreamUnavailable(AdapterError):
    """A connection to the upstream system could not be established — DNS,
    connection refused, connection reset — even after the bounded retry."""


class UpstreamResponseError(AdapterError):
    """The upstream system answered with a status this adapter treats as a
    hard failure rather than success or a typed absence.

    Used both for a 5xx (a struggling server) and for a 404 against a
    resource the caller itself named and that must exist — see each client
    method's docstring for which of its 404s this is, versus the ones that
    return ``None``.
    """

    def __init__(self, method: str, path: str, status_code: int) -> None:
        self.method = method
        self.path = path
        self.status_code = status_code
        super().__init__(f"{method} {path} -> HTTP {status_code}")
