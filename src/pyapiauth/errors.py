"""Exceptions raised by pyapiauth.

Both are one level under `AuthError`. They need opposite answers: a rejected
token is the caller's to fix by logging in again, and an unreachable issuer is
nobody's to fix by logging in.
"""

from __future__ import annotations


class AuthError(Exception):
    """Base class for every error this package raises."""


class Rejected(AuthError):
    """A token failed a check. The message is for the API's log, never for the caller."""


class IssuerUnreachable(AuthError):
    """The issuer could not be asked, or published no usable keys, so the token was never judged."""
