"""Verify an OIDC provider's RFC 9068 access tokens inside a Python web API.

The Python sibling of goapiauth. A CLI logs in with the device grant, and a
service with the client-credentials grant, and each sends the provider's access
token as a bearer. `Verifier` checks it against the issuer's published keys and
returns the `Caller` it establishes: a person, or a service client limited to
its scopes.

    from pyapiauth import LazyVerifier, person_prefix, service_prefix

    verifier = LazyVerifier('https://auth.example.com', person_prefix('acme'), service_prefix=service_prefix('acme'))
    caller = verifier.verify(token)  # Rejected, or IssuerUnreachable

The FastAPI dependencies live in `pyapiauth.fastapi_dependencies`, installed
with the `fastapi` extra.
"""

from pyapiauth.errors import AuthError
from pyapiauth.errors import IssuerUnreachable
from pyapiauth.errors import Rejected
from pyapiauth.verifier import USER_AGENT
from pyapiauth.verifier import Caller
from pyapiauth.verifier import HeldKeys
from pyapiauth.verifier import LazyVerifier
from pyapiauth.verifier import Verifier
from pyapiauth.verifier import bearer_token
from pyapiauth.verifier import discover_jwks_uri
from pyapiauth.verifier import person_prefix
from pyapiauth.verifier import service_prefix

__all__ = [
    'USER_AGENT',
    'AuthError',
    'Caller',
    'HeldKeys',
    'IssuerUnreachable',
    'LazyVerifier',
    'Rejected',
    'Verifier',
    'bearer_token',
    'discover_jwks_uri',
    'person_prefix',
    'service_prefix',
]
