"""FastAPI dependencies that admit a request by its bearer token, installed with the `fastapi` extra.

goapiauth's `RequireBearer` and `LimitServices`, as dependency factories:

    from fastapi import APIRouter, Depends
    from pyapiauth import LazyVerifier, person_prefix, service_prefix
    from pyapiauth.fastapi_dependencies import person_dependency

    verifier = LazyVerifier('https://auth.example.com', person_prefix('acme'), service_prefix=service_prefix('acme'))
    router = APIRouter(dependencies=[Depends(person_dependency(verifier))])

Each puts the verified `Caller` on `request.state.caller` and returns it. A
refusal is an `HTTPException`, so FastAPI answers it as `{"detail": ...}`:

- **401** with a `WWW-Authenticate` challenge for a missing or rejected token.
  The detail is one opaque sentence, so a caller probing with forged tokens
  learns nothing about which check failed. The reason goes to the log.
- **503** where the issuer cannot be reached, because a login cannot fix that.
- **403** where a service client reaches a route it holds no scope for.

The bearer is the only credential read. A header a proxy might set, such as
`Remote-User`, is whatever the caller typed unless the proxy strips it.
"""

from __future__ import annotations

import logging

from fastapi import HTTPException
from fastapi import Request

from .errors import IssuerUnreachable
from .errors import Rejected
from .verifier import Caller
from .verifier import bearer_token

log = logging.getLogger(__name__)

UNAUTHORIZED_DETAIL = 'Invalid credentials'
ISSUER_UNAVAILABLE_DETAIL = 'Identity provider unavailable'
PERSON_ONLY_DETAIL = 'This route answers a person, not a service client'
SCOPE_REFUSED_DETAIL = 'This service client holds no scope this route answers'


def caller_dependency(verifier):
    """A dependency admitting any caller whose token `verifier` accepts."""

    def require_caller(request: Request) -> Caller:
        token = bearer_token(request.headers.get('Authorization', ''))
        if not token:
            log.info('bearer_missing', extra={'path': request.url.path})
            raise HTTPException(401, UNAUTHORIZED_DETAIL, {'WWW-Authenticate': 'Bearer'})
        try:
            caller = verifier.verify(token)
        except IssuerUnreachable as error:
            log.error('issuer_unreachable', extra={'path': request.url.path, 'error': str(error)})
            raise HTTPException(503, ISSUER_UNAVAILABLE_DETAIL) from None
        except Rejected as error:
            log.warning('bearer_rejected', extra={'path': request.url.path, 'error': str(error)})
            raise HTTPException(401, UNAUTHORIZED_DETAIL, {'WWW-Authenticate': 'Bearer error="invalid_token"'}) from None
        request.state.caller = caller
        return caller

    return require_caller


def person_dependency(verifier):
    """As `caller_dependency`, refusing a service principal with 403."""
    require_caller = caller_dependency(verifier)

    def require_person(request: Request) -> Caller:
        caller = require_caller(request)
        if caller.service:
            log.info('service_refused', extra={'path': request.url.path, 'client_id': caller.client_id})
            raise HTTPException(403, PERSON_ONLY_DETAIL)
        return caller

    return require_person


def person_or_scoped_service_dependency(verifier, scope):
    """As `caller_dependency`, admitting a person, or a service principal holding `scope`."""
    require_caller = caller_dependency(verifier)

    def require_person_or_scope(request: Request) -> Caller:
        caller = require_caller(request)
        if caller.service and scope not in caller.scopes:
            log.info('service_refused', extra={'path': request.url.path, 'client_id': caller.client_id, 'scope': scope})
            raise HTTPException(403, SCOPE_REFUSED_DETAIL)
        return caller

    return require_person_or_scope
