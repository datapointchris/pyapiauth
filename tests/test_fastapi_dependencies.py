"""What each dependency answers: the caller on the request, or a 401, 403 or 503 with one opaque sentence."""

from __future__ import annotations

import pytest
from fastapi import Depends
from fastapi import FastAPI
from fastapi import Request
from fastapi.testclient import TestClient

from pyapiauth import Caller
from pyapiauth import IssuerUnreachable
from pyapiauth import Rejected
from pyapiauth.fastapi_dependencies import caller_dependency
from pyapiauth.fastapi_dependencies import person_dependency
from pyapiauth.fastapi_dependencies import person_or_scoped_service_dependency

PERSON = Caller(subject='a-user', client_id='acme-cli-laptop', name='chris')
SERVICE = Caller(subject='', client_id='acme-svc-scheduler', scopes=frozenset({'acme.read'}), service=True)


class NamedTokens:
    """Each token string names its outcome."""

    def verify(self, token):
        match token:
            case 'person':
                return PERSON
            case 'service':
                return SERVICE
            case 'down':
                raise IssuerUnreachable('connection refused')
        raise Rejected('signature: forged')


@pytest.fixture
def client():
    verifier = NamedTokens()
    app = FastAPI()

    @app.get('/any', dependencies=[Depends(caller_dependency(verifier))])
    def any_caller(request: Request):
        return {'who': request.state.caller.who}

    @app.get('/person', dependencies=[Depends(person_dependency(verifier))])
    def person_only():
        return {}

    @app.get('/read', dependencies=[Depends(person_or_scoped_service_dependency(verifier, 'acme.read'))])
    def readable():
        return {}

    @app.get('/write', dependencies=[Depends(person_or_scoped_service_dependency(verifier, 'acme.write'))])
    def writable():
        return {}

    return TestClient(app)


def bearer(token):
    return {'Authorization': f'Bearer {token}'}


def test_an_admitted_caller_is_on_the_request(client):
    assert client.get('/any', headers=bearer('person')).json() == {'who': 'chris'}


@pytest.mark.parametrize(('headers', 'challenge'), [({}, 'Bearer'), (bearer('forged'), 'Bearer error="invalid_token"')])
def test_a_missing_or_rejected_token_is_one_opaque_401_with_a_challenge(client, headers, challenge):
    response = client.get('/any', headers=headers)
    assert response.status_code == 401
    assert response.json() == {'detail': 'Invalid credentials'}
    assert response.headers['WWW-Authenticate'] == challenge


def test_an_unreachable_issuer_is_503_since_no_login_fixes_it(client):
    assert client.get('/any', headers=bearer('down')).status_code == 503


@pytest.mark.parametrize(
    ('path', 'token', 'status'),
    [
        ('/person', 'person', 200),
        ('/person', 'service', 403),
        ('/read', 'service', 200),
        ('/write', 'service', 403),
        ('/write', 'person', 200),
    ],
)
def test_a_service_reaches_only_the_routes_its_scopes_list(client, path, token, status):
    assert client.get(path, headers=bearer(token)).status_code == status
