"""The bearer verifier, against a real RSA key and real signatures.

The JWKS is served from memory rather than fetched. Everything below the key
lookup — the signature, the claims and their order — runs as in production.
"""

from __future__ import annotations

import json
import time

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from pyapiauth import USER_AGENT
from pyapiauth import Caller
from pyapiauth import HeldKeys
from pyapiauth import IssuerUnreachable
from pyapiauth import LazyVerifier
from pyapiauth import Rejected
from pyapiauth import Verifier
from pyapiauth import bearer_token
from pyapiauth import discover_jwks_uri
from pyapiauth import person_prefix
from pyapiauth import service_prefix

ISSUER = 'https://auth.example.test'
PERSON = person_prefix('acme')
SERVICE = service_prefix('acme')
KEY_ID = 'main'
NOW = 1_800_000_000

SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
STRANGER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def key_set(*kids, key=SIGNING_KEY):
    jwk = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    return jwt.PyJWKSet([{**jwk, 'kid': kid, 'alg': 'RS256', 'use': 'sig'} for kid in kids])


class Issuer:
    """The issuer's JWKS endpoint: the key set it publishes now, or an outage."""

    def __init__(self, *kids):
        self.kids = kids or (KEY_ID,)
        self.down = False
        self.reads = 0

    def __call__(self):
        self.reads += 1
        if self.down:
            raise jwt.PyJWKClientConnectionError('connection refused')
        return key_set(*self.kids)


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def claims(**overrides):
    return {'iss': ISSUER, 'sub': 'a-user', 'client_id': 'acme-cli-laptop', 'iat': NOW - 60, 'exp': NOW + 3600, **overrides}


def token(key=SIGNING_KEY, typ='at+jwt', kid=KEY_ID, **overrides):
    body = {key_: value for key_, value in claims(**overrides).items() if value is not None}
    return jwt.encode(body, key, algorithm='RS256', headers={'typ': typ, 'kid': kid})


def verifier(keys=None):
    return Verifier(ISSUER, PERSON, keys or HeldKeys(Issuer()), clock=lambda: NOW, service_prefix=SERVICE)


class TestAGoodToken:
    def test_it_establishes_the_caller(self):
        assert verifier().verify(token()) == Caller(subject='a-user', client_id='acme-cli-laptop')

    def test_a_persons_scopes_and_name_come_from_the_token(self):
        caller = verifier().verify(token(scp=['openid', 'acme.write'], preferred_username='chris'))
        assert caller.scopes == {'openid', 'acme.write'}
        assert caller.who == 'chris'
        assert not caller.service


class TestAServiceToken:
    """The prefix decides the kind, never the absence of `sub`."""

    def service_token(self, **overrides):
        return token(**{'client_id': 'acme-svc-scheduler', 'sub': None, 'scp': ['acme.read'], **overrides})

    def test_it_is_a_service_principal_with_its_scopes_and_no_subject(self):
        caller = verifier().verify(self.service_token())
        assert caller == Caller(subject='', client_id='acme-svc-scheduler', scopes=frozenset({'acme.read'}), service=True)

    def test_a_subject_does_not_make_it_a_user(self):
        """A provider can omit `sub` from a client-credentials token, and a release can put it back."""
        caller = verifier().verify(self.service_token(sub='a-user'))
        assert caller.service
        assert caller.subject == ''

    @pytest.mark.parametrize('scp', [[], None, 'acme.read'])
    def test_one_holding_no_scope_list_is_rejected(self, scp):
        with pytest.raises(Rejected, match='scope'):
            verifier().verify(self.service_token(scp=scp))

    def test_an_api_naming_no_service_prefix_refuses_every_service_token(self):
        """Every string has the empty prefix, so an unguarded check would read every client as a service."""
        bare = Verifier(ISSUER, PERSON, HeldKeys(Issuer()), clock=lambda: NOW)
        with pytest.raises(Rejected, match='client'):
            bare.verify(self.service_token())


class TestEachCheckRejects:
    @pytest.mark.parametrize(
        ('make', 'reason'),
        [
            (lambda: token(typ='JWT'), 'type'),
            (lambda: token(key=STRANGER_KEY), 'signature'),
            (lambda: token(kid='rotated-away'), 'no signing key'),
            (lambda: token(iss='https://elsewhere.test'), 'issuer'),
            (lambda: token(sub=None), 'subject'),
            (lambda: token(sub=''), 'subject'),
            (lambda: token(client_id='other-cli-laptop'), 'client'),
            (lambda: token(client_id=None), 'client'),
            (lambda: token(client_id=7), 'client'),
            (lambda: token(exp=NOW - 1), 'expired'),
            (lambda: token(exp=None), 'expired'),
            (lambda: 'not-a-jwt', 'header'),
        ],
    )
    def test_a_token_failing_one_check_is_rejected_naming_it(self, make, reason):
        with pytest.raises(Rejected, match=reason):
            verifier().verify(make())

    def test_an_expired_id_token_is_rejected_as_the_wrong_type(self):
        """The type check runs first, so the log names what the token is rather than its age."""
        with pytest.raises(Rejected, match='type'):
            verifier().verify(token(typ='JWT', exp=NOW - 1))

    def test_a_forged_issuer_is_caught_after_the_signature(self):
        """Checked first, the issuer would log a claim nobody signed as the reason."""
        with pytest.raises(Rejected, match='signature'):
            verifier().verify(token(key=STRANGER_KEY, iss='https://elsewhere.test'))


@pytest.mark.parametrize(
    ('person', 'service'),
    [('acme', ''), ('acme-cli-', 'acme'), ('-cli-', ''), ('acme-cli-', 'acme-cli-svc-')],
)
def test_a_prefix_no_product_builds_is_refused(person, service):
    """A bare product name admits every client id it starts: `acme` admits `acmecorp-cli-desk`."""
    with pytest.raises(ValueError, match='prefix'):
        Verifier(ISSUER, person, HeldKeys(Issuer()), service_prefix=service)


class TestTheHeldKeys:
    def test_held_keys_verify_through_an_outage_of_the_issuer(self):
        issuer, clock = Issuer(), Clock()
        checking = verifier(HeldKeys(issuer, clock=clock))
        checking.verify(token())
        issuer.down = True
        clock.now += 3600
        assert checking.verify(token()).subject == 'a-user'
        assert issuer.reads == 2

    def test_forged_kids_cost_one_read_per_gap(self):
        issuer, clock = Issuer(), Clock()
        checking = verifier(HeldKeys(issuer, clock=clock))
        checking.verify(token())
        clock.now += 31
        for kid in ('forged-1', 'forged-2', 'forged-3'):
            with pytest.raises(Rejected, match='no signing key'):
                checking.verify(token(kid=kid))
        assert issuer.reads == 2

    def test_a_key_rotated_in_is_found_and_one_rotated_out_stops_verifying(self):
        issuer, clock = Issuer(), Clock()
        checking = verifier(HeldKeys(issuer, clock=clock))
        checking.verify(token())
        issuer.kids = ('next',)
        clock.now += 31
        assert checking.verify(token(kid='next')).subject == 'a-user'
        with pytest.raises(Rejected, match='no signing key'):
            checking.verify(token())

    def test_an_issuer_never_read_is_unreachable_rather_than_rejected(self):
        issuer = Issuer()
        issuer.down = True
        with pytest.raises(IssuerUnreachable):
            verifier(HeldKeys(issuer)).verify(token())


def test_a_failed_build_is_not_remembered():
    attempts = []

    def build(issuer, prefix, service_prefix='', user_agent=''):
        attempts.append(issuer)
        if len(attempts) == 1:
            raise IssuerUnreachable('down')
        return verifier()

    lazy = LazyVerifier(ISSUER, PERSON, build=build)
    with pytest.raises(IssuerUnreachable):
        lazy.verify(token())
    assert lazy.verify(token()).subject == 'a-user'
    lazy.verify(token())
    assert len(attempts) == 2


def discovery(document, status=200):
    seen = {}

    def handler(request):
        seen['request'] = request
        return httpx2.Response(status, text=json.dumps(document))

    return httpx2.Client(transport=httpx2.MockTransport(handler)), seen


class TestDiscovery:
    def test_the_jwks_uri_comes_from_the_document_and_the_request_names_itself(self):
        """A CDN in front of the issuer can refuse an unidentified client."""
        client, seen = discovery({'issuer': ISSUER, 'jwks_uri': f'{ISSUER}/jwks.json'})
        assert discover_jwks_uri(ISSUER, client=client) == f'{ISSUER}/jwks.json'
        assert seen['request'].url.path == '/.well-known/openid-configuration'
        assert seen['request'].headers['User-Agent'] == USER_AGENT

    def test_a_document_naming_another_issuer_is_refused(self):
        client, _ = discovery({'issuer': 'https://elsewhere.test', 'jwks_uri': 'x'})
        with pytest.raises(IssuerUnreachable, match='advertises itself'):
            discover_jwks_uri(ISSUER, client=client)

    def test_an_error_status_is_unreachable(self):
        client, _ = discovery({}, status=502)
        with pytest.raises(IssuerUnreachable):
            discover_jwks_uri(ISSUER, client=client)


@pytest.mark.parametrize(
    ('header', 'expected'),
    [('Bearer abc', 'abc'), ('bearer abc ', 'abc'), ('Basic abc', ''), ('', ''), ('Bearer', '')],
)
def test_only_a_bearer_credential_is_taken(header, expected):
    assert bearer_token(header) == expected


def test_the_clock_is_real_by_default():
    assert Verifier(ISSUER, PERSON, HeldKeys(Issuer())).clock() == pytest.approx(time.time(), abs=5)
