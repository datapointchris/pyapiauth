"""Verifying the RFC 9068 access tokens an OIDC provider issues to a product's CLIs and service clients.

A CLI logs in with the device authorization grant and sends its access token as
a bearer. A service logs in with the client-credentials grant and does the same.
The token is a signed JWT, so the API verifies it against the issuer's published
keys and asks nothing of the edge. The checks run in this order:

1. the header's `typ` is `at+jwt`
2. the signature verifies against a key from the issuer's JWKS
3. `iss` is the issuer this API trusts
4. `client_id` carries one of this product's two prefixes
5. `exp` is in the future
6. a person's token, `<product>-cli-*`, carries a `sub`; a service's token,
   `<product>-svc-*`, carries a non-empty `scp`

The prefix decides which kind a token is, never the absence of `sub`. A provider
can omit `sub` from a client-credentials token, and a release can put it back.
The audience claim is not checked, because some providers leave it empty on a
device grant's token. The prefix is what keeps a token issued to another
product's CLI out.

The type check comes first because an id_token from the same issuer is signed by
the same key. Without the check it would pass every later step, and an id_token
is handed to the client where an access token is not.

## The keys outlive an outage of the issuer

`HeldKeys` reads the key set once and holds it. A token whose `kid` no held key
carries makes it read again, which finds a key the provider has just rotated in.
Those reads are at least `KEY_REREAD_GAP_SECONDS` apart, so a stream of forged
tokens costs the provider one read per gap. Keys older than
`KEY_SET_LIFESPAN_SECONDS` are read again too, which bounds how long a key the
provider stopped publishing still verifies. A read that fails keeps the held
keys, because a provider that cannot be read has not rotated its keys out.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

import httpx2
import jwt

from .errors import IssuerUnreachable
from .errors import Rejected

ACCESS_TOKEN_TYPE = 'at+jwt'
SIGNING_ALGORITHMS = ['RS256']
DISCOVERY_PATH = '/.well-known/openid-configuration'
DISCOVERY_TIMEOUT_SECONDS = 10.0
KEY_READ_TIMEOUT_SECONDS = 10
KEY_SET_LIFESPAN_SECONDS = 300.0
KEY_REREAD_GAP_SECONDS = 30.0

# A CDN in front of an issuer can refuse a client that names none. urllib's
# default agent, which PyJWKClient sends unless told otherwise, is one such.
USER_AGENT = 'pyapiauth (+https://github.com/datapointchris/pyapiauth)'


def person_prefix(product):
    """The client id prefix of every person's CLI for `product`: `acme-cli-`."""
    return f'{product}-cli-'


def service_prefix(product):
    """The client id prefix of every service client for `product`: `acme-svc-`."""
    return f'{product}-svc-'


@dataclass(frozen=True)
class Caller:
    """What a verified token establishes about who is asking.

    `subject` is empty for a service principal, which acts as no user. A
    provider's subject can be an opaque id, so `name` carries the token's
    `preferred_username` where the provider copies it into the access token.
    """

    subject: str
    client_id: str
    scopes: frozenset[str] = frozenset()
    service: bool = False
    name: str = ''

    @property
    def who(self):
        """The caller as a record shows it: the username, else the subject, else the service client."""
        return self.name or self.subject or self.client_id


def bearer_token(authorization):
    """The credential in an Authorization header, or '' where there is no bearer."""
    scheme, _, credential = authorization.partition(' ')
    if scheme.lower() != 'bearer':
        return ''
    return credential.strip()


def discover_jwks_uri(issuer, client=None, user_agent=USER_AGENT):
    """The issuer's JWKS endpoint, from its discovery document.

    The document must name the issuer it was asked about. One that names another
    is a misrouted request or a misconfigured proxy, and its keys would verify
    tokens this API was never told to trust.
    """
    client = client or httpx2.Client(timeout=DISCOVERY_TIMEOUT_SECONDS)
    try:
        response = client.get(issuer.rstrip('/') + DISCOVERY_PATH, headers={'User-Agent': user_agent}, timeout=DISCOVERY_TIMEOUT_SECONDS)
        response.raise_for_status()
        document = response.json()
    except (httpx2.HTTPError, ValueError) as error:
        raise IssuerUnreachable(f'discovery at {issuer} failed: {error}') from error
    if document.get('issuer') != issuer:
        raise IssuerUnreachable(f'{issuer} advertises itself as {document.get("issuer")!r}')
    jwks_uri = document.get('jwks_uri')
    if not jwks_uri:
        raise IssuerUnreachable(f'{issuer} advertises no jwks_uri')
    return jwks_uri


class HeldKeys:
    """The issuer's signing keys, read once and held through an outage of the issuer.

    `read_key_set` returns a `jwt.PyJWKSet`, and raises a `jwt.PyJWTError` where
    the issuer cannot be read. `clock` is a parameter so the lifespan and the
    gap can be driven from a test.
    """

    def __init__(self, read_key_set, clock=time.monotonic):
        self.read_key_set = read_key_set
        self.clock = clock
        self.keys = {}
        self.read_at = None
        self.tried_at = None
        self.mutex = threading.Lock()

    @classmethod
    def from_jwks_uri(cls, jwks_uri, user_agent=USER_AGENT):
        reader = jwt.PyJWKClient(
            jwks_uri, cache_jwk_set=False, cache_keys=False, headers={'User-Agent': user_agent}, timeout=KEY_READ_TIMEOUT_SECONDS
        )
        return cls(lambda: reader.get_jwk_set(refresh=True))

    def get_signing_key_from_jwt(self, token):
        """The held key the token's `kid` names, read again first where it is unknown or the keys are old.

        `jwt.PyJWKClientConnectionError` means no key has ever been read.
        """
        kid = jwt.get_unverified_header(token).get('kid')
        with self.mutex:
            if kid not in self.keys or self.clock() - self.read_at >= KEY_SET_LIFESPAN_SECONDS:
                self.read()
            key = self.keys.get(kid)
        if key is None:
            raise jwt.PyJWKClientError(f'the issuer publishes no signing key {kid!r}')
        return key

    def read(self):
        now = self.clock()
        if self.keys and self.tried_at is not None and now - self.tried_at < KEY_REREAD_GAP_SECONDS:
            return
        self.tried_at = now
        try:
            key_set = self.read_key_set()
        except jwt.PyJWTError as error:
            if self.keys:
                return
            raise jwt.PyJWKClientConnectionError(f'the issuer published no usable key: {error}') from error
        self.keys = {key.key_id: key for key in key_set.keys if key.key_id and key.public_key_use in ('sig', None)}
        self.read_at = now


class Verifier:
    """Judges a bearer token against one issuer and this product's two client prefixes.

    `person_prefix` starts every person's CLI client id, such as `acme-cli-`.
    `service_prefix` starts every service client's, such as `acme-svc-`, and
    empty refuses every service token. `keys` answers
    `get_signing_key_from_jwt`, as `HeldKeys` and `jwt.PyJWKClient` both do.
    """

    def __init__(self, issuer, person_prefix, keys, clock=time.time, service_prefix=''):
        check_prefixes(person_prefix, service_prefix)
        self.issuer = issuer
        self.person_prefix = person_prefix
        self.service_prefix = service_prefix
        self.keys = keys
        self.clock = clock

    @classmethod
    def from_discovery(cls, issuer, person_prefix, client=None, service_prefix='', user_agent=USER_AGENT):
        jwks_uri = discover_jwks_uri(issuer, client=client, user_agent=user_agent)
        return cls(issuer, person_prefix, HeldKeys.from_jwks_uri(jwks_uri, user_agent), service_prefix=service_prefix)

    def kind_of(self, client_id):
        """'person' or 'service' by the client's prefix, or '' for a client this API does not know."""
        if not isinstance(client_id, str):
            return ''
        if client_id.startswith(self.person_prefix):
            return 'person'
        if self.service_prefix and client_id.startswith(self.service_prefix):
            return 'service'
        return ''

    def verify(self, token):
        """The caller a token establishes, or `Rejected` naming the check it failed."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as error:
            raise Rejected(f'header unreadable: {error}') from error
        token_type = str(header.get('typ', ''))
        if token_type.lower() != ACCESS_TOKEN_TYPE:
            raise Rejected(f'type {token_type!r} is not {ACCESS_TOKEN_TYPE}')

        try:
            key = self.keys.get_signing_key_from_jwt(token)
        except jwt.PyJWKClientConnectionError as error:
            raise IssuerUnreachable(f'JWKS fetch failed: {error}') from error
        except jwt.PyJWTError as error:
            raise Rejected(f'no signing key: {error}') from error

        # PyJWT's own claim checks are switched off so each runs below in the
        # order above. Its order would report an expired id_token as expired
        # rather than as the wrong kind of token.
        try:
            claims = jwt.decode(
                token,
                key.key,
                algorithms=SIGNING_ALGORITHMS,
                options={'verify_exp': False, 'verify_iss': False, 'verify_aud': False, 'verify_iat': False, 'verify_nbf': False},
            )
        except jwt.PyJWTError as error:
            raise Rejected(f'signature: {error}') from error

        if claims.get('iss') != self.issuer:
            raise Rejected(f'issuer {claims.get("iss")!r} is not {self.issuer!r}')
        client_id = claims.get('client_id')
        kind = self.kind_of(client_id)
        if not kind:
            known = ' or '.join(f'{prefix}*' for prefix in (self.person_prefix, self.service_prefix) if prefix)
            raise Rejected(f'client {client_id!r} is not a {known} client')
        expires = claims.get('exp')
        if not isinstance(expires, int | float) or expires <= self.clock():
            raise Rejected(f'expired or no expiry: exp={expires!r}')
        granted = claims.get('scp')
        scopes = frozenset(scope for scope in granted if isinstance(scope, str)) if isinstance(granted, list) else frozenset()
        if kind == 'service':
            if not scopes:
                raise Rejected(f'service client {client_id} holds no scope')
            return Caller(subject='', client_id=client_id, scopes=scopes, service=True)
        subject = claims.get('sub')
        if not isinstance(subject, str) or not subject:
            raise Rejected('no subject')
        name = claims.get('preferred_username')
        return Caller(subject=subject, client_id=client_id, scopes=scopes, name=name if isinstance(name, str) else '')


def check_prefixes(person, service):
    """Refuse a prefix `person_prefix` or `service_prefix` could not have built, or two that overlap.

    A bare product name would admit every client id it starts: `acme` admits
    `acmecorp-cli-desk`.
    """
    if not person.endswith('-cli-') or person == '-cli-':
        raise ValueError(f'person prefix {person!r} is not person_prefix(product) for any product')
    if service and (not service.endswith('-svc-') or service == '-svc-'):
        raise ValueError(f'service prefix {service!r} is not service_prefix(product) for any product')
    if service and (person.startswith(service) or service.startswith(person)):
        raise ValueError(f'client prefixes {person!r} and {service!r} overlap')


class LazyVerifier:
    """A `Verifier` built on first use, and rebuilt after a failed build. goapiauth's `Connecting`.

    Discovery needs the issuer up. Building at startup would make an issuer
    outage stop the API from starting, and its health route would go with it. A
    failed build is not remembered, so the request after the issuer returns
    succeeds.
    """

    def __init__(self, issuer, person_prefix, build=Verifier.from_discovery, service_prefix='', user_agent=USER_AGENT):
        check_prefixes(person_prefix, service_prefix)
        self.issuer = issuer
        self.person_prefix = person_prefix
        self.service_prefix = service_prefix
        self.user_agent = user_agent
        self.build = build
        self.verifier = None

    def verify(self, token):
        if self.verifier is None:
            self.verifier = self.build(self.issuer, self.person_prefix, service_prefix=self.service_prefix, user_agent=self.user_agent)
        return self.verifier.verify(token)
