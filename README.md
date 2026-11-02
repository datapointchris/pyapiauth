# pyapiauth

Verify an OIDC provider's RFC 9068 access tokens inside a Python web API. A CLI
logs in with the device grant, a service with the client-credentials grant, and
each sends the provider's access token as a bearer. pyapiauth checks it against
the issuer's published keys and says who is asking: a person, or a service
client limited to its scopes.

It is the Python sibling of
[goapiauth](https://github.com/datapointchris/goapiauth). Its client-side
counterpart is [pyclilogin](https://github.com/datapointchris/pyclilogin),
which obtains the tokens this package verifies.

## Install

```bash
uv add pyapiauth              # the verifier
uv add "pyapiauth[fastapi]"   # plus the FastAPI dependencies
```

## Starting from scratch

An API for a product called `acme` trusts one issuer and two client prefixes:
`acme-cli-` for each person's machine, and `acme-svc-` for each service.

```python
from fastapi import APIRouter, Depends
from pyapiauth import LazyVerifier, person_prefix, service_prefix
from pyapiauth.fastapi_dependencies import person_dependency, person_or_scoped_service_dependency

verifier = LazyVerifier('https://auth.example.com', person_prefix('acme'), service_prefix=service_prefix('acme'))

people = APIRouter(dependencies=[Depends(person_dependency(verifier))])
readers = APIRouter(dependencies=[Depends(person_or_scoped_service_dependency(verifier, 'acme.read'))])
```

Each dependency puts the verified `Caller` on `request.state.caller`. Without
FastAPI, `verifier.verify(token)` returns the `Caller` or raises.

`LazyVerifier` reads the issuer's discovery document on the first request,
rather than at startup. An issuer that is down then cannot stop the API from
starting, and a failed read is tried again on the next request.

## A token passes six checks, in this order

1. The header's `typ` is `at+jwt`.
2. The signature verifies against a key from the issuer's JWKS.
3. `iss` is the issuer the API trusts.
4. `client_id` starts with the person prefix or the service prefix.
5. `exp` is in the future.
6. A person's token carries a `sub`. A service's token carries a non-empty
   `scp`.

The type check comes first because an id_token from the same issuer is signed
by the same key, and would otherwise pass every later step. The prefix decides
whether a token is a person's or a service's, never the absence of `sub`. The
audience claim is not checked, because some providers leave it empty on a
device grant's token. The client prefix keeps another product's tokens out.

A prefix no product name builds is refused when the verifier is built. A bare
`acme` would admit `acmecorp-cli-desk`. An empty service prefix refuses every
service token.

## A refusal tells the caller nothing, and an outage is not a refusal

| Outcome | Exception | FastAPI answer |
| --- | --- | --- |
| No bearer, or one that fails a check | `Rejected` | 401 `Invalid credentials`, with a `WWW-Authenticate` challenge |
| The issuer cannot be read | `IssuerUnreachable` | 503 `Identity provider unavailable` |
| A service on a route no scope of its admits | — | 403 |

A caller probing with forged tokens learns nothing about which check failed.
The reason goes to the `pyapiauth.fastapi_dependencies` logger, as
`bearer_rejected` at WARNING, `issuer_unreachable` at ERROR, and
`bearer_missing` and `service_refused` at INFO. A 503 never sends anyone to log
in again, because a login cannot fix a network fault.

## The keys outlive an outage of the issuer

`HeldKeys` reads the key set once and holds it. A token naming a `kid` no held
key carries reads it again, which finds a key the provider has just rotated in.
Those reads are at least 30 seconds apart, so a stream of forged tokens costs
the provider one read per gap. Keys older than five minutes are read again too,
which bounds how long a key the provider stopped publishing still verifies. A
read that fails keeps the held keys, so an outage of the issuer is not an
outage of the API.

## What it deliberately does not do

It does not issue, refresh or store tokens; pyclilogin does that on the client.
It verifies RS256 alone, and does not introspect opaque tokens.
