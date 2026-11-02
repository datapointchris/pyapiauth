# pyapiauth — Claude Code instructions

A public Python library, not a server. There is no entry point; it ships to
PyPI and is imported by Python web APIs whose users log in through an OIDC
provider. pyclilogin is the command-line client those users log in with.

Its users are strangers, who know it only through what it ships. Treat the
public API, the README and the docstrings as the product. A change that suits
one known consumer is not right for that reason alone.

It is the Python sibling of goapiauth and keeps its contract: the checks and
their order, the client prefixes, held keys that outlive an outage, and an
opaque refusal. A behavior changed here is checked against goapiauth first.

## Layout

| Path | Holds |
| --- | --- |
| `errors.py` | `AuthError`, `Rejected` and `IssuerUnreachable` |
| `verifier.py` | `Verifier`, `LazyVerifier`, `HeldKeys`, `Caller`, discovery and the client prefixes |
| `fastapi_dependencies.py` | The FastAPI dependencies. The only module importing FastAPI |

## Constraints that must not regress

- **The type check runs first.** An id_token from the same issuer is signed by
  the same key and would pass every later check.
  `test_an_expired_id_token_is_rejected_as_the_wrong_type` holds the order.
- **The client id decides person or service, never the presence of `sub`.**
- **An empty service prefix refuses every service token.** Every string has
  the empty prefix, so an unguarded check reads every client as a service.
  `test_an_api_naming_no_service_prefix_refuses_every_service_token` fails
  without the guard.
- **Held keys verify through an outage.** A failed re-read never discards
  them. `TestTheHeldKeys` holds that and the one-read-per-gap bound under
  forged tokens.
- **A refusal is opaque to the caller and specific in the log.** The
  dependencies answer one sentence per status, and log the check that failed.
- **An unreachable issuer is a 503, never a 401.** A login cannot fix a network
  fault.
- **FastAPI stays confined to `fastapi_dependencies.py`,** installed through
  the `fastapi` extra, so an API on another framework never installs it.
- **The floor is Python 3.11.** CI tests it.

## Where it differs from goapiauth

goapiauth's refusal body is `{"error", "message", "code"}`, and its clients
branch on the code. FastAPI answers an `HTTPException` as `{"detail": ...}`,
and the Python clients of these APIs read `detail`, so the dependencies keep
FastAPI's shape. goapiauth answers a stale held key's token without waiting on
the re-read. `HeldKeys` re-reads first, holding a lock, and falls back to the
held keys where the read fails.
