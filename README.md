# AgentGuard

AgentGuard is a small Python security MVP for checking an AI agent's claim
against independently collected evidence. It demonstrates a practical rule:
an agent's report is not proof that an operation happened.

The project has no runtime dependencies and targets Python 3.11 or newer.
It includes deterministic claim verification, HMAC-signed evidence with
freshness checks, durable replay protection for one-time workflows, and a
macOS-only authenticated local connector service.

## Quick start

```bash
git clone <your-fork-url>
cd AgentGuard
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
```

For development without installing the package, prefix commands with
`PYTHONPATH=src`.

## Safe end-to-end demo

This demo creates a temporary SQLite booking record, has a simulated agent
claim success, and independently finds that the booking failed. It uses no
Keychain item, network service, or production secret.

```bash
PYTHONPATH=src python3 examples/sqlite_demo.py
```

The resulting verdict is `FAILED`. That is the expected success case for the
demo: AgentGuard caught an unsupported claim. The JSON scenario demo is also
available:

```bash
PYTHONPATH=src python3 -m agentguard.cli examples/demo.json
```

It deliberately exits with status `1`, because the scenario's verdict is
`FAILED`.

## Architecture

```text
agent claim ────────────────┐
                            v
                     verify_claim / verify_signed_claim
independent connector ─> signed evidence ─> freshness + HMAC checks
                                              │
one-time protected operation ─> verify_and_consume_claim
                                              │
                                      SQLite replay store
```

- `core.py` compares a claim with typed evidence and returns `VERIFIED`,
  `FAILED`, or `INCONCLUSIVE`.
- `evidence_signing.py` signs canonical JSON evidence with HMAC-SHA-256,
  checks timestamps, and issues a signed UUID4 `evidence_id`.
- `replay_store.py` atomically records consumed evidence IDs in SQLite. A
  duplicate one-time use raises `ReplayDetectedError`; consumed IDs are not
  pruned by this MVP.
- `trusted_connector.py` reads a controlled SQLite booking source and signs
  only trusted server-side allowlisted actions.
- `connector_service.py` exposes that connector over a local Unix-domain
  socket on macOS, with peer-credential authorization.

Missing, unavailable, or corrupt SQLite evidence is treated as absent and
therefore yields `INCONCLUSIVE`; it never produces a false `VERIFIED` verdict.

## Security model

### Signed evidence and replay protection

New evidence includes a cryptographically random UUID4 `evidence_id` inside
the HMAC-signed payload. `verify_signed_claim()` is intentionally read-only
and may be called repeatedly. For a one-time protected operation, call
`verify_and_consume_claim()` with:

- a valid, fresh signed envelope;
- an `expected_action_id` obtained from the trusted protected-operation
  context, never from an untrusted agent request; and
- a `SQLiteReplayStore` shared by the protected operation.

The store uses a SQLite primary-key constraint and `BEGIN IMMEDIATE` so
concurrent consumers have one winner. Invalid, expired, malformed, or
action-mismatched evidence is not recorded as consumed.

An HMAC proves integrity relative to the protected signing key. It does
**not** prove that the underlying database record or any external event is
true. The evidence source, connector process, and key custody remain part of
the trust boundary.

### Local connector service (macOS)

`agentguard-connector` (or `python3 -m agentguard.connector_service`) runs a
Unix-domain socket service. Its database path, Keychain service/account,
allowlist, approved UID/GID, and five-second request timeout are trusted
server-startup configuration. A wire client can send only one JSON object with
an `action_id`; it cannot choose a database, signing key, allowlist, or other
privileged configuration.

On macOS, the service obtains `LOCAL_PEERCRED` before reading the request and
requires the configured UID and GID. It fails closed when peer credentials
cannot be safely retrieved. The socket directory must be service-owned mode
`0700`; the socket is mode `0600`. Request size is capped at 1024 bytes,
strict schema validation is applied, and an idle client is disconnected after
the request timeout. Stale paths are removed only when they are sockets owned
by the service user.

The service is deliberately unavailable rather than insecure on platforms
without macOS `LOCAL_PEERCRED` support. It is a local service, not a network
protocol.

### Keychain handling

Signing keys are loaded from macOS Keychain by the service after successful
peer authentication and request validation. Key material is never printed by
AgentGuard, and Keychain-tool failure details are not copied into exceptions
or service responses. Use a dedicated non-production Keychain item for local
development; never put a signing key in a shell command, source file, JSON
request, or environment variable.

## Limitations and non-goals

- A malicious process running as the same macOS UID as an approved client is
  **not** isolated by filesystem permissions or UID/GID peer credentials. Use
  dedicated identities or code-signing identity verification for that threat
  model.
- AgentGuard does not authenticate remote callers, verify user intent, or
  make a compromised evidence source truthful.
- SQLite replay entries are retained indefinitely in this MVP. A future
  retention policy must be proven safe with respect to evidence freshness and
  clock-skew bounds before pruning is enabled.
- The included SQLite connector is a demonstration source. Production
  deployments need an independently authorized evidence connector and
  deployment-specific operational controls.

## Development and test commands

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
git diff --check
```

The Unix-socket tests use injectable peer credentials and Keychain loaders, so
they never read a real Keychain item. If an execution sandbox forbids pathname
`AF_UNIX` binding, the two pathname-socket integration tests skip. On a normal
macOS Terminal, run the same test command above to exercise them.
