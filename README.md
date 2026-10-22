# AgentGuard

AgentGuard evaluates an AI agent's claim about an action against independent
evidence of the outcome.

## Verdicts

- `VERIFIED`: trusted independent evidence agrees with the claimed state.
- `FAILED`: trusted independent evidence contradicts the claimed state.
- `INCONCLUSIVE`: evidence is missing, untrusted, unrelated, or conflicting.

## Run the tests

From the project root:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Run the demo

```bash
PYTHONPATH=src python3 -m agentguard.cli examples/demo.json
```

The example intentionally claims that a booking was confirmed while the
independent record says it failed. The expected verdict is `FAILED`, so the
demo command exits with status 1.

## Important trust boundary

This MVP is a deterministic verification engine, not yet a production security
boundary. The `trusted` and `independent` fields must be populated by
authenticated integrations that AgentGuard controls. An agent must not be
allowed to certify its own evidence. Real connectors, identity verification,
tamper-resistant audit logs, and deployment hardening remain future work.
