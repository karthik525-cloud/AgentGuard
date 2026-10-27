"""Run core AgentGuard success and adversarial security scenarios."""

import json
import tempfile
from copy import deepcopy
from pathlib import Path

from agentguard import (
    ReplayDetectedError,
    SQLiteReplayStore,
    sign_evidence,
    verify_and_consume_claim,
    verify_signed_claim,
)


def main() -> None:
    key = b"agentguard-demo-signing-key-at-least-32-bytes"
    claim = {"action_id": "booking-security-demo", "claimed_state": "confirmed"}
    evidence = {
        "action_id": "booking-security-demo",
        "source": "controlled-demo-tool",
        "record_id": "record-security-demo",
        "observed_state": "confirmed",
    }
    envelope = sign_evidence(evidence, key)

    with tempfile.TemporaryDirectory() as directory:
        replay_store = SQLiteReplayStore(Path(directory) / "replay.db")
        verified = verify_signed_claim(claim, [envelope], key)
        consumed = verify_and_consume_claim(
            claim,
            envelope,
            key,
            replay_store,
            expected_action_id="booking-security-demo",
        )
        try:
            verify_and_consume_claim(
                claim,
                envelope,
                key,
                replay_store,
                expected_action_id="booking-security-demo",
            )
        except ReplayDetectedError:
            replay = "rejected"
        else:
            replay = "unexpectedly accepted"

    tampered = deepcopy(envelope)
    tampered["evidence"]["observed_state"] = "failed"
    false_claim = dict(claim, claimed_state="failed")

    print(json.dumps({
        "matching_evidence": verified["verdict"],
        "false_claim": verify_signed_claim(false_claim, [envelope], key)["verdict"],
        "tampered_evidence": verify_signed_claim(claim, [tampered], key)["verdict"],
        "first_one_time_use": consumed["verdict"],
        "replayed_one_time_use": replay,
    }, indent=2))


if __name__ == "__main__":
    main()
