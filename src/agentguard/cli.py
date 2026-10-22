"""Command-line interface for AgentGuard."""

import argparse
import json
import sys
from pathlib import Path

from .core import EvidenceRecord, verify_claim
from .sqlite_source import verify_from_sqlite

REQUIRED_EVIDENCE_FIELDS = (
    "action_id",
    "source",
    "record_id",
    "observed_state",
)


def evidence_records_from_scenario(payload: object) -> tuple[object, list[EvidenceRecord]]:
    """Parse a local JSON scenario into claim data and EvidenceRecord objects.

    JSON scenarios are demo/test input. The trusted/independent flags are
    ignored and are not treated as authentication.
    """
    if not isinstance(payload, dict):
        raise ValueError("Scenario must be a JSON object")
    if "claim" not in payload:
        raise ValueError("Scenario is missing the claim field")
    if "evidence" not in payload:
        raise ValueError("Scenario is missing the evidence field")

    raw_evidence = payload["evidence"]
    if not isinstance(raw_evidence, list):
        raise ValueError("evidence must be a list")

    records: list[EvidenceRecord] = []
    for item in raw_evidence:
        if not isinstance(item, dict):
            raise ValueError("Each evidence item must be a JSON object")

        values: dict[str, str] = {}
        for field in REQUIRED_EVIDENCE_FIELDS:
            value = item.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Evidence is missing required field: {field}"
                )
            values[field] = value

        records.append(
            EvidenceRecord(
                action_id=values["action_id"],
                source=values["source"],
                record_id=values["record_id"],
                observed_state=values["observed_state"],
            )
        )

    return payload["claim"], records


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="agentguard",
        description="Verify AI agent claims against independent evidence.",
    )
    subparsers = parser.add_subparsers(dest="command")

    json_parser = subparsers.add_parser(
        "json", help="Verify a claim from a JSON scenario."
    )
    json_parser.add_argument("scenario", type=Path)

    sqlite_parser = subparsers.add_parser(
        "verify", help="Verify a claim against a SQLite database."
    )
    sqlite_parser.add_argument("--db", required=True, type=Path)
    sqlite_parser.add_argument("--action-id", required=True)
    sqlite_parser.add_argument("--claimed-state", required=True)

    # Support both "agentguard scenario.json" and subcommands.
    if len(sys.argv) == 2 and sys.argv[1] not in ("-h", "--help"):
        args = argparse.Namespace(
            command="json",
            scenario=Path(sys.argv[1]),
        )
    else:
        args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    try:
        if args.command == "json":
            payload = json.loads(args.scenario.read_text(encoding="utf-8"))
            claim, evidence = evidence_records_from_scenario(payload)
            result = verify_claim(claim, evidence)
        else:
            claim = {
                "action_id": args.action_id,
                "claimed_state": args.claimed_state,
            }
            result = verify_from_sqlite(claim, args.db)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        return 2

    print(json.dumps(result, indent=2))
    return 0 if result["verdict"] == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
