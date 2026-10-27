
import csv
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "dataset"


def load(filename):
    with (DATASET / filename).open(
        encoding="utf-8-sig",
        newline=""
    ) as file:
        return list(csv.DictReader(file))


def display(title, rows, limit=5):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)

    print("COUNT:", len(rows))

    for row in rows[:limit]:
        print(json.dumps(
            row,
            indent=2,
            ensure_ascii=False
        ))


def main():
    activities = load("system_activity.csv")
    identities = load("user_identities.csv")
    history = load("user_audit_log.csv")
    requests = load("sample_deletion_requests.csv")
    expected = load("sample_output.csv")

    # Inspect explicit resource-to-user links.
    links = [
        row for row in activities
        if row["event_type"] == "LINK_RESOURCE_IDENTITY"
    ]
    display("RESOURCE IDENTITY LINKS", links, 12)

    # Inspect flow and restore events.
    for operation in (
        "CHECK_DATA_FLOW",
        "DISABLE_DATA_FLOW",
        "CHECK_RESTORE_ACCESS",
        "BLOCK_RESTORE",
        "RESTORE_BACKUP"
    ):
        selected = [
            row for row in activities
            if row["event_type"] == operation
        ]
        display(operation, selected, 3)

    # Inspect the expected steps for the first cases.
    for row in expected[:6]:
        print("\n" + "=" * 70)
        print("EXPECTED:", row["case_id"])
        print("=" * 70)

        print("STATUS:", row["deletion_status"])

        steps = json.loads(row["steps_json"])

        for step in steps:
            print(json.dumps(
                step,
                ensure_ascii=False
            ))

    # Identify which resources have activity records.
    activity_resources = {
        row["resource_id"]
        for row in activities
        if row["resource_id"]
    }

    expected_resources = set()

    for row in expected:
        for step in json.loads(row["steps_json"]):
            resource_id = step.get("resource_id")
            if resource_id:
                expected_resources.add(resource_id)

    overlapping = (
        activity_resources & expected_resources
    )

    print("\n" + "=" * 70)
    print("RESOURCE COVERAGE")
    print("=" * 70)

    print(
        "Unique activity resources:",
        len(activity_resources)
    )
    print(
        "Unique expected sample resources:",
        len(expected_resources)
    )
    print(
        "Expected resources found in activity:",
        len(overlapping)
    )

    # Inspect historical identifiers for sample users.
    email_to_user = {
        row["email"].lower(): row["user_id"]
        for row in identities
    }

    sample_users = {
        email_to_user.get(
            request["email"].lower()
        )
        for request in requests
    }

    sample_users.discard(None)

    sample_history = [
        row for row in history
        if row["user_id"] in sample_users
    ]

    display(
        "SAMPLE USER IDENTITY HISTORY",
        sample_history,
        10
    )

    print("\nRESOURCE LINK DIAGNOSTIC COMPLETE")


if __name__ == "__main__":
    main()
