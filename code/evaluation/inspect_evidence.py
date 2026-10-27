
import csv
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "dataset"


def load_csv(filename):
    path = DATASET / filename

    with path.open(
        newline="",
        encoding="utf-8-sig"
    ) as file:
        return list(csv.DictReader(file))


def show_file(filename, sample_count=3):
    rows = load_csv(filename)

    print("\n" + "=" * 70)
    print(filename)
    print("=" * 70)

    print("TOTAL ROWS:", len(rows))

    if not rows:
        return

    print("COLUMNS:", list(rows[0].keys()))

    for row in rows[:sample_count]:
        print(json.dumps(row, indent=2))


def main():
    for filename in (
        "sample_deletion_requests.csv",
        "user_identities.csv",
        "user_audit_log.csv",
        "system_activity.csv",
        "evidence_files.csv",
        "deletion_rules.csv",
    ):
        show_file(filename, sample_count=2)

    requests = load_csv(
        "sample_deletion_requests.csv"
    )

    print("\n" + "=" * 70)
    print("SAMPLE REQUESTS 01-04")
    print("=" * 70)

    for row in requests[:4]:
        print(json.dumps(row, indent=2))

    activities = load_csv("system_activity.csv")

    print("\n" + "=" * 70)
    print("SYSTEM ACTIVITY OPERATIONS")
    print("=" * 70)

    for field in (
        "event_type",
        "operation",
        "action",
        "result",
        "status"
    ):
        if field in activities[0]:
            counts = Counter(
                row.get(field, "")
                for row in activities
            )
            print("\nFIELD:", field)
            for value, count in counts.most_common():
                print(f"{value}: {count}")

    print("\nDIAGNOSTIC COMPLETE")


if __name__ == "__main__":
    main()
