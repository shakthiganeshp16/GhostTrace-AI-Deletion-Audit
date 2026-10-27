
import csv
import json
from pathlib import Path


DATASET = Path("dataset")


def inspect_manifest():

    print("\n=== EVIDENCE MANIFEST ===")

    path = DATASET / "evidence_files.csv"

    with path.open(
        encoding="utf-8-sig",
        newline=""
    ) as file:

        rows = list(csv.DictReader(file))

    for evidence_id in [
        "evidence_03",
        "evidence_54",
        "evidence_94"
    ]:

        matches = [
            row for row in rows
            if evidence_id in row.values()
        ]

        print("\n", evidence_id)

        for row in matches:
            print(json.dumps(row, indent=2))


def inspect_account_resources():

    print("\n=== ACCOUNT RESOURCE EVIDENCE ===")

    from unified_evidence_index import UnifiedEvidenceIndex

    index = UnifiedEvidenceIndex()
    index.build()

    for resource_id in [
        "account_001",
        "account_002",
        "account_7566"
    ]:

        print("\nRESOURCE:", resource_id)

        matches = index.find_resource(
            resource_id,
            "2026-10-02T00:00:00Z"
        )

        print("MATCHES:", len(matches))

        for record in matches[:8]:

            print(
                json.dumps(
                    record,
                    indent=2,
                    default=str
                )[:1600]
            )


def inspect_sample_answers():

    print("\n=== SAMPLE EXPECTED ANSWERS ===")

    path = DATASET / "sample_output.csv"

    with path.open(
        encoding="utf-8-sig",
        newline=""
    ) as file:

        rows = list(csv.DictReader(file))

    for row in rows[:3]:

        print("\nCASE:", row["case_id"])
        print("STATUS:", row["deletion_status"])

        steps = json.loads(row["steps_json"])

        for step in steps:
            print(
                step["phase"],
                "|",
                step["operation"],
                "|",
                step["resource_id"],
                "|",
                step["evidence_id"]
            )


if __name__ == "__main__":

    inspect_manifest()
    inspect_account_resources()
    inspect_sample_answers()

    print("\nLESSON 29 DIAGNOSTIC COMPLETE")
