
import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "code"))

from unified_evidence_index import UnifiedEvidenceIndex

DATASET = ROOT / "dataset"


def load_csv(filename):
    with (DATASET / filename).open(
        newline="",
        encoding="utf-8-sig"
    ) as file:
        return list(csv.DictReader(file))


def show(title, data, limit=8):
    print("\n" + "=" * 75)
    print(title)
    print("=" * 75)

    print("COUNT:", len(data))

    for item in data[:limit]:
        print(json.dumps(
            item,
            indent=2,
            ensure_ascii=False,
            default=str
        ))


def main():
    requests = load_csv(
        "sample_deletion_requests.csv"
    )
    identities = load_csv(
        "user_identities.csv"
    )
    activities = load_csv(
        "system_activity.csv"
    )
    evidence_files = load_csv(
        "evidence_files.csv"
    )

    index = UnifiedEvidenceIndex()
    index.build()

    print("TOTAL INDEXED OBSERVATIONS:", len(index.records))

    # 1. Inspect important evidence file metadata.
    important_files = {
        "evidence_54",
        "evidence_56",
        "evidence_57",
        "evidence_94"
    }

    show(
        "IMPORTANT EVIDENCE FILES",
        [
            row for row in evidence_files
            if row["file_id"] in important_files
        ],
        20
    )

    # 2. Inspect normalized records from these files.
    for evidence_id in sorted(important_files):
        records = [
            row for row in index.records
            if row.get("evidence_id") == evidence_id
        ]

        show(
            f"NORMALIZED RECORDS: {evidence_id}",
            records,
            8
        )

        categories = Counter(
            str(row.get("category"))
            for row in records
        )

        print("CATEGORIES:", dict(categories))

    # 3. Inspect known sample resources.
    target_resources = [
        "account_001",
        "account_002",
        "account_004",
        "account_005",
        "account_006",
        "account_7566",
        "audit_record_2016",
        "analytics_9406",
        "analytics_901",
        "search_001"
    ]

    for resource_id in target_resources:
        evidence_matches = [
            row for row in index.records
            if str(row.get("resource_id")) == resource_id
        ]

        activity_matches = [
            row for row in activities
            if row["resource_id"] == resource_id
        ]

        print("\n" + "=" * 75)
        print("RESOURCE:", resource_id)
        print("=" * 75)

        print(
            "EVIDENCE OBSERVATIONS:",
            len(evidence_matches)
        )
        print(
            "ACTIVITY EVENTS:",
            len(activity_matches)
        )

        for row in evidence_matches[:3]:
            print(
                "EVIDENCE:",
                json.dumps(
                    row,
                    ensure_ascii=False,
                    default=str
                )
            )

        for row in activity_matches[:3]:
            print(
                "ACTIVITY:",
                json.dumps(
                    row,
                    ensure_ascii=False
                )
            )

    # 4. Inspect identity mappings for first six cases.
    by_email = {
        row["email"].lower(): row
        for row in identities
    }

    for request in requests[:6]:
        print("\n" + "=" * 75)
        print("CASE:", request["case_id"])
        print("=" * 75)

        identity = by_email.get(
            request["email"].lower()
        )

        print(
            "IDENTITY:",
            json.dumps(
                identity,
                ensure_ascii=False
            )
        )

        print(
            "AUDIT AT:",
            request["audit_at"]
        )

    # 5. Inspect the original SQL evidence.
    for item in evidence_files:
        if item["file_id"] != "evidence_54":
            continue

        
        relative_path = Path(item["file_path"])

        candidates = [
            ROOT / relative_path,
            ROOT / "dataset" / relative_path,
        ]

        path = next(
            (candidate for candidate in candidates
             if candidate.is_file()),
            None
        )

        if path is None:
            print(
                "FILE NOT FOUND. CHECKED:",
                *candidates,
                sep="\n"
            )
            continue



if __name__ == "__main__":
    main()
