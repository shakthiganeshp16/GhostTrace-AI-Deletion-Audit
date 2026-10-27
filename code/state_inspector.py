
from pathlib import Path
import json
import pandas as pd

DATASET = Path("dataset")

activities = pd.read_csv(
    DATASET / "system_activity.csv",
    dtype=str,
    keep_default_na=False
)

manifest = pd.read_csv(
    DATASET / "evidence_files.csv",
    dtype=str,
    keep_default_na=False
)

resources = [
    "export_1260",
    "export_1842",
    "backup_9287",
    "search_4882"
]

print("=" * 65)
print("RESOURCE ACTIVITY HISTORY")
print("=" * 65)

for resource_id in resources:
    matches = activities[
        (activities["resource_id"] == resource_id)
        | (
            activities["details"].str.contains(
                resource_id,
                regex=False,
                na=False
            )
        )
    ].copy()

    matches = matches.sort_values(
        ["event_time", "activity_id"]
    )

    print("\nRESOURCE:", resource_id)
    print("RELATED EVENTS:", len(matches))

    for _, row in matches.iterrows():
        print(
            row["activity_id"],
            "|",
            row["event_time"],
            "|",
            row["event_type"],
            "|",
            row["reported_result"]
        )
        print("Details:", row["details"][:300])

print("\n" + "=" * 65)
print("EVIDENCE 83 — STRUCTURE")
print("=" * 65)

record = manifest[
    manifest["file_id"] == "evidence_83"
]

if not record.empty:
    path = DATASET / record.iloc[0]["file_path"]

    print("Path:", path)
    print("Captured:", record.iloc[0]["captured_at"])

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:
        data = json.load(file)

    print("Root type:", type(data).__name__)

    if isinstance(data, dict):
        print("Top-level keys:", list(data.keys()))

        for key, value in data.items():
            print(
                "Field:",
                key,
                "| Type:",
                type(value).__name__
            )

            if isinstance(value, list):
                print("  Number of items:", len(value))

                if value and isinstance(value[0], dict):
                    print(
                        "  First item keys:",
                        list(value[0].keys())
                    )

    elif isinstance(data, list):
        print("Number of items:", len(data))

        if data and isinstance(data[0], dict):
            print(
                "First item keys:",
                list(data[0].keys())
            )

    print("\nRESOURCE REFERENCES IN EVIDENCE 83")

    text = json.dumps(
        data,
        ensure_ascii=False
    )

    for resource_id in resources[:2]:
        print(
            resource_id,
            "| Present:",
            resource_id in text
        )

print("\nSTATE INSPECTION COMPLETE")
