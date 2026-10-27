
from pathlib import Path
import pandas as pd


def main():

    print("=" * 65)
    print("GHOSTTRACE - ACTIVITY SCHEMA INSPECTOR")
    print("=" * 65)

    activities = pd.read_csv(
        Path("dataset") / "system_activity.csv",
        dtype=str,
        keep_default_na=False
    )

    print("\nTOTAL ACTIVITIES:", len(activities))

    print("\n" + "=" * 65)
    print("EVENT TYPES AND COUNTS")
    print("=" * 65)

    counts = (
        activities["event_type"]
        .value_counts()
        .sort_index()
    )

    for event_type, count in counts.items():
        print(f"{event_type}: {count}")

    print("\n" + "=" * 65)
    print("EVENT TYPES BY REPORTED RESULT")
    print("=" * 65)

    summary = pd.crosstab(
        activities["event_type"],
        activities["reported_result"]
    )

    print(summary.to_string())

    print("\n" + "=" * 65)
    print("EXAMPLE EVENTS")
    print("=" * 65)

    for event_type, group in activities.groupby("event_type"):

        row = group.iloc[0]

        print("\nEVENT TYPE:", event_type)
        print("Activity:", row["activity_id"])
        print("Source:", row["source_system"])
        print("Target:", row["target_system"])
        print("Resource:", row["resource_id"])
        print("Result:", row["reported_result"])

        details = row["details"]

        print(
            "Details:",
            details[:300] if details else "(empty)"
        )

    print("\n" + "=" * 65)
    print("EVIDENCE FILE FORMATS")
    print("=" * 65)

    evidence = pd.read_csv(
        Path("dataset") / "evidence_files.csv",
        dtype=str,
        keep_default_na=False
    )

    evidence["extension"] = (
        evidence["file_path"]
        .map(lambda path: Path(path).suffix.lower())
    )

    for extension, count in (
        evidence["extension"]
        .value_counts()
        .sort_index()
        .items()
    ):
        print(extension or "(none)", ":", count)

    print("\nACTIVITY SCHEMA INSPECTION COMPLETE")


if __name__ == "__main__":
    main()
