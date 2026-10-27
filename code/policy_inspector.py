
import json
from pathlib import Path

import pandas as pd


DATASET = Path("dataset")


def main():

    print("=" * 65)
    print("GHOSTTRACE - POLICY AND OUTPUT INSPECTOR")
    print("=" * 65)

    # Read deletion rules.
    rules = pd.read_csv(
        DATASET / "deletion_rules.csv",
        dtype=str,
        keep_default_na=False
    )

    print("\nTOTAL DELETION RULES:", len(rules))
    print("RULE COLUMNS:", list(rules.columns))

    print("\n" + "=" * 65)
    print("ALL DELETION RULES")
    print("=" * 65)

    for _, rule in rules.iterrows():
        print("\nRULE:", rule.get("rule_id", ""))

        print(
            "Category:",
            rule.get("data_category", "")
        )

        print(
            "Condition:",
            rule.get("condition", "")
        )

        print(
            "Required action:",
            rule.get("required_action", "")
        )

    # Inspect the sample output contract.
    sample_path = DATASET / "sample_output.csv"

    if not sample_path.exists():
        sample_path = Path("sample_output.csv")

    if not sample_path.exists():
        print("\nSample output file not found.")
        return

    sample = pd.read_csv(
        sample_path,
        dtype=str,
        keep_default_na=False
    )

    print("\n" + "=" * 65)
    print("SAMPLE OUTPUT")
    print("=" * 65)

    print("Rows:", len(sample))
    print("Columns:", list(sample.columns))

    if "deletion_status" in sample.columns:
        print("\nSTATUS COUNTS:")

        print(
            sample["deletion_status"]
            .value_counts()
            .to_string()
        )

    if "steps_json" in sample.columns:

        print("\nSTEP STRUCTURE EXAMPLES:")

        examples_shown = 0

        for _, row in sample.iterrows():

            try:
                steps = json.loads(row["steps_json"])
            except json.JSONDecodeError:
                print(
                    "Invalid JSON in case:",
                    row["case_id"]
                )
                continue

            if not steps:
                continue

            print("\nCASE:", row["case_id"])
            print("STATUS:", row["deletion_status"])
            print("NUMBER OF STEPS:", len(steps))

            print(
                "FIRST STEP:",
                json.dumps(
                    steps[0],
                    indent=2
                )
            )

            examples_shown += 1

            if examples_shown == 3:
                break

    print("\nPOLICY INSPECTION COMPLETE")


if __name__ == "__main__":
    main()
