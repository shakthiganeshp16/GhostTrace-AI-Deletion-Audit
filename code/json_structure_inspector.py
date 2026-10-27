
from pathlib import Path
import json
import pandas as pd

DATASET = Path("dataset")

manifest = pd.read_csv(
    DATASET / "evidence_files.csv",
    dtype=str,
    keep_default_na=False
)

record = manifest[
    manifest["file_id"] == "evidence_83"
].iloc[0]

path = DATASET / record["file_path"]

with path.open("r", encoding="utf-8") as file:
    data = json.load(file)

print("=" * 60)
print("EVIDENCE 83 — SERVICE EXPORT STRUCTURE")
print("=" * 60)

exports = data.get("service_exports", {})

print("Service exports type:", type(exports).__name__)

if isinstance(exports, dict):
    print("Number of top-level entries:", len(exports))
    print("Top-level keys:", list(exports.keys()))

    for key, value in exports.items():
        print("\nSERVICE:", key)
        print("Value type:", type(value).__name__)

        if isinstance(value, dict):
            print("Fields:", list(value.keys()))

            for field, field_value in value.items():
                print(
                    " ",
                    field,
                    "| Type:",
                    type(field_value).__name__
                )

                if isinstance(field_value, list):
                    print(
                        "   Number of records:",
                        len(field_value)
                    )

                    if field_value:
                        first = field_value[0]

                        if isinstance(first, dict):
                            print(
                                "   Record fields:",
                                list(first.keys())
                            )

        elif isinstance(value, list):
            print("Number of records:", len(value))

            if value and isinstance(value[0], dict):
                print(
                    "Record fields:",
                    list(value[0].keys())
                )

print("\nJSON STRUCTURE INSPECTION COMPLETE")
