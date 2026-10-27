
from pathlib import Path
import pandas as pd

# Locate the official dataset folder
dataset_path = Path("dataset")

files = [
    "deletion_requests.csv",
    "sample_deletion_requests.csv",
    "sample_output.csv",
    "user_identities.csv",
    "user_audit_log.csv",
    "system_activity.csv",
    "deletion_rules.csv",
    "evidence_files.csv"
]

for filename in files:
    path = dataset_path / filename

    print("\n" + "=" * 60)
    print("FILE:", filename)

    if not path.exists():
        print("FILE NOT FOUND")
        continue

    df = pd.read_csv(path, dtype=str, keep_default_na=False)

    print("Total Rows:", len(df))
    print("Columns:", list(df.columns))
    print("\nFirst 2 Records:")
    print(df.head(2).to_string(index=False, max_colwidth=35))

print("\nDATASET INSPECTION COMPLETED")
