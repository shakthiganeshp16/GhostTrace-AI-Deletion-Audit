
from pathlib import Path
from collections import Counter
import pandas as pd

DATASET = Path("dataset")

manifest = pd.read_csv(
    DATASET / "evidence_files.csv",
    dtype=str,
    keep_default_na=False
)

print("TOTAL EVIDENCE FILES:", len(manifest))
print("=" * 60)

file_types = Counter()
missing_files = []
evidence_locations = []

for _, row in manifest.iterrows():
    file_id = row["file_id"]
    relative_path = row["file_path"]
    full_path = DATASET / relative_path

    extension = full_path.suffix.lower()
    file_types[extension or "(no extension)"] += 1

    if not full_path.is_file():
        missing_files.append(file_id)

    evidence_locations.append({
        "file_id": file_id,
        "extension": extension,
        "path": relative_path,
        "captured_at": row["captured_at"]
    })

print("\nEVIDENCE FILE TYPES:")
for extension, count in sorted(file_types.items()):
    print(f"{extension}: {count}")

print("\nMISSING FILES:", len(missing_files))
print("Missing IDs:", missing_files)

print("\nFIRST 10 EVIDENCE FILES:")
for item in evidence_locations[:10]:
    print(
        item["file_id"],
        "|", item["extension"],
        "|", item["path"]
    )

print("\nEVIDENCE CAPTURE DATE RANGE:")
dates = pd.to_datetime(
    manifest["captured_at"],
    utc=True,
    errors="coerce"
)

print("Earliest:", dates.min())
print("Latest:", dates.max())

print("\nREQUEST AUDIT DATE RANGE:")
requests = pd.read_csv(
    DATASET / "deletion_requests.csv"
)

audit_dates = pd.to_datetime(
    requests["audit_at"],
    utc=True
)

print("Earliest:", audit_dates.min())
print("Latest:", audit_dates.max())

print("\nINSPECTION COMPLETE")
