
from pathlib import Path
import json
import pandas as pd


class JSONEvidenceExtractor:

    def __init__(self, dataset_dir="dataset"):

        self.dataset = Path(dataset_dir)

        self.manifest = pd.read_csv(
            self.dataset / "evidence_files.csv",
            dtype=str,
            keep_default_na=False
        )

    def extract_file(self, evidence_id):

        matches = self.manifest[
            self.manifest["file_id"] == evidence_id
        ]

        if matches.empty:
            return []

        row = matches.iloc[0]

        path = self.dataset / row["file_path"]

        if path.suffix.lower() != ".json":
            return []

        if not path.is_file():
            print("Missing evidence file:", path)
            return []

        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            return []

        service_exports = data.get("service_exports", {})

        if not isinstance(service_exports, dict):
            return []

        extracted = []

        for system_id, sections in service_exports.items():

            if not isinstance(sections, dict):
                continue

            for category, records in sections.items():

                if not isinstance(records, list):
                    continue

                for record_index, record in enumerate(records):

                    if not isinstance(record, dict):
                        continue

                    extracted.append({
                        "evidence_id": evidence_id,
                        "system_id": system_id,
                        "category": category,
                        "resource_id": str(
                            record.get("resource_id", "")
                        ),
                        "observed_at": record.get(
                            "observed_at", ""
                        ),
                        "captured_at": row["captured_at"],
                        "record_index": record_index,
                        "data": record
                    })

        return extracted

    def extract_all(self):

        all_records = []

        json_files = self.manifest[
            self.manifest["file_path"]
            .str.lower()
            .str.endswith(".json", na=False)
        ]

        for _, row in json_files.iterrows():

            records = self.extract_file(row["file_id"])

            all_records.extend(records)

        return all_records

    def records_before(self, records, audit_at):

        cutoff = pd.to_datetime(
            audit_at,
            utc=True,
            errors="coerce"
        )

        if pd.isna(cutoff):
            return []

        eligible = []

        for record in records:

            captured = pd.to_datetime(
                record["captured_at"],
                utc=True,
                errors="coerce"
            )

            observed = pd.to_datetime(
                record["observed_at"],
                utc=True,
                errors="coerce"
            )

            if pd.isna(captured) or pd.isna(observed):
                continue

            if captured > cutoff or observed > cutoff:
                continue

            eligible.append(record)

        return eligible


if __name__ == "__main__":

    extractor = JSONEvidenceExtractor()

    print("=" * 60)
    print("GHOSTTRACE - JSON EVIDENCE EXTRACTOR")
    print("=" * 60)

    records = extractor.extract_file("evidence_83")

    print("\nEVIDENCE 83 RECORDS:", len(records))

    all_records = extractor.extract_all()

    print("ALL JSON RECORDS:", len(all_records))

    json_count = (
        extractor.manifest["file_path"]
        .str.lower()
        .str.endswith(".json", na=False)
        .sum()
    )

    print("JSON FILES:", json_count)

    requests = pd.read_csv(
        "dataset/deletion_requests.csv",
        dtype=str,
        keep_default_na=False
    )

    request = requests.iloc[0]

    eligible = extractor.records_before(
        all_records,
        request["audit_at"]
    )

    print("\nCASE:", request["case_id"])
    print("AUDIT TIME:", request["audit_at"])
    print("TIME-ELIGIBLE RECORDS:", len(eligible))

    print("\nEXTRACTION COMPLETE")
