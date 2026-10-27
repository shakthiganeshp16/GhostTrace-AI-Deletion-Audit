
import json
import re
import shlex
from pathlib import Path

import pandas as pd


class TextEvidenceParser:

    def __init__(self, dataset_dir="dataset"):

        self.dataset = Path(dataset_dir)

        self.manifest = pd.read_csv(
            self.dataset / "evidence_files.csv",
            dtype=str,
            keep_default_na=False
        )

    def parse_log_line(self, line, evidence_id, captured_at):

        parts = line.strip().split(maxsplit=1)

        if len(parts) != 2:
            return None

        event_time, content = parts

        timestamp = pd.to_datetime(
            event_time,
            utc=True,
            errors="coerce"
        )

        if pd.isna(timestamp):
            return None

        data = {}

        if content.startswith("{"):

            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                return None

        else:

            try:
                tokens = shlex.split(content)
            except ValueError:
                return None

            for token in tokens:

                if "=" in token:
                    key, value = token.split("=", 1)
                    data[key] = value

        if not isinstance(data, dict):
            return None

        return {
            "evidence_id": evidence_id,
            "captured_at": captured_at,
            "observed_at": event_time,
            "system_id": str(data.get("service", "")),
            "category": str(data.get("event", "")),
            "resource_id": str(data.get("resource_id", "")),
            "evidence_format": "LOG",
            "data": data
        }

    def parse_txt_line(self, line, evidence_id, captured_at):

        # Example:
        # - timestamp | system | resource | category | status | email

        match = re.match(
            r"^\s*-\s*([^|]+)\|([^|]+)\|([^|]+)"
            r"\|([^|]+)\|([^|]+)\|(.+)$",
            line
        )

        if not match:
            return None

        values = [
            value.strip()
            for value in match.groups()
        ]

        observed_at, system_id, resource_id, category, status, identity = values

        if pd.isna(
            pd.to_datetime(
                observed_at,
                utc=True,
                errors="coerce"
            )
        ):
            return None

        return {
            "evidence_id": evidence_id,
            "captured_at": captured_at,
            "observed_at": observed_at,
            "system_id": system_id,
            "category": category,
            "resource_id": resource_id,
            "evidence_format": "TXT",
            "data": {
                "status": status,
                "identity": identity
            }
        }

    def parse_all(self):

        records = []

        for _, row in self.manifest.iterrows():

            path = self.dataset / row["file_path"]

            extension = path.suffix.lower()

            if extension not in {".log", ".txt"}:
                continue

            if not path.exists():
                continue

            lines = path.read_text(
                encoding="utf-8",
                errors="replace"
            ).splitlines()

            for line in lines:

                if extension == ".log":

                    record = self.parse_log_line(
                        line,
                        row["file_id"],
                        row["captured_at"]
                    )

                else:

                    record = self.parse_txt_line(
                        line,
                        row["file_id"],
                        row["captured_at"]
                    )

                if record is not None:
                    records.append(record)

        return records


def main():

    print("=" * 65)
    print("GHOSTTRACE - TEXT EVIDENCE PARSER")
    print("=" * 65)

    parser = TextEvidenceParser()

    records = parser.parse_all()

    print("\nTOTAL PARSED EVENTS:", len(records))

    print("\nRECORDS BY FORMAT:")

    counts = {}

    for record in records:

        extension = record["evidence_format"]
        counts[extension] = counts.get(extension, 0) + 1

    for extension, count in sorted(counts.items()):
        print(extension, ":", count)

    print("\nEVENTS WITH RESOURCE IDs:")

    resource_records = [
        record
        for record in records
        if record["resource_id"]
    ]

    print(len(resource_records))

    print("\nSAMPLE RESOURCE EVENTS:")

    for record in resource_records[:5]:

        print(
            record["evidence_id"],
            "|",
            record["system_id"],
            "|",
            record["resource_id"],
            "|",
            record["category"],
            "|",
            record["observed_at"]
        )

    print("\nTEXT EVIDENCE PARSING COMPLETE")


if __name__ == "__main__":
    main()
