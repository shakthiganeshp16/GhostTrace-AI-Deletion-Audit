
from pathlib import Path
from collections import Counter
import pandas as pd


class NonJSONEvidenceInspector:

    def __init__(self, dataset_dir="dataset"):

        self.dataset = Path(dataset_dir)

        self.manifest = pd.read_csv(
            self.dataset / "evidence_files.csv",
            dtype=str,
            keep_default_na=False
        )

    def inspect(self):

        extensions = {".sql", ".log", ".txt"}

        files = []

        for _, row in self.manifest.iterrows():

            path = self.dataset / row["file_path"]

            if path.suffix.lower() in extensions:
                files.append((row, path))

        print("\nTEXT EVIDENCE FILES:", len(files))

        counts = Counter()

        for row, path in files:

            counts[path.suffix.lower()] += 1

        print("\nFORMATS:")

        for extension, count in sorted(counts.items()):
            print(extension, ":", count)

        print("\n" + "=" * 65)
        print("FIRST TWO FILES PER FORMAT")
        print("=" * 65)

        shown = Counter()

        for row, path in files:

            extension = path.suffix.lower()

            if shown[extension] >= 2:
                continue

            shown[extension] += 1

            print("\nEVIDENCE:", row["file_id"])
            print("FORMAT:", extension)
            print("CAPTURED:", row["captured_at"])
            print("PATH:", path)

            if not path.exists():
                print("FILE NOT FOUND")
                continue

            text = path.read_text(
                encoding="utf-8",
                errors="replace"
            )

            lines = text.splitlines()

            print("TOTAL LINES:", len(lines))

            print("\nFIRST 12 LINES:")

            for line in lines[:12]:
                print(line[:250])

    def search_resources(self, resource_ids, audit_at):

        cutoff = pd.to_datetime(
            audit_at,
            utc=True,
            errors="coerce"
        )

        print("\n" + "=" * 65)
        print("RESOURCE REFERENCES IN TEXT EVIDENCE")
        print("=" * 65)

        for _, row in self.manifest.iterrows():

            path = self.dataset / row["file_path"]

            if path.suffix.lower() not in {
                ".sql", ".log", ".txt"
            }:
                continue

            captured = pd.to_datetime(
                row["captured_at"],
                utc=True,
                errors="coerce"
            )

            if pd.isna(captured) or captured > cutoff:
                continue

            if not path.exists():
                continue

            lines = path.read_text(
                encoding="utf-8",
                errors="replace"
            ).splitlines()

            for number, line in enumerate(lines, start=1):

                for resource_id in resource_ids:

                    # Diagnostic only: exact identifier
                    # boundaries are validated later.
                    import re

                    pattern = (
                        r"(?<![A-Za-z0-9_])"
                        + re.escape(resource_id)
                        + r"(?![A-Za-z0-9_])"
                    )

                    if re.search(pattern, line):

                        print("\nRESOURCE:", resource_id)
                        print("EVIDENCE:", row["file_id"])
                        print("LINE:", number)
                        print("TEXT:", line[:300])


def main():

    print("=" * 65)
    print("GHOSTTRACE - NON-JSON EVIDENCE INSPECTOR")
    print("=" * 65)

    inspector = NonJSONEvidenceInspector()

    inspector.inspect()

    inspector.search_resources(
        ["export_1260", "export_1842"],
        "2026-07-19T13:00:00Z"
    )

    print("\nNON-JSON INSPECTION COMPLETE")


if __name__ == "__main__":
    main()
