
import sqlite3
from pathlib import Path

import pandas as pd


class SQLEvidenceParser:

    def __init__(self, dataset_dir="dataset"):

        self.dataset = Path(dataset_dir)

        self.manifest = pd.read_csv(
            self.dataset / "evidence_files.csv",
            dtype=str,
            keep_default_na=False
        )

    def parse_file(self, evidence_id):

        matching = self.manifest[
            self.manifest["file_id"] == evidence_id
        ]

        if matching.empty:
            return []

        row = matching.iloc[0]

        path = self.dataset / row["file_path"]

        if path.suffix.lower() != ".sql":
            return []

        if not path.exists():
            print("Missing SQL file:", path)
            return []

        script = path.read_text(
            encoding="utf-8",
            errors="replace"
        )

        connection = sqlite3.connect(":memory:")

        try:
            connection.executescript(script)

            tables = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """
            ).fetchall()

            results = []

            for (table_name,) in tables:

                # Table names are obtained from SQLite's
                # own schema, not from user input.
                escaped = table_name.replace('"', '""')

                cursor = connection.execute(
                    f'SELECT * FROM "{escaped}"'
                )

                columns = [
                    item[0]
                    for item in cursor.description
                ]

                for values in cursor.fetchall():

                    record = dict(zip(columns, values))

                    results.append({
                        "evidence_id": evidence_id,
                        "captured_at": row["captured_at"],
                        "table": table_name,
                        "data": record
                    })

            return results

        finally:
            connection.close()

    def parse_all(self):

        all_records = []

        sql_files = self.manifest[
            self.manifest["file_path"]
            .str.lower()
            .str.endswith(".sql", na=False)
        ]

        for _, row in sql_files.iterrows():

            records = self.parse_file(
                row["file_id"]
            )

            all_records.extend(records)

        return all_records


def main():

    print("=" * 65)
    print("GHOSTTRACE - SQL EVIDENCE PARSER")
    print("=" * 65)

    parser = SQLEvidenceParser()

    sql_files = parser.manifest[
        parser.manifest["file_path"]
        .str.lower()
        .str.endswith(".sql", na=False)
    ]

    print("\nSQL FILES:", len(sql_files))

    all_records = parser.parse_all()

    print("TOTAL SQL ROWS:", len(all_records))

    print("\n" + "=" * 65)
    print("TABLES AND ROW COUNTS")
    print("=" * 65)

    counts = {}

    for record in all_records:

        table = record["table"]

        counts[table] = counts.get(table, 0) + 1

    for table, count in sorted(counts.items()):
        print(table, ":", count)

    print("\n" + "=" * 65)
    print("SAMPLE RECORD STRUCTURE")
    print("=" * 65)

    shown = set()

    for record in all_records:

        table = record["table"]

        if table in shown:
            continue

        shown.add(table)

        print("\nTABLE:", table)
        print("EVIDENCE:", record["evidence_id"])
        print("CAPTURED:", record["captured_at"])

        print(
            "COLUMNS:",
            list(record["data"].keys())
        )

        print(
            "RESOURCE:",
            record["data"].get(
                "resource_id",
                "(no resource_id column)"
            )
        )

    print("\nSQL EVIDENCE PARSING COMPLETE")


if __name__ == "__main__":
    main()
