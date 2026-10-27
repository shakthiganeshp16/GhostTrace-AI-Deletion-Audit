
from collections import Counter

import pandas as pd

from json_evidence_extractor import JSONEvidenceExtractor
from sql_evidence_normalizer import SQLEvidenceNormalizer
from text_evidence_parser import TextEvidenceParser


class UnifiedEvidenceIndex:

    def __init__(self):

        self.json_extractor = JSONEvidenceExtractor()
        self.sql_normalizer = SQLEvidenceNormalizer()
        self.text_parser = TextEvidenceParser()

        self.records = []
        self.resource_lookup = {}

    def build(self):

        json_records = self.json_extractor.extract_all()
        sql_records = self.sql_normalizer.normalize_all()
        text_records = self.text_parser.parse_all()

        self.records = []
        self.resource_lookup = {}

        for record in json_records:

            self.records.append({
                **record,
                "evidence_format": "JSON",
                "source_table": None
            })

        for record in sql_records:

            self.records.append({
                **record,
                "evidence_format": "SQL"
            })

        for record in text_records:

            self.records.append({
                **record,
                "source_table": None
            })

        for record in self.records:

            resource_id = record["resource_id"]

            if resource_id:

                self.resource_lookup.setdefault(
                    resource_id, []
                ).append(record)

        return self.records

    @staticmethod
    def is_time_eligible(record, audit_at):

        cutoff = pd.to_datetime(
            audit_at,
            utc=True,
            errors="coerce"
        )

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

        return (
            pd.notna(cutoff)
            and pd.notna(captured)
            and pd.notna(observed)
            and captured <= cutoff
            and observed <= cutoff
        )

    def records_before(self, audit_at):

        return [
            record
            for record in self.records
            if self.is_time_eligible(record, audit_at)
        ]

    def find_resource(self, resource_id, audit_at):

        candidates = self.resource_lookup.get(
            resource_id, []
        )

        return [
            record
            for record in candidates
            if self.is_time_eligible(record, audit_at)
        ]

    def summary(self):

        print("\nTOTAL INDEXED RECORDS:", len(self.records))

        counts = Counter(
            record["evidence_format"]
            for record in self.records
        )

        print("\nRECORDS BY FORMAT:")

        for evidence_format, count in sorted(counts.items()):
            print(evidence_format, ":", count)


def main():

    print("=" * 65)
    print("GHOSTTRACE - UNIFIED EVIDENCE INDEX")
    print("=" * 65)

    index = UnifiedEvidenceIndex()
    index.build()
    index.summary()

    audit_at = "2026-07-19T13:00:00Z"

    print("\n" + "=" * 65)
    print("CASE 33 RESOURCE SEARCH")
    print("=" * 65)

    for resource_id in ["export_1260", "export_1842"]:

        matches = index.find_resource(
            resource_id,
            audit_at
        )

        print("\nRESOURCE:", resource_id)
        print("MATCHING RECORDS:", len(matches))

        for record in matches:

            print(
                record["evidence_id"],
                "|",
                record["evidence_format"],
                "|",
                record["system_id"],
                "|",
                record["category"],
                "|",
                record["observed_at"]
            )

    print("\n" + "=" * 65)
    print("TIME FILTER CHECK")
    print("=" * 65)

    eligible = index.records_before(audit_at)

    print("TOTAL TIME-ELIGIBLE RECORDS:", len(eligible))

    print("\nUNIFIED INDEX COMPLETE")


if __name__ == "__main__":
    main()
