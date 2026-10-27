
import json
from collections import Counter

import pandas as pd

from sql_evidence_parser import SQLEvidenceParser


TABLE_CATEGORIES = {
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "customer_profiles_primary": ("account_service", "USER_PROFILE"),
    "customer_profiles_failover_replica": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "search_documents_primary": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "customer_exports": ("export_service", "USER_EXPORT"),
    "support_records": ("support_platform", "SUPPORT_MESSAGE"),
    "security_audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
    "backup_restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "connector_subscriptions": ("integration_service", "DATA_FLOW")
}


class SQLEvidenceNormalizer:

    def __init__(self):
        self.parser = SQLEvidenceParser()

    def normalize_record(self, record):

        table = record["table"]

        if table == "snapshot_scope":
            return None

        data = dict(record["data"])

        # Generic primary and replica snapshots
        # store their actual record inside record_json.
        if "record_json" in data:

            raw = data["record_json"]

            try:
                payload = json.loads(raw)
            except (TypeError, json.JSONDecodeError):
                payload = {}

            if not isinstance(payload, dict):
                payload = {}

            system_id = data.get("origin_system", "")

            category = data.get("collection_name", "")

            # Preserve both the metadata and the payload.
            combined_data = {
                **data,
                **payload
            }

        else:

            system_id, category = TABLE_CATEGORIES.get(
                table,
                ("UNKNOWN", "UNKNOWN")
            )

            combined_data = data

        return {
            "evidence_id": record["evidence_id"],
            "captured_at": record["captured_at"],
            "system_id": system_id,
            "category": category,
            "resource_id": str(
                data.get("resource_id", "")
            ),
            "observed_at": data.get(
                "updated_at",
                record["captured_at"]
            ),
            "source_table": table,
            "data": combined_data
        }

    def normalize_all(self):

        records = self.parser.parse_all()

        normalized = []

        for record in records:

            result = self.normalize_record(record)

            if result is not None:
                normalized.append(result)

        return normalized

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

            if (
                pd.notna(captured)
                and pd.notna(observed)
                and captured <= cutoff
                and observed <= cutoff
            ):
                eligible.append(record)

        return eligible


def main():

    print("=" * 65)
    print("GHOSTTRACE - SQL EVIDENCE NORMALIZER")
    print("=" * 65)

    normalizer = SQLEvidenceNormalizer()

    records = normalizer.normalize_all()

    print("\nNORMALIZED SQL RECORDS:", len(records))

    print("\n" + "=" * 65)
    print("RECORDS BY SOURCE TABLE")
    print("=" * 65)

    table_counts = Counter(
        record["source_table"]
        for record in records
    )

    for table, count in sorted(table_counts.items()):
        print(table, ":", count)

    print("\n" + "=" * 65)
    print("RECORDS BY CATEGORY")
    print("=" * 65)

    category_counts = Counter(
        record["category"]
        for record in records
    )

    for category, count in sorted(category_counts.items()):
        print(category, ":", count)

    requests = pd.read_csv(
        "dataset/deletion_requests.csv",
        dtype=str,
        keep_default_na=False
    )

    request = requests.iloc[0]

    eligible = normalizer.records_before(
        records,
        request["audit_at"]
    )

    print("\nCASE:", request["case_id"])
    print("AUDIT TIME:", request["audit_at"])
    print("TIME-ELIGIBLE SQL RECORDS:", len(eligible))

    print("\nSQL NORMALIZATION COMPLETE")


if __name__ == "__main__":
    main()
