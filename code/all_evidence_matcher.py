
from collections import Counter
import pandas as pd

from identity_resolver import IdentityResolver
from json_evidence_extractor import JSONEvidenceExtractor
from evidence_identity_matcher import EvidenceIdentityMatcher
from resource_mapper import ResourceMapper


def main():

    print("=" * 65)
    print("GHOSTTRACE - ALL JSON EVIDENCE MATCHER")
    print("=" * 65)

    resolver = IdentityResolver()
    extractor = JSONEvidenceExtractor()
    matcher = EvidenceIdentityMatcher()
    mapper = ResourceMapper()

    requests = pd.read_csv(
        "dataset/deletion_requests.csv",
        dtype=str,
        keep_default_na=False
    )

    request = requests.iloc[0]

    case_id = request["case_id"]
    audit_at = request["audit_at"]

    identity = resolver.resolve_email(
        request["email"]
    )

    if identity is None:
        print("Identity could not be resolved.")
        return

    user_id = identity["user_id"]

    print("\nCASE:", case_id)
    print("USER:", user_id)
    print("AUDIT TIME:", audit_at)

    # 1. Extract every supported structured JSON record.
    all_records = extractor.extract_all()

    print("\nTOTAL JSON RECORDS:", len(all_records))

    # 2. Apply audit-time filtering.
    eligible = extractor.records_before(
        all_records,
        audit_at
    )

    print("TIME-ELIGIBLE RECORDS:", len(eligible))

    # 3. Find exact identity matches.
    direct_matches = matcher.find_user_records(
        eligible,
        identity
    )

    print("DIRECT IDENTITY MATCHES:", len(direct_matches))

    # 4. Find explicit catalog resource links.
    linked_resources = mapper.get_resources(
        user_id,
        audit_at
    )

    linked_ids = {
        item["resource_id"]
        for item in linked_resources
    }

    print(
        "CATALOG-LINKED RESOURCES:",
        len(linked_resources)
    )

    # 5. Match structured records by exact resource ID.
    resource_matches = [
        record
        for record in eligible
        if record["resource_id"] in linked_ids
    ]

    print(
        "RESOURCE-ID EVIDENCE MATCHES:",
        len(resource_matches)
    )

    # 6. Combine records using stable record identifiers.
    combined = {}

    def add_match(record, method):

        key = (
            record["evidence_id"],
            record["system_id"],
            record["category"],
            record["resource_id"],
            record["record_index"]
        )

        if key not in combined:
            combined[key] = {
                **record,
                "match_methods": set()
            }

        combined[key]["match_methods"].add(method)

    for record in direct_matches:
        add_match(record, "DIRECT_IDENTITY")

    for record in resource_matches:
        add_match(record, "RESOURCE_LINK")

    results = sorted(
        combined.values(),
        key=lambda record: (
            record["system_id"],
            record["resource_id"],
            record["observed_at"],
            record["evidence_id"],
            record["record_index"]
        )
    )

    print("\n" + "=" * 65)
    print("MATCHED EVIDENCE RECORDS")
    print("=" * 65)

    if not results:
        print("No structured JSON matches found.")

    for index, record in enumerate(results, start=1):

        print(f"\nRECORD {index}")

        print("Evidence:", record["evidence_id"])
        print("System:", record["system_id"])
        print("Category:", record["category"])
        print("Resource:", record["resource_id"])
        print("Observed:", record["observed_at"])

        print(
            "Match methods:",
            ", ".join(sorted(record["match_methods"]))
        )

    print("\n" + "=" * 65)
    print("SUMMARY")
    print("=" * 65)

    print("Matching evidence records:", len(results))

    systems = Counter(
        record["system_id"]
        for record in results
    )

    print("\nMATCHES BY SYSTEM:")

    for system, count in sorted(systems.items()):
        print(system, ":", count)

    print("\nEXPLICIT CATALOG LINKS:")

    for resource in linked_resources:
        print(
            resource["resource_id"],
            "|",
            resource["system_id"],
            "|",
            resource["activity_id"]
        )

    print("\nALL JSON EVIDENCE MATCHING COMPLETE")


if __name__ == "__main__":
    main()
