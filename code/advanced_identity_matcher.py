
import json
from collections import defaultdict

import pandas as pd

from identity_resolver import IdentityResolver
from unified_evidence_index import UnifiedEvidenceIndex


class AdvancedIdentityMatcher:

    IDENTITY_FIELDS = {
        "user_id",
        "customer_reference",
        "subject_reference",
        "email",
        "customer_email",
        "owner_email",
        "requester_email",
        "email_hash",
        "phone",
        "owner_phone",
        "requester_phone",
        "lookup_key",
        "match_key",
        "subject_key",
        "identity"
    }

    def __init__(self):

        self.resolver = IdentityResolver()

        self.index = UnifiedEvidenceIndex()
        self.index.build()

    @staticmethod
    def normalize(value):

        return str(value).strip().lower()

    def collect_identity_values(self, identity):

        values = set()

        for field in [
            "user_id",
            "email",
            "phone",
            "email_hash"
        ]:

            value = identity.get(field, "")

            if value:
                values.add(self.normalize(value))

        return values

    def extract_identity_fields(self, data):

        found = []

        if isinstance(data, dict):

            for key, value in data.items():

                if key.lower() in self.IDENTITY_FIELDS:

                    if isinstance(value, (str, int, float)):
                        found.append(
                            self.normalize(value)
                        )

                if isinstance(value, (dict, list)):
                    found.extend(
                        self.extract_identity_fields(value)
                    )

        elif isinstance(data, list):

            for item in data:
                found.extend(
                    self.extract_identity_fields(item)
                )

        return found

    def find_matches(self, identity, audit_at):

        identity_values = self.collect_identity_values(
            identity
        )

        eligible = self.index.records_before(
            audit_at
        )

        matches = []

        for record in eligible:

            values = self.extract_identity_fields(
                record.get("data", {})
            )

            matching_values = (
                identity_values.intersection(values)
            )

            if matching_values:

                matches.append({
                    **record,
                    "matched_identifiers": sorted(
                        matching_values
                    )
                })

        return matches


def main():

    print("=" * 65)
    print("GHOSTTRACE - ADVANCED IDENTITY MATCHER")
    print("=" * 65)

    matcher = AdvancedIdentityMatcher()

    sample = pd.read_csv(
        "dataset/sample_deletion_requests.csv",
        dtype=str,
        keep_default_na=False
    )

    main_requests = pd.read_csv(
        "dataset/deletion_requests.csv",
        dtype=str,
        keep_default_na=False
    )

    cases = pd.concat(
        [
            sample.head(3),
            main_requests.head(1)
        ],
        ignore_index=True
    )

    for _, request in cases.iterrows():

        case_id = request["case_id"]

        identity = matcher.resolver.resolve_email(
            request["email"]
        )

        print("\n" + "=" * 65)
        print("CASE:", case_id)
        print("=" * 65)

        if identity is None:
            print("IDENTITY NOT RESOLVED")
            continue

        matches = matcher.find_matches(
            identity,
            request["audit_at"]
        )

        resources = sorted({
            record["resource_id"]
            for record in matches
            if record.get("resource_id")
        })

        print("USER:", identity["user_id"])
        print("MATCHING RECORDS:", len(matches))
        print("UNIQUE RESOURCES:", len(resources))

        for record in matches[:10]:

            print(
                record["evidence_id"],
                "|",
                record["evidence_format"],
                "|",
                record["resource_id"],
                "|",
                record["category"]
            )

    print("\nADVANCED IDENTITY MATCHING COMPLETE")


if __name__ == "__main__":
    main()
