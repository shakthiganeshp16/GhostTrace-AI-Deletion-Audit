
import pandas as pd

from identity_resolver import IdentityResolver
from resource_mapper import ResourceMapper
from evidence_identity_matcher import EvidenceIdentityMatcher
from resource_state_engine import ResourceStateEngine


class CaseAuditEngine:

    def __init__(self):

        self.resolver = IdentityResolver()
        self.mapper = ResourceMapper()
        self.matcher = EvidenceIdentityMatcher()
        self.state_engine = ResourceStateEngine()

        self.requests = pd.read_csv(
            "dataset/deletion_requests.csv",
            dtype=str,
            keep_default_na=False
        )

    def audit_case(self, case_id):

        matches = self.requests[
            self.requests["case_id"] == case_id
        ]

        if matches.empty:
            return {
                "case_id": case_id,
                "error": "CASE_NOT_FOUND"
            }

        request = matches.iloc[0]
        audit_at = request["audit_at"]

        identity = self.resolver.resolve_email(
            request["email"]
        )

        if identity is None:
            return {
                "case_id": case_id,
                "error": "IDENTITY_NOT_RESOLVED"
            }

        user_id = identity["user_id"]

        eligible_records = (
            self.state_engine.index.records_before(
                audit_at
            )
        )

        direct_matches = (
            self.matcher.find_user_records(
                eligible_records,
                identity
            )
        )

        linked_resources = self.mapper.get_resources(
            user_id,
            audit_at
        )

        resource_ids = {
            record["resource_id"]
            for record in direct_matches
            if record.get("resource_id")
        }

        resource_ids.update(
            item["resource_id"]
            for item in linked_resources
        )

        resource_reports = []

        for resource_id in sorted(resource_ids):

            observations = (
                self.state_engine.analyze_resource(
                    resource_id,
                    audit_at
                )
            )

            resource_reports.append({
                "resource_id": resource_id,
                "observation_count": len(observations),
                "observations": observations
            })

        return {
            "case_id": case_id,
            "user_id": user_id,
            "audit_at": audit_at,
            "request_text": request["request_text"],
            "reported_status": request["reported_status"],
            "direct_identity_matches": len(
                direct_matches
            ),
            "catalog_linked_resources": len(
                linked_resources
            ),
            "resources_found": len(
                resource_reports
            ),
            "resources": resource_reports
        }



def main():

    print("=" * 65)
    print("GHOSTTRACE - CASE AUDIT ENGINE")
    print("=" * 65)

    engine = CaseAuditEngine()

    sample_requests = pd.read_csv(
        "dataset/sample_deletion_requests.csv",
        dtype=str,
        keep_default_na=False
    )

    print("\nMAIN DATASET CASES:", len(engine.requests))
    print("SAMPLE DATASET CASES:", len(sample_requests))

    print("\nFIRST 5 MAIN CASE IDs:")
    print(engine.requests["case_id"].head().tolist())

    print("\nFIRST 5 SAMPLE CASE IDs:")
    print(sample_requests["case_id"].head().tolist())

    # Test three sample cases and one main case.
    test_cases = (
        sample_requests["case_id"].head(3).tolist()
        + ["case_33"]
    )

    for case_id in test_cases:

        if case_id in sample_requests["case_id"].values:

            # Temporarily use sample requests for this case.
            original_requests = engine.requests
            engine.requests = sample_requests

            result = engine.audit_case(case_id)

            engine.requests = original_requests

        else:
            result = engine.audit_case(case_id)

        print("\n" + "=" * 65)
        print("CASE:", case_id)
        print("=" * 65)

        if "error" in result:
            print("ERROR:", result["error"])
            continue

        print("USER:", result["user_id"])
        print("AUDIT:", result["audit_at"])
        print("REPORTED:", result["reported_status"])
        print("DIRECT MATCHES:", result["direct_identity_matches"])
        print("CATALOG LINKS:", result["catalog_linked_resources"])
        print("RESOURCES FOUND:", result["resources_found"])

        for resource in result["resources"][:10]:

            print("\nRESOURCE:", resource["resource_id"])
            print("OBSERVATIONS:", resource["observation_count"])

            for observation in resource["observations"][-3:]:

                print(
                    observation["evidence_id"],
                    "|",
                    observation["format"],
                    "|",
                    observation["state"],
                    "|",
                    observation["observed_at"]
                )

    print("\nCASE AUDIT ENGINE TEST COMPLETE")


if __name__ == "__main__":
    main()
