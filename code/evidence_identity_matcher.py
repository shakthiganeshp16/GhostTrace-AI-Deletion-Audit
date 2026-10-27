
import pandas as pd

from identity_resolver import IdentityResolver
from json_evidence_extractor import JSONEvidenceExtractor


class EvidenceIdentityMatcher:

    EMAIL_FIELDS = {
        "email",
        "owner_email",
        "customer_email",
        "requester_email"
    }

    REFERENCE_FIELDS = {
        "customer_reference",
        "subject_reference"
    }

    PHONE_FIELDS = {
        "phone",
        "owner_phone",
        "requester_phone"
    }

    HASH_FIELDS = {
        "email_hash"
    }

    def normalize(self, value):
        return str(value).strip().casefold()

    
    def match_record(self, record, identity):

        data = record["data"]
        user_id = str(identity["user_id"]).strip().casefold()

        emails = {
            str(value).strip().casefold()
            for value in identity.get("emails", [])
            if value
        }

        phones = {
            str(value).strip().casefold()
            for value in identity.get("phones", [])
            if value
        }

        hashes = {
            str(value).strip().casefold()
            for value in identity.get("email_hashes", [])
            if value
        }

        matched_fields = []

        for field, value in data.items():

            normalized = str(value).strip().casefold()

            if not normalized:
                continue

            if field in self.REFERENCE_FIELDS:
                if normalized == user_id:
                    matched_fields.append(field)

            elif field in self.EMAIL_FIELDS:
                if normalized in emails:
                    matched_fields.append(field)

            elif field in self.PHONE_FIELDS:
                if normalized in phones:
                    matched_fields.append(field)

            elif field in self.HASH_FIELDS:
                if normalized in hashes:
                    matched_fields.append(field)

        return matched_fields

    def find_user_records(self, records, identity):

        results = []

        for record in records:

            matched_fields = self.match_record(
                record,
                identity
            )

            if matched_fields:

                results.append({
                    **record,
                    "matched_fields": matched_fields
                })

        return results


def main():

    print("=" * 60)
    print("GHOSTTRACE - EVIDENCE IDENTITY MATCHER")
    print("=" * 60)

    resolver = IdentityResolver()

    extractor = JSONEvidenceExtractor()

    matcher = EvidenceIdentityMatcher()

    requests = pd.read_csv(
        "dataset/deletion_requests.csv",
        dtype=str,
        keep_default_na=False
    )

    request = requests.iloc[0]

    case_id = request["case_id"]
    email = request["email"]
    audit_at = request["audit_at"]

    identity = resolver.resolve_email(email)

    if identity is None:
        print("Identity could not be resolved.")
        return

    print("\nCASE:", case_id)
    print("USER:", identity["user_id"])
    print("AUDIT TIME:", audit_at)

    records = extractor.extract_file(
        "evidence_83"
    )

    eligible = extractor.records_before(
        records,
        audit_at
    )

    matches = matcher.find_user_records(
        eligible,
        identity
    )
   
    print("\nREFERENCE DEBUG:")

    for record in eligible:
        data = record["data"]

        for field in ("customer_reference", "subject_reference"):
            value = data.get(field)

            if value is None:
                continue

            if "user_18" in str(value).casefold():
                print(
                    record["resource_id"],
                    "|",
                    field,
                    "|",
                    repr(value),
                    "| exact match:",
                    str(value).strip().casefold()
                    == str(identity["user_id"]).strip().casefold()
                )
 

    print("\nTOTAL EVIDENCE RECORDS:", len(records))
    print("ELIGIBLE RECORDS:", len(eligible))
    print("MATCHING USER RECORDS:", len(matches))

    print("\n" + "=" * 60)
    print("MATCHED RESOURCES")
    print("=" * 60)

    if not matches:
        print("No matching records found.")

    for index, record in enumerate(matches, start=1):

        print("\nRecord:", index)

        print(
            "Evidence ID:",
            record["evidence_id"]
        )

        print(
            "System:",
            record["system_id"]
        )

        print(
            "Category:",
            record["category"]
        )

        print(
            "Resource ID:",
            record["resource_id"]
        )

        print(
            "Observed At:",
            record["observed_at"]
        )

        print(
            "Matched Fields:",
            ", ".join(record["matched_fields"])
        )

    print("\n" + "=" * 60)
    print("IDENTITY MATCHING COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
