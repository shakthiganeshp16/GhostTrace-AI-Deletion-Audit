
from collections import Counter
from datetime import datetime, timezone

from unified_evidence_index import UnifiedEvidenceIndex


class ResourceStateEngine:

    def __init__(self):
        self.index = UnifiedEvidenceIndex()
        self.index.build()

    @staticmethod
    def as_bool(value):
        if isinstance(value, bool):
            return value

        if isinstance(value, str):
            if value.lower() == "true":
                return True
            if value.lower() == "false":
                return False

        return None

    @staticmethod
    def as_int(value):
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    def interpret_observation(self, record):

        data = record.get("data") or {}
        fmt = record.get("evidence_format", "")
        category = str(record.get("category", "")).lower()
        event = str(data.get("event", "")).lower()

        # --------------------------------------------------
        # TXT EVIDENCE
        # --------------------------------------------------

        if fmt == "TXT":

            status = str(
                data.get("status", "")
            ).upper()

            if status in ("NOT_FOUND", "ABSENT"):
                return "ABSENT"

            if status in ("FOUND", "PRESENT"):
                return "PRESENT"

        # --------------------------------------------------
        # LOG EVIDENCE
        # --------------------------------------------------

        if fmt == "LOG":

            # Account lookup verification
            if event == "profile_lookup_completed":

                http_status = str(
                    data.get(
                        "http_status",
                        data.get("status_code", "")
                    )
                )

                rows = self.as_int(data.get("rows"))

                if http_status == "404" and rows == 0:
                    return "ABSENT"

                if http_status == "200":
                    return "PRESENT"

            # Search index lookup
            if event == "index_query_completed":

                hits = self.as_int(
                    data.get("hits")
                )

                if hits is not None:
                    return (
                        "PRESENT"
                        if hits > 0
                        else "ABSENT"
                    )

                result = str(
                    data.get("result", "")
                ).lower()

                if result in ("hit", "found"):
                    return "PRESENT"

                if result in ("miss", "not_found"):
                    return "ABSENT"

            # Explicit restore access observations
            restore_allowed = self.as_bool(
                data.get("restore_allowed")
            )

            if restore_allowed is True:
                return "RESTORABLE"

            if restore_allowed is False:
                return "RESTORE_BLOCKED"

            # Generic logs do not prove record presence.
            return "UNKNOWN"

        # --------------------------------------------------
        # JSON / SQL EVIDENCE
        # --------------------------------------------------

        if fmt in ("JSON", "SQL"):

            restore_allowed = self.as_bool(
                data.get("restore_allowed")
            )

            if restore_allowed is True:
                return "RESTORABLE"

            if restore_allowed is False:
                return "RESTORE_BLOCKED"

            account_status = str(
                data.get("account_status", "")
            ).lower()

            # A deleted account status does not by itself
            # prove that every personal-data row is absent.
            if account_status in ("active", "enabled"):
                return "PRESENT"

            if account_status in ("deleted", "not_found"):
                return "UNKNOWN"

            status_code = str(
                data.get(
                    "http_status",
                    data.get("status_code", "")
                )
            )

            if status_code == "404":
                return "ABSENT"

            if status_code == "200":
                return "PRESENT"

            hits = self.as_int(
                data.get("hits")
            )

            if hits is not None:
                return (
                    "PRESENT"
                    if hits > 0
                    else "ABSENT"
                )

            # A disabled connector is not the same as
            # an absent user record.
            enabled = self.as_bool(
                data.get("enabled")
            )

            if enabled is True:
                return "ACTIVE"

            if enabled is False:
                return "DISABLED"

            # SQL rows prove a row was captured, but
            # their policy significance needs further
            # category-specific analysis.
            if fmt == "SQL":
                return "PRESENT"

        return "UNKNOWN"

    def analyze_resource(self, resource_id, audit_at):

        records = self.index.find_resource(
            resource_id,
            audit_at
        )

        observations = []

        for record in records:

            observations.append({
                "evidence_id": record.get(
                    "evidence_id", ""
                ),
                "format": record.get(
                    "evidence_format", ""
                ),
                "system_id": record.get(
                    "system_id", ""
                ),
                "resource_id": resource_id,
                "category": record.get(
                    "category", ""
                ),
                "state": self.interpret_observation(
                    record
                ),
                "observed_at": record.get(
                    "observed_at", ""
                ),
                "captured_at": record.get(
                    "captured_at", ""
                ),
                "source_table": record.get(
                    "source_table"
                )
            })

        observations.sort(
            key=lambda item: (
                str(item["observed_at"]),
                str(item["captured_at"]),
                str(item["evidence_id"])
            )
        )

        return observations


def main():

    print("=" * 65)
    print("GHOSTTRACE - RESOURCE STATE ENGINE")
    print("=" * 65)

    engine = ResourceStateEngine()

    tests = [
        (
            "account_146",
            "2026-10-02T00:00:00Z"
        ),
        (
            "account_1810",
            "2026-10-02T00:00:00Z"
        ),
        (
            "account_7566",
            "2026-09-26T11:00:00Z"
        ),
        (
            "export_1260",
            "2026-07-19T13:00:00Z"
        ),
        (
            "export_1842",
            "2026-07-19T13:00:00Z"
        )
    ]

    print("\nTEST RESOURCES")

    for resource_id, audit_at in tests:

        observations = engine.analyze_resource(
            resource_id,
            audit_at
        )

        print("\nRESOURCE:", resource_id)
        print("AUDIT AT:", audit_at)
        print("OBSERVATIONS:", len(observations))

        for observation in observations[-5:]:

            print(
                observation["evidence_id"],
                "|",
                observation["format"],
                "|",
                observation["state"],
                "|",
                observation["observed_at"]
            )

    print("\n" + "=" * 65)
    print("OBSERVATION STATE COUNTS")
    print("=" * 65)

    counts = Counter()

    for record in engine.index.records:

        state = engine.interpret_observation(
            record
        )

        counts[state] += 1

    for state, count in sorted(counts.items()):
        print(state, ":", count)

    print("\nRESOURCE STATE ENGINE TEST COMPLETE")


if __name__ == "__main__":
    main()
