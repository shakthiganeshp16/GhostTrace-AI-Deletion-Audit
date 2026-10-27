
from pathlib import Path
import pandas as pd

from identity_resolver import IdentityResolver
from resource_mapper import ResourceMapper


class ResourceStateAnalyzer:

    def __init__(self, dataset_dir="dataset"):

        self.activities = pd.read_csv(
            Path(dataset_dir) / "system_activity.csv",
            dtype=str,
            keep_default_na=False
        )

        self.activities["parsed_time"] = pd.to_datetime(
            self.activities["event_time"],
            utc=True,
            errors="coerce"
        )

    def get_history(self, resource_id, audit_at):

        cutoff = pd.to_datetime(
            audit_at,
            utc=True,
            errors="coerce"
        )

        if pd.isna(cutoff):
            return self.activities.iloc[0:0].copy()

        history = self.activities[
            (self.activities["resource_id"] == resource_id)
            & (self.activities["parsed_time"].notna())
            & (self.activities["parsed_time"] <= cutoff)
        ].copy()

        return history.sort_values(
            ["parsed_time", "activity_id"]
        )

    def analyze(self, resource_id, audit_at):

        history = self.get_history(
            resource_id,
            audit_at
        )

        result = {
            "resource_id": resource_id,
            "audit_at": audit_at,
            "event_count": len(history),
            "last_event": None,
            "deletion_attempts": 0,
            "successful_deletions": 0,
            "failed_deletions": 0,
            "partial_deletions": 0,
            "state": "UNKNOWN"
        }

        if history.empty:
            return result

        for _, event in history.iterrows():

            event_type = event["event_type"]
            status = event["reported_result"]

            if event_type == "DELETE_RECORD":

                result["deletion_attempts"] += 1

                if status == "SUCCESS":
                    result["successful_deletions"] += 1

                elif status == "FAILED":
                    result["failed_deletions"] += 1

                elif status == "PARTIAL":
                    result["partial_deletions"] += 1

        last = history.iloc[-1]

        result["last_event"] = {
            "activity_id": last["activity_id"],
            "event_time": last["event_time"],
            "event_type": last["event_type"],
            "reported_result": last["reported_result"]
        }

        # Conservative classification:
        # activity outcomes alone do not prove
        # whether the resource is present or absent.
        result["state"] = "UNKNOWN"

        return result


def main():

    print("=" * 65)
    print("GHOSTTRACE - TEMPORAL RESOURCE STATE ANALYZER")
    print("=" * 65)

    resolver = IdentityResolver()
    mapper = ResourceMapper()
    analyzer = ResourceStateAnalyzer()

    requests = pd.read_csv(
        "dataset/deletion_requests.csv",
        dtype=str,
        keep_default_na=False
    )

    request = requests.iloc[0]

    identity = resolver.resolve_email(
        request["email"]
    )

    if identity is None:
        raise SystemExit("Identity not resolved")

    resources = mapper.get_resources(
        identity["user_id"],
        request["audit_at"]
    )

    print("\nCASE:", request["case_id"])
    print("USER:", identity["user_id"])
    print("AUDIT TIME:", request["audit_at"])

    print("\nLINKED RESOURCES:", len(resources))

    for resource in resources:

        result = analyzer.analyze(
            resource["resource_id"],
            request["audit_at"]
        )

        print("\nRESOURCE:", result["resource_id"])
        print("EVENT COUNT:", result["event_count"])
        print("DELETE ATTEMPTS:", result["deletion_attempts"])
        print("SUCCESSFUL:", result["successful_deletions"])
        print("FAILED:", result["failed_deletions"])
        print("PARTIAL:", result["partial_deletions"])
        print("CURRENT STATE:", result["state"])

        if result["last_event"]:
            print(
                "LAST EVENT:",
                result["last_event"]
            )

    print("\nTEMPORAL STATE ANALYSIS COMPLETE")


if __name__ == "__main__":
    main()
