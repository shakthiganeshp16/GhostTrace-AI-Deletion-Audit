
from pathlib import Path
from collections import defaultdict
import re
import pandas as pd


class ResourceMapper:
    def __init__(self, dataset_dir="dataset"):
        self.activities = pd.read_csv(
            Path(dataset_dir) / "system_activity.csv",
            dtype=str,
            keep_default_na=False
        )

        self.links = self.activities[
            (self.activities["event_type"] == "LINK_RESOURCE_IDENTITY")
            & (self.activities["reported_result"] == "SUCCESS")
        ].copy()

        self.links["parsed_time"] = pd.to_datetime(
            self.links["event_time"],
            utc=True,
            errors="coerce"
        )

    def get_resources(self, user_id, audit_at):
        cutoff = pd.to_datetime(audit_at, utc=True)

        eligible = self.links[
            self.links["parsed_time"].notna()
            & (self.links["parsed_time"] <= cutoff)
        ]

        resources = {}

        for _, row in eligible.iterrows():
            # Match a complete user ID, not a substring.
            user_ids = set(re.findall(
                r"\buser_\d+\b",
                row["details"]
            ))

            if user_id not in user_ids:
                continue

            resource_id = row["resource_id"]

            resources[resource_id] = {
                "resource_id": resource_id,
                "system_id": row["target_system"],
                "activity_id": row["activity_id"],
                "linked_at": row["event_time"]
            }

        return sorted(
            resources.values(),
            key=lambda item: (
                item["system_id"],
                item["resource_id"]
            )
        )

    def get_resource_events(self, resource_id, audit_at):
        cutoff = pd.to_datetime(audit_at, utc=True)

        events = self.activities.copy()

        events["parsed_time"] = pd.to_datetime(
            events["event_time"],
            utc=True,
            errors="coerce"
        )

        events = events[
            events["parsed_time"].notna()
            & (events["parsed_time"] <= cutoff)
            & (events["resource_id"] == resource_id)
        ]

        return events.sort_values(
            ["parsed_time", "activity_id"]
        )


if __name__ == "__main__":
    from identity_resolver import IdentityResolver

    resolver = IdentityResolver()
    mapper = ResourceMapper()

    requests = pd.read_csv(
        "dataset/deletion_requests.csv",
        dtype=str,
        keep_default_na=False
    )

    request = requests.iloc[0]
    identity = resolver.resolve_email(request["email"])

    if identity is None:
        raise SystemExit("Identity not resolved")

    user_id = identity["user_id"]
    audit_at = request["audit_at"]

    print("CASE:", request["case_id"])
    print("USER:", user_id)
    print("AUDIT TIME:", audit_at)

    resources = mapper.get_resources(
        user_id,
        audit_at
    )

    print("\nLINKED RESOURCES:", len(resources))

    for resource in resources:
        print(
            resource["resource_id"],
            "|",
            resource["system_id"],
            "|",
            resource["activity_id"]
        )

        events = mapper.get_resource_events(
            resource["resource_id"],
            audit_at
        )

        print("  Related events:", len(events))

        for _, event in events.iterrows():
            print(
                " ",
                event["event_time"],
                "|",
                event["event_type"],
                "|",
                event["reported_result"]
            )

    print("\nRESOURCE MAPPING COMPLETE")
