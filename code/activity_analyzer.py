
from collections import Counter
from pathlib import Path
import pandas as pd


class ActivityAnalyzer:
    def __init__(self, dataset_dir="dataset"):
        path = Path(dataset_dir) / "system_activity.csv"

        self.activities = pd.read_csv(
            path,
            dtype=str,
            keep_default_na=False
        )

        self.activities["event_time_parsed"] = pd.to_datetime(
            self.activities["event_time"],
            utc=True,
            errors="coerce"
        )

    def get_events_before(self, audit_at):
        cutoff = pd.to_datetime(audit_at, utc=True)

        return self.activities[
            self.activities["event_time_parsed"].notna()
            & (self.activities["event_time_parsed"] <= cutoff)
        ].copy()

    def find_user_events(self, identifiers, audit_at):
        events = self.get_events_before(audit_at)

        terms = {
            str(value).strip().casefold()
            for value in identifiers
            if str(value).strip()
        }

        results = []

        for _, row in events.iterrows():
            searchable = " ".join([
                row["resource_id"],
                row["details"]
            ]).casefold()

            matched = [
                term for term in terms
                if term in searchable
            ]

            if matched:
                results.append({
                    "activity_id": row["activity_id"],
                    "event_time": row["event_time"],
                    "event_type": row["event_type"],
                    "source_system": row["source_system"],
                    "target_system": row["target_system"],
                    "resource_id": row["resource_id"],
                    "reported_result": row["reported_result"]
                })

        return sorted(
            results,
            key=lambda x: (
                x["event_time"],
                x["activity_id"]
            )
        )


if __name__ == "__main__":
    from identity_resolver import IdentityResolver

    analyzer = ActivityAnalyzer()
    resolver = IdentityResolver()

    requests = pd.read_csv(
        "dataset/deletion_requests.csv",
        dtype=str,
        keep_default_na=False
    )

    print("TOTAL ACTIVITIES:", len(analyzer.activities))

    print("\nEVENT TYPE COUNTS:")
    event_counts = Counter(
        analyzer.activities["event_type"]
    )

    for event_type, count in event_counts.most_common():
        print(event_type, ":", count)

    print("\nREPORTED RESULT COUNTS:")
    result_counts = Counter(
        analyzer.activities["reported_result"]
    )

    for result, count in result_counts.most_common():
        print(result, ":", count)

    print("\nSOURCE SYSTEMS:")
    for system, count in Counter(
        analyzer.activities["source_system"]
    ).most_common():
        print(system, ":", count)

    print("\nTARGET SYSTEMS:")
    for system, count in Counter(
        analyzer.activities["target_system"]
    ).most_common():
        print(system, ":", count)

    request = requests.iloc[0]
    identity = resolver.resolve_email(request["email"])

    if identity is None:
        raise SystemExit("Identity not uniquely resolved")

    identifiers = {identity["user_id"]}

    for field in [
        "emails",
        "names",
        "phones",
        "email_hashes"
    ]:
        identifiers.update(identity[field])

    matches = analyzer.find_user_events(
        identifiers,
        request["audit_at"]
    )

    print("\nCASE:", request["case_id"])
    print("USER:", identity["user_id"])
    print("MATCHING ACTIVITY EVENTS:", len(matches))

    for event in matches[:20]:
        print(
            event["activity_id"],
            "|",
            event["event_time"],
            "|",
            event["event_type"],
            "|",
            event["target_system"],
            "|",
            event["reported_result"]
        )

    print("\nACTIVITY ANALYSIS COMPLETE")
