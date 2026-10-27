
import csv
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from identity_resolver import IdentityResolver
from resource_mapper import ResourceMapper
from unified_evidence_index import UnifiedEvidenceIndex
from resource_state_engine import ResourceStateEngine
from remediation_planner import RemediationPlanner


ROOT = Path(".")
DATASET = ROOT / "dataset"
OUTPUT = ROOT / "output.csv"
DIAGNOSTICS = ROOT / "prediction_diagnostics.csv"

IDENTITY_FIELDS = {
    "user_id", "customer_id", "subject_id",
    "customer_reference", "subject_reference",
    "email", "customer_email", "owner_email",
    "requester_email", "email_hash",
    "phone", "owner_phone", "requester_phone",
    "lookup_key", "match_key", "subject_key",
    "identity", "subject_email", "user_email",
}

CATEGORY_MAP = {
    "customer_profiles": "USER_PROFILE",
    "customer_search_documents": "SEARCH_INDEX_ENTRY",
    "customer_analytics_reports": "ANALYTICS_PROFILE",
    "customer_export_jobs": "USER_EXPORT",
    "security_audit_events": "SECURITY_AUDIT_LOG",
    "support_conversations": "SUPPORT_MESSAGE",
    "ticket_attachments": "SUPPORT_ATTACHMENT",
    "retained_order_records": "SUPPORT_MESSAGE",
    "deleted_customer_references": "ACCOUNT_TOMBSTONE",
    "backup_catalog": "BACKUP_ARCHIVE",
}

DELETION_WORDS = (
    "delete", "deletion", "erase", "erasure",
    "remove my data", "remove my account",
    "forget me", "close my account",
)

NON_DELETION_PATTERNS = (
    r"\bdo not delete\b",
    r"\bdon't delete\b",
    r"\bnot requesting deletion\b",
    r"\bnot a deletion request\b",
    r"\bkeep my account\b",
    r"\bcancel my deletion\b",
    r"\bwithdraw my deletion\b",
)


def parse_time(value):
    if isinstance(value, datetime):
        dt = value
    else:
        if not value:
            return None
        try:
            dt = datetime.fromisoformat(
                str(value).strip().replace("Z", "+00:00")
            )
        except (TypeError, ValueError):
            return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def normalize(value):
    if value is None:
        return ""
    return str(value).strip().lower()


def extract_identifiers(value):
    """Recursively extract values from known identity fields."""
    found = set()

    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in IDENTITY_FIELDS:
                if isinstance(item, (str, int, float)):
                    normalized = normalize(item)
                    if normalized:
                        found.add(normalized)

            if isinstance(item, (dict, list)):
                found.update(extract_identifiers(item))

    elif isinstance(value, list):
        for item in value:
            found.update(extract_identifiers(item))

    return found



def is_deletion_request(text):
    """
    Determine whether the message requests deletion.

    Reject only explicit cancellations or statements
    that no deletion is requested.

    An empty or ambiguous message is not automatically
    classified as NOT_APPLICABLE.
    """
    value = normalize(text)

    cancellation_patterns = (
        r"\bdo not delete\b",
        r"\bdon't delete\b",
        r"\bnot requesting deletion\b",
        r"\bnot a deletion request\b",
        r"\bkeep my account\b",
        r"\bcancel my deletion\b",
        r"\bwithdraw my deletion\b",
        r"\bstop my deletion\b",
    )

    if any(
        re.search(pattern, value)
        for pattern in cancellation_patterns
    ):
        return False

    # Include common privacy request language.
    request_patterns = (
        r"\bdelet(?:e|ion|ing)\b",
        r"\beras(?:e|ure|ing)\b",
        r"\bremov(?:e|al|ing)\b",
        r"\bforget\b",
        r"\bclose my account\b",
        r"\bpersonal data\b",
        r"\bprivacy request\b",
        r"\bdata subject request\b",
        r"\bright to be forgotten\b",
        r"\bpurge\b",
    )

    if any(
        re.search(pattern, value)
        for pattern in request_patterns
    ):
        return True

    # Ambiguous requests need review, not automatic
    # NOT_APPLICABLE classification.
    return True



def read_csv_rows(path):
    with open(path, newline="", encoding="utf-8-sig") as file:
        return list(csv.DictReader(file))


class GhostTraceAgent:

    def __init__(self):
        print("Loading GhostTrace components...", flush=True)

        self.resolver = IdentityResolver()
        self.mapper = ResourceMapper()
        self.planner = RemediationPlanner()

        self.requests = read_csv_rows(
            DATASET / "deletion_requests.csv"
        )

        # Build the unified evidence index only once.
        self.index = UnifiedEvidenceIndex()
        self.index.build()

        # Reuse the same index for state interpretation.
        self.state_engine = ResourceStateEngine.__new__(
            ResourceStateEngine
        )
        self.state_engine.index = self.index

        self.records = []
        self.by_resource = defaultdict(list)

        print("Preparing timestamp and identity indexes...", flush=True)

        for record in self.index.records:
            item = dict(record)

            item["_observed_dt"] = parse_time(
                item.get("observed_at")
            )
            item["_captured_dt"] = parse_time(
                item.get("captured_at")
            )
            item["_identity_values"] = extract_identifiers(
                item.get("data") or {}
            )

            self.records.append(item)

            resource_id = item.get("resource_id")
            if resource_id:
                self.by_resource[str(resource_id)].append(item)

        print(
            f"Indexed {len(self.records)} evidence observations.",
            flush=True
        )
        print(
            f"Loaded {len(self.requests)} deletion requests.",
            flush=True
        )

    @staticmethod
    def eligible(record, cutoff):
        observed = record["_observed_dt"]
        captured = record["_captured_dt"]

        return (
            cutoff is not None
            and observed is not None
            and captured is not None
            and observed <= cutoff
            and captured <= cutoff
        )

    @staticmethod
    def identity_values(identity):
        values = set()

        for key in (
            "user_id", "email", "phone", "email_hash"
        ):
            value = identity.get(key)
            if value:
                values.add(normalize(value))

        return values

    @staticmethod
    def category_for(record):
        category = str(
            record.get("category") or ""
        ).strip()

        if category.upper() in {
            "USER_PROFILE",
            "SECONDARY_IDENTIFIER",
            "SEARCH_INDEX_ENTRY",
            "CACHE_ENTRY",
            "SUPPORT_MESSAGE",
            "SUPPORT_ATTACHMENT",
            "ANALYTICS_PROFILE",
            "PRODUCT_TELEMETRY",
            "USER_EXPORT",
            "MARKETING_PROFILE",
            "EMAIL_DELIVERY_LOG",
            "SECURITY_AUDIT_LOG",
            "LEGAL_HOLD_RECORD",
            "BACKUP_ARCHIVE",
            "ACCOUNT_TOMBSTONE",
        }:
            return category.upper()

        source = str(
            record.get("source_table") or category
        ).lower()

        return CATEGORY_MAP.get(source, "")

    def observations_for(self, resource_id, cutoff):
        observations = []

        for record in self.by_resource.get(
            str(resource_id), []
        ):
            if not self.eligible(record, cutoff):
                continue

            observations.append({
                "evidence_id": record.get("evidence_id", ""),
                "format": record.get("evidence_format", ""),
                "system_id": record.get("system_id", ""),
                "resource_id": resource_id,
                "category": self.category_for(record),
                "state": self.state_engine.interpret_observation(
                    record
                ),
                "observed_at": record.get("observed_at", ""),
                "captured_at": record.get("captured_at", ""),
                "_observed_dt": record["_observed_dt"],
                "_captured_dt": record["_captured_dt"],
            })

        observations.sort(
            key=lambda x: (
                x["_observed_dt"],
                x["_captured_dt"],
                x["evidence_id"]
            )
        )
        return observations

    @staticmethod
    def choose_latest(observations):
        meaningful = [
            obs for obs in observations
            if obs["state"] != "UNKNOWN"
        ]
        return meaningful[-1] if meaningful else None

    def audit_request(self, request):
        case_id = request["case_id"]
        cutoff = parse_time(request["audit_at"])

        if not is_deletion_request(
            request["request_text"]
        ):
            return {
                "case_id": case_id,
                "deletion_status": "NOT_APPLICABLE",
                "steps_json": "[]",
                "diagnostic": "NON_DELETION_REQUEST",
                "resource_count": 0,
                "unresolved_count": 0,
            }

        identity = self.resolver.resolve_email(
            request["email"]
        )

        if not identity:
            return {
                "case_id": case_id,
                "deletion_status": "INCOMPLETE",
                "steps_json": "[]",
                "diagnostic": "IDENTITY_NOT_RESOLVED",
                "resource_count": 0,
                "unresolved_count": 1,
            }

        identity_set = self.identity_values(identity)
        resources = {}

        # Discover direct identity matches.
        for record in self.records:
            if not self.eligible(record, cutoff):
                continue

            if not (
                record["_identity_values"] & identity_set
            ):
                continue

            resource_id = record.get("resource_id")
            if not resource_id:
                continue

            resources.setdefault(
                str(resource_id),
                {
                    "category": self.category_for(record),
                    "system_id": record.get("system_id", ""),
                }
            )

        # Include operationally linked resources.
        linked = self.mapper.get_resources(
            identity["user_id"],
            request["audit_at"]
        )

        for item in linked:
            resource_id = item.get("resource_id")
            if resource_id:
                resources.setdefault(
                    str(resource_id),
                    {
                        "category": "",
                        "system_id": "",
                    }
                )

        steps = []
        unresolved = 0

        for resource_id, resource in resources.items():
            observations = self.observations_for(
                resource_id, cutoff
            )

            latest = self.choose_latest(observations)

            if latest is None:
                unresolved += 1
                continue

            state = latest["state"]
            system_id = (
                latest["system_id"]
                or resource["system_id"]
            )
            category = (
                latest["category"]
                or resource["category"]
            )
            evidence_id = latest["evidence_id"]

            if state in ("ACTIVE", "DISABLED"):
                planned = self.planner.plan_data_flow(
                    system_id,
                    resource_id,
                    state,
                    evidence_id
                )

            elif state in (
                "RESTORABLE", "RESTORE_BLOCKED"
            ):
                planned = self.planner.plan_restore(
                    system_id,
                    resource_id,
                    state,
                    evidence_id
                )

            else:
                planned = self.planner.plan_record(
                    system_id,
                    resource_id,
                    category,
                    state,
                    evidence_id
                )

            if not planned:
                unresolved += 1

            steps.extend(planned)

        steps = self.planner.finalize(steps)

        has_remediation = any(
            step["phase"] == "REMEDIATION"
            for step in steps
        )

        if has_remediation or unresolved or not resources:
            status = "INCOMPLETE"
        else:
            status = "COMPLETE"

        if not resources:
            unresolved += 1

        return {
            "case_id": case_id,
            "deletion_status": status,
            "steps_json": json.dumps(
                steps, separators=(",", ":")
            ),
            "diagnostic": (
                "UNRESOLVED_EVIDENCE"
                if unresolved
                else "PROCESSED"
            ),
            "resource_count": len(resources),
            "unresolved_count": unresolved,
        }

    def run(self):
        results = []
        diagnostics = []

        for number, request in enumerate(
            self.requests, 1
        ):
            result = self.audit_request(request)

            results.append({
                "case_id": result["case_id"],
                "deletion_status": result["deletion_status"],
                "steps_json": result["steps_json"],
            })

            diagnostics.append({
                "case_id": result["case_id"],
                "status": result["deletion_status"],
                "diagnostic": result["diagnostic"],
                "resource_count": result["resource_count"],
                "unresolved_count": result["unresolved_count"],
            })

            if number % 50 == 0 or number == len(
                self.requests
            ):
                print(
                    f"Processed {number}/{len(self.requests)} cases",
                    flush=True
                )

        results.sort(key=lambda row: row["case_id"])

        with OUTPUT.open(
            "w", newline="", encoding="utf-8"
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=[
                    "case_id",
                    "deletion_status",
                    "steps_json",
                ]
            )
            writer.writeheader()
            writer.writerows(results)

        with DIAGNOSTICS.open(
            "w", newline="", encoding="utf-8"
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=[
                    "case_id",
                    "status",
                    "diagnostic",
                    "resource_count",
                    "unresolved_count",
                ]
            )
            writer.writeheader()
            writer.writerows(diagnostics)

        print("\n" + "=" * 65)
        print("GHOSTTRACE - FULL DATASET RESULTS")
        print("=" * 65)
        print("TOTAL CASES:", len(results))

        print("\nSTATUS DISTRIBUTION:")
        counts = Counter(
            row["deletion_status"]
            for row in results
        )

        for status, count in sorted(counts.items()):
            print(f"{status}: {count}")

        print("\nOUTPUT:", OUTPUT)
        print("DIAGNOSTICS:", DIAGNOSTICS)
        print("\nPREDICTION GENERATION COMPLETE")


if __name__ == "__main__":
    agent = GhostTraceAgent()
    agent.run()
