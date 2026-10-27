
import csv
import json
from pathlib import Path


class RemediationPlanner:

    PHASE_ORDER = {
        "FINDING": 0,
        "REMEDIATION": 1,
        "VERIFICATION": 2
    }

    OPERATION_ORDER = {
        "REPORT_REMAINING_RECORD": 0,
        "REPORT_EXPOSED_PII": 1,
        "REPORT_ACTIVE_DATA_FLOW": 2,
        "REPORT_RESTORE_RISK": 3,
        "DISABLE_DATA_FLOW": 4,
        "BLOCK_RESTORE": 5,
        "DELETE_RECORD": 6,
        "REDACT_RECORD": 7,
        "ANONYMIZE_RECORD": 8,
        "VERIFY_RECORD_ABSENT": 9,
        "VERIFY_RECORD_PRESENT": 10,
        "VERIFY_RECORD_REDACTED": 11,
        "VERIFY_RECORD_ANONYMIZED": 12,
        "VERIFY_DATA_FLOW_DISABLED": 13,
        "VERIFY_RESTORE_BLOCKED": 14
    }

    POLICY_OPERATIONS = {
        "DELETE": (
            "REPORT_REMAINING_RECORD",
            "DELETE_RECORD",
            "VERIFY_RECORD_ABSENT",
            "PRESENT",
            "ABSENT"
        ),
        "REDACT": (
            "REPORT_EXPOSED_PII",
            "REDACT_RECORD",
            "VERIFY_RECORD_REDACTED",
            "PRESENT",
            "REDACTED"
        ),
        "ANONYMIZE": (
            "REPORT_EXPOSED_PII",
            "ANONYMIZE_RECORD",
            "VERIFY_RECORD_ANONYMIZED",
            "PRESENT",
            "ANONYMIZED"
        )
    }

    def __init__(self):

        self.rules = {}

        path = Path("dataset/deletion_rules.csv")

        with path.open(
            newline="",
            encoding="utf-8-sig"
        ) as file:

            for row in csv.DictReader(file):

                category = row.get(
                    "data_category", ""
                ).strip().upper()

                action = row.get(
                    "required_action", ""
                ).strip().upper()

                if category and action:
                    self.rules[category] = action

    @staticmethod
    def make_step(
        phase,
        system_id,
        resource_id,
        operation,
        state,
        evidence_id=""
    ):

        return {
            "step_no": 0,
            "phase": phase,
            "system_id": system_id,
            "resource_id": resource_id,
            "operation": operation,
            "state": state,
            "evidence_id": evidence_id
        }

    def plan_record(
        self,
        system_id,
        resource_id,
        category,
        observed_state,
        evidence_id=""
    ):

        category = str(category).upper()
        state = str(observed_state).upper()

        action = self.rules.get(category)

        if action is None:
            return []

        # A policy-required retained record must remain.
        if action == "RETAIN":

            if state == "PRESENT" and evidence_id:

                return [
                    self.make_step(
                        "VERIFICATION",
                        system_id,
                        resource_id,
                        "VERIFY_RECORD_PRESENT",
                        "PRESENT",
                        evidence_id
                    )
                ]

            return []

        if action not in self.POLICY_OPERATIONS:
            return []

        (
            finding_operation,
            remediation_operation,
            verification_operation,
            finding_state,
            desired_state
        ) = self.POLICY_OPERATIONS[action]

        # Already compliant: cite the proof.
        if state == desired_state and evidence_id:

            return [
                self.make_step(
                    "VERIFICATION",
                    system_id,
                    resource_id,
                    verification_operation,
                    desired_state,
                    evidence_id
                )
            ]

        # An absent record satisfies deletion policy.
        if action == "DELETE" and state == "ABSENT":

            return []

        # Unknown is not proof of noncompliance.
        # Return no steps until evidence is resolved.
        if state == "UNKNOWN":
            return []

        if state != finding_state:
            return []

        return [
            self.make_step(
                "FINDING",
                system_id,
                resource_id,
                finding_operation,
                finding_state,
                evidence_id
            ),
            self.make_step(
                "REMEDIATION",
                system_id,
                resource_id,
                remediation_operation,
                desired_state,
                ""
            ),
            self.make_step(
                "VERIFICATION",
                system_id,
                resource_id,
                verification_operation,
                desired_state,
                ""
            )
        ]

    def plan_data_flow(
        self,
        system_id,
        resource_id,
        state,
        evidence_id=""
    ):

        state = str(state).upper()

        if state == "DISABLED" and evidence_id:

            return [
                self.make_step(
                    "VERIFICATION",
                    system_id,
                    resource_id,
                    "VERIFY_DATA_FLOW_DISABLED",
                    "DISABLED",
                    evidence_id
                )
            ]

        if state != "ACTIVE":
            return []

        return [
            self.make_step(
                "FINDING",
                system_id,
                resource_id,
                "REPORT_ACTIVE_DATA_FLOW",
                "ACTIVE",
                evidence_id
            ),
            self.make_step(
                "REMEDIATION",
                system_id,
                resource_id,
                "DISABLE_DATA_FLOW",
                "DISABLED",
                ""
            ),
            self.make_step(
                "VERIFICATION",
                system_id,
                resource_id,
                "VERIFY_DATA_FLOW_DISABLED",
                "DISABLED",
                ""
            )
        ]

    def plan_restore(
        self,
        system_id,
        resource_id,
        state,
        evidence_id=""
    ):

        state = str(state).upper()

        if state == "RESTORE_BLOCKED" and evidence_id:

            return [
                self.make_step(
                    "VERIFICATION",
                    system_id,
                    resource_id,
                    "VERIFY_RESTORE_BLOCKED",
                    "BLOCKED",
                    evidence_id
                )
            ]

        if state != "RESTORABLE":
            return []

        return [
            self.make_step(
                "FINDING",
                system_id,
                resource_id,
                "REPORT_RESTORE_RISK",
                "ACTIVE",
                evidence_id
            ),
            self.make_step(
                "REMEDIATION",
                system_id,
                resource_id,
                "BLOCK_RESTORE",
                "BLOCKED",
                ""
            ),
            self.make_step(
                "VERIFICATION",
                system_id,
                resource_id,
                "VERIFY_RESTORE_BLOCKED",
                "BLOCKED",
                ""
            )
        ]

    def finalize(self, steps):

        unique = {}

        for step in steps:

            key = (
                step["phase"],
                step["system_id"],
                step["resource_id"],
                step["operation"],
                step["state"]
            )

            if key not in unique:
                unique[key] = step.copy()

            elif (
                not unique[key]["evidence_id"]
                and step["evidence_id"]
            ):
                unique[key] = step.copy()

        ordered = sorted(
            unique.values(),
            key=lambda step: (
                self.PHASE_ORDER[step["phase"]],
                self.OPERATION_ORDER[step["operation"]],
                step["system_id"],
                step["resource_id"]
            )
        )

        for number, step in enumerate(ordered, 1):
            step["step_no"] = number

        return ordered


def main():

    print("=" * 65)
    print("GHOSTTRACE - REMEDIATION PLANNER")
    print("=" * 65)

    planner = RemediationPlanner()

    print("\nPOLICY RULES LOADED:", len(planner.rules))

    print("\nPOLICY ACTIONS:")
    for category, action in sorted(
        planner.rules.items()
    ):
        print(category, "->", action)

    steps = []

    # Synthetic test resources, not case answers.
    steps.extend(
        planner.plan_record(
            "account_service",
            "test_account",
            "USER_PROFILE",
            "PRESENT",
            "test_evidence_01"
        )
    )

    steps.extend(
        planner.plan_record(
            "analytics_service",
            "test_analytics",
            "ANALYTICS_PROFILE",
            "PRESENT",
            "test_evidence_02"
        )
    )

    steps.extend(
        planner.plan_record(
            "security_service",
            "test_audit",
            "SECURITY_AUDIT_LOG",
            "PRESENT",
            "test_evidence_03"
        )
    )

    steps.extend(
        planner.plan_data_flow(
            "sync_service",
            "test_connector",
            "ACTIVE",
            "test_evidence_04"
        )
    )

    steps.extend(
        planner.plan_restore(
            "backup_service",
            "test_backup",
            "RESTORABLE",
            "test_evidence_05"
        )
    )

    steps = planner.finalize(steps)

    print("\n" + "=" * 65)
    print("GENERATED STEPS")
    print("=" * 65)

    print(
        json.dumps(
            steps,
            indent=2
        )
    )

    print("\nTOTAL STEPS:", len(steps))
    print("\nREMEDIATION PLANNER TEST COMPLETE")


if __name__ == "__main__":
    main()
