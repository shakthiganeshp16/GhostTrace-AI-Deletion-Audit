
from pathlib import Path
import pandas as pd


class PolicyEngine:

    def __init__(self, dataset_dir="dataset"):

        self.dataset = Path(dataset_dir)

        self.rules = pd.read_csv(
            self.dataset / "deletion_rules.csv",
            dtype=str,
            keep_default_na=False
        )

        self.rule_index = {}

        for _, row in self.rules.iterrows():

            category = row["data_category"].strip().upper()

            self.rule_index[category] = {
                "rule_id": row["rule_id"],
                "category": category,
                "condition": row["condition"],
                "required_action": row["required_action"]
            }

    def get_rule(self, category):

        category = str(category).strip().upper()

        return self.rule_index.get(category)

    def evaluate(self, category, context=None):

        context = context or {}

        rule = self.get_rule(category)

        if rule is None:
            return {
                "category": category,
                "action": "UNKNOWN",
                "applicable": None,
                "reason": "No matching deletion rule"
            }

        action = rule["required_action"]
        condition = rule["condition"]

        # Unconditional policies.
        if condition.strip().casefold() == "always":

            return {
                "category": rule["category"],
                "rule_id": rule["rule_id"],
                "action": action,
                "applicable": True,
                "reason": "Unconditional policy"
            }

        # Conditional policies must be evaluated
        # using actual evidence, not assumptions.
        condition_fields = {
            "SUPPORT_MESSAGE": "shared_context",
            "SUPPORT_ATTACHMENT": "subject_only",
            "ANALYTICS_PROFILE": "attributable",
            "PRODUCT_TELEMETRY": "attributable",
            "EMAIL_DELIVERY_LOG": "contains_email",
            "SECURITY_AUDIT_LOG": "within_retention",
            "LEGAL_HOLD_RECORD": "legal_hold_active",
            "BACKUP_ARCHIVE": "restore_access_blockable",
            "ACCOUNT_TOMBSTONE": "account_deleted"
        }

        field = condition_fields.get(rule["category"])

        if field is None or field not in context:

            return {
                "category": rule["category"],
                "rule_id": rule["rule_id"],
                "action": action,
                "applicable": None,
                "reason": "Condition requires evidence"
            }

        value = context[field]

        if not isinstance(value, bool):

            return {
                "category": rule["category"],
                "rule_id": rule["rule_id"],
                "action": action,
                "applicable": None,
                "reason": "Condition must be a boolean"
            }

        # Tombstone also requires that only a stable
        # internal user ID is needed.
        if rule["category"] == "ACCOUNT_TOMBSTONE":

            stable_only = context.get("stable_user_id_only")

            if not isinstance(stable_only, bool):

                return {
                    "category": rule["category"],
                    "rule_id": rule["rule_id"],
                    "action": action,
                    "applicable": None,
                    "reason": "Stable-ID requirement not established"
                }

            value = value and stable_only

        return {
            "category": rule["category"],
            "rule_id": rule["rule_id"],
            "action": action,
            "applicable": value,
            "reason": (
                "Condition satisfied"
                if value
                else "Condition not satisfied"
            )
        }


def main():

    engine = PolicyEngine()

    print("=" * 60)
    print("GHOSTTRACE - DELETION POLICY ENGINE")
    print("=" * 60)

    print("\nLOADED RULES:", len(engine.rule_index))

    print("\nUNCONDITIONAL RULE TEST")

    result = engine.evaluate("USER_PROFILE")

    print(result)

    print("\nCONDITIONAL RULE TEST")

    result = engine.evaluate(
        "ANALYTICS_PROFILE",
        {"attributable": True}
    )

    print(result)

    print("\nRETENTION RULE TEST")

    result = engine.evaluate(
        "SECURITY_AUDIT_LOG",
        {"within_retention": True}
    )

    print(result)

    print("\nMISSING EVIDENCE TEST")

    result = engine.evaluate("BACKUP_ARCHIVE")

    print(result)

    print("\nPOLICY ENGINE TEST COMPLETE")


if __name__ == "__main__":
    main()
