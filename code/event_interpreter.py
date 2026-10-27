
import pandas as pd

from resource_state_analyzer import ResourceStateAnalyzer


class EventInterpreter:

    ACTION_EVENTS = {
        "DELETE_RECORD": "DELETE",
        "REDACT_RECORD": "REDACT",
        "ANONYMIZE_RECORD": "ANONYMIZE",
        "RETAIN_RECORD": "RETAIN",
        "BLOCK_RESTORE": "BLOCK_RESTORE",
        "DISABLE_DATA_FLOW": "DISABLE_DATA_FLOW"
    }

    def interpret(self, event):

        event_type = str(event["event_type"]).upper()
        result = str(event["reported_result"]).upper()
        details = str(event["details"]).lower()

        interpretation = {
            "activity_id": event["activity_id"],
            "resource_id": event["resource_id"],
            "event_time": event["event_time"],
            "event_type": event_type,
            "reported_result": result,
            "signal": "UNKNOWN",
            "confirmed_absence": False
        }

        if event_type in self.ACTION_EVENTS:

            action = self.ACTION_EVENTS[event_type]

            if result == "SUCCESS":
                interpretation["signal"] = (
                    action + "_SUCCEEDED"
                )

            elif result == "FAILED":
                interpretation["signal"] = (
                    action + "_FAILED"
                )

            elif result == "PARTIAL":
                interpretation["signal"] = (
                    action + "_PARTIAL"
                )

        elif event_type == "CHECK_DATA_FLOW":

            if "remains enabled" in details:
                interpretation["signal"] = "FLOW_ENABLED"

            elif (
                "disabled" in details
                or "no longer enabled" in details
            ):
                interpretation["signal"] = "FLOW_DISABLED"

        elif event_type == "CHECK_RESTORE_ACCESS":

            if (
                "can still be restored" in details
                or "restore remains allowed" in details
            ):
                interpretation["signal"] = "RESTORE_ALLOWED"

            elif (
                "restore access blocked" in details
                or "cannot be restored" in details
            ):
                interpretation["signal"] = "RESTORE_BLOCKED"

        elif event_type == "RESTORE_BACKUP":

            if result == "SUCCESS":
                interpretation["signal"] = (
                    "RESOURCE_RESTORED"
                )

        elif event_type == "CREATE_EXPORT":

            if result == "SUCCESS":
                interpretation["signal"] = (
                    "EXPORT_CREATED"
                )

        elif event_type == "INDEX_RECORD":

            if result == "SUCCESS":
                interpretation["signal"] = (
                    "INDEX_WRITTEN"
                )

        elif event_type == "REFRESH_CACHE":

            if result == "SUCCESS":
                interpretation["signal"] = (
                    "CACHE_REFRESHED"
                )

        elif event_type == "SYNC_RECORD":

            if result == "SUCCESS":
                interpretation["signal"] = (
                    "RECORD_SYNCED"
                )

        elif event_type == "UPDATE_RECORD":

            if result == "SUCCESS":
                interpretation["signal"] = (
                    "RECORD_UPDATED"
                )

        return interpretation

    def interpret_history(self, history):

        interpretations = []

        for _, event in history.iterrows():
            interpretations.append(
                self.interpret(event)
            )

        return interpretations


def main():

    print("=" * 65)
    print("GHOSTTRACE - EVENT INTERPRETER")
    print("=" * 65)

    analyzer = ResourceStateAnalyzer()
    interpreter = EventInterpreter()

    activities = analyzer.activities

    selected_types = [
        "DELETE_RECORD",
        "REDACT_RECORD",
        "ANONYMIZE_RECORD",
        "CHECK_DATA_FLOW",
        "CHECK_RESTORE_ACCESS",
        "BLOCK_RESTORE",
        "DISABLE_DATA_FLOW",
        "RESTORE_BACKUP"
    ]

    print("\nEVENT INTERPRETATION EXAMPLES")

    for event_type in selected_types:

        matching = activities[
            activities["event_type"] == event_type
        ]

        if matching.empty:
            continue

        event = matching.iloc[0]

        interpreted = interpreter.interpret(event)

        print("\nEVENT:", event_type)
        print("ACTIVITY:", interpreted["activity_id"])
        print("RESOURCE:", interpreted["resource_id"])
        print("RESULT:", interpreted["reported_result"])
        print("SIGNAL:", interpreted["signal"])

    print("\n" + "=" * 65)
    print("CASE 33 TEMPORAL CHECK")
    print("=" * 65)

    audit_at = "2026-07-19T13:00:00Z"

    for resource_id in ["export_1260", "export_1842"]:

        history = analyzer.get_history(
            resource_id,
            audit_at
        )

        signals = interpreter.interpret_history(history)

        print("\nRESOURCE:", resource_id)

        for signal in signals:
            print(
                signal["event_time"],
                "|",
                signal["event_type"],
                "|",
                signal["signal"]
            )

    print("\nEVENT INTERPRETATION COMPLETE")


if __name__ == "__main__":
    main()
