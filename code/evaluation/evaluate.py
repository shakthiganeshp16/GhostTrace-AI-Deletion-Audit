
import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "code"))

from generate_predictions import GhostTraceAgent


ALLOWED_STATUSES = {
    "COMPLETE",
    "INCOMPLETE",
    "NOT_APPLICABLE"
}

REQUIRED_FIELDS = {
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id"
}

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


def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as file:
        return list(csv.DictReader(file))


def validate_row(row):
    errors = []

    if row["deletion_status"] not in ALLOWED_STATUSES:
        errors.append("INVALID_STATUS")

    try:
        steps = json.loads(row["steps_json"])
    except (ValueError, TypeError):
        return ["INVALID_JSON"]

    if not isinstance(steps, list):
        return ["STEPS_NOT_ARRAY"]

    if (
        row["deletion_status"] == "NOT_APPLICABLE"
        and steps
    ):
        errors.append("NON_APPLICABLE_HAS_STEPS")

    if (
        row["deletion_status"] == "COMPLETE"
        and any(
            step.get("phase") != "VERIFICATION"
            for step in steps
            if isinstance(step, dict)
        )
    ):
        errors.append("COMPLETE_HAS_NON_VERIFICATION")

    previous_key = None

    for number, step in enumerate(steps, 1):
        if not isinstance(step, dict):
            errors.append("INVALID_STEP")
            continue

        if set(step) != REQUIRED_FIELDS:
            errors.append("WRONG_STEP_FIELDS")
            continue

        if step["step_no"] != number:
            errors.append("WRONG_STEP_NUMBER")

        phase = step["phase"]
        operation = step["operation"]

        if phase not in PHASE_ORDER:
            errors.append("INVALID_PHASE")

        if operation not in OPERATION_ORDER:
            errors.append("INVALID_OPERATION")

        if (
            phase not in PHASE_ORDER
            or operation not in OPERATION_ORDER
        ):
            continue

        key = (
            PHASE_ORDER[phase],
            OPERATION_ORDER[operation],
            str(step["system_id"]),
            str(step["resource_id"])
        )

        if previous_key is not None and key < previous_key:
            errors.append("WRONG_STEP_ORDER")

        previous_key = key

        if (
            phase == "REMEDIATION"
            and step["evidence_id"] != ""
        ):
            errors.append("REMEDIATION_HAS_EVIDENCE")

    return sorted(set(errors))


def canonical_step(step):
    return tuple(
        (key, json.dumps(step.get(key), sort_keys=True))
        for key in sorted(REQUIRED_FIELDS)
    )


def evaluate_sample(agent):
    requests = read_csv(
        ROOT / "dataset/sample_deletion_requests.csv"
    )

    expected_rows = {
        row["case_id"]: row
        for row in read_csv(
            ROOT / "dataset/sample_output.csv"
        )
    }

    comparisons = []
    status_correct = 0
    exact_sequence_correct = 0

    predicted_step_total = 0
    expected_step_total = 0
    matched_steps = 0

    field_matches = 0
    field_total = 0

    for request in requests:
        case_id = request["case_id"]

        predicted = agent.audit_request(request)
        expected = expected_rows[case_id]

        predicted_steps = json.loads(
            predicted["steps_json"]
        )
        expected_steps = json.loads(
            expected["steps_json"]
        )

        status_match = (
            predicted["deletion_status"]
            == expected["deletion_status"]
        )

        sequence_match = (
            predicted_steps == expected_steps
        )

        status_correct += int(status_match)
        exact_sequence_correct += int(sequence_match)

        pred_counts = Counter(
            canonical_step(step)
            for step in predicted_steps
        )
        exp_counts = Counter(
            canonical_step(step)
            for step in expected_steps
        )

        matched_steps += sum(
            (pred_counts & exp_counts).values()
        )

        predicted_step_total += len(predicted_steps)
        expected_step_total += len(expected_steps)

        # Positional field agreement, reported separately
        # from exact step matching.
        for p, e in zip(
            predicted_steps, expected_steps
        ):
            for field in REQUIRED_FIELDS:
                field_total += 1
                field_matches += int(
                    p.get(field) == e.get(field)
                )

        comparisons.append({
            "case_id": case_id,
            "expected_status": expected["deletion_status"],
            "predicted_status": predicted["deletion_status"],
            "status_correct": status_match,
            "exact_sequence_correct": sequence_match,
            "expected_steps": len(expected_steps),
            "predicted_steps": len(predicted_steps),
            "unresolved_count": predicted["unresolved_count"]
        })

    count = len(requests)

    precision = (
        matched_steps / predicted_step_total
        if predicted_step_total else 0
    )

    recall = (
        matched_steps / expected_step_total
        if expected_step_total else 0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0
    )

    return {
        "comparisons": comparisons,
        "status_accuracy": status_correct / count,
        "sequence_accuracy": exact_sequence_correct / count,
        "step_precision": precision,
        "step_recall": recall,
        "step_f1": f1,
        "positional_field_accuracy": (
            field_matches / field_total
            if field_total else 0
        ),
        "matched_steps": matched_steps,
        "predicted_steps": predicted_step_total,
        "expected_steps": expected_step_total
    }


def main():
    print("=" * 65)
    print("GHOSTTRACE - EVALUATION")
    print("=" * 65)

    output_path = ROOT / "output.csv"
    rows = read_csv(output_path)

    print("\nFULL OUTPUT VALIDATION")
    print("ROWS:", len(rows))

    if len(rows) != 518:
        print("ERROR: Expected 518 rows")

    invalid = []

    for row in rows:
        errors = validate_row(row)
        if errors:
            invalid.append(
                (row["case_id"], errors)
            )

    print("INVALID CASES:", len(invalid))

    for case_id, errors in invalid[:10]:
        print(case_id, ":", errors)

    print("\nRUNNING SAMPLE EVALUATION")

    agent = GhostTraceAgent()
    metrics = evaluate_sample(agent)

    print("\n" + "=" * 65)
    print("SAMPLE METRICS")
    print("=" * 65)

    for key in (
        "status_accuracy",
        "sequence_accuracy",
        "step_precision",
        "step_recall",
        "step_f1",
        "positional_field_accuracy"
    ):
        print(
            f"{key}: {metrics[key] * 100:.2f}%"
        )

    print(
        "MATCHED STEPS:",
        metrics["matched_steps"]
    )
    print(
        "PREDICTED STEPS:",
        metrics["predicted_steps"]
    )
    print(
        "EXPECTED STEPS:",
        metrics["expected_steps"]
    )

    print("\nSAMPLE CASE COMPARISON")

    for item in metrics["comparisons"]:
        print(
            item["case_id"],
            "| expected:", item["expected_status"],
            "| predicted:", item["predicted_status"],
            "| steps:", item["predicted_steps"],
            "/", item["expected_steps"]
        )

    report_dir = ROOT / "code/evaluation"
    report_dir.mkdir(
        parents=True, exist_ok=True
    )

    report = report_dir / "sample_comparison.csv"

    with report.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=list(
                metrics["comparisons"][0].keys()
            )
        )
        writer.writeheader()
        writer.writerows(
            metrics["comparisons"]
        )

    print("\nCOMPARISON SAVED:", report)
    print("\nEVALUATION COMPLETE")


if __name__ == "__main__":
    main()
