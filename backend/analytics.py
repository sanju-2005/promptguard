"""Live analytics for the PromptGuard evaluation dataset."""

import time

from backend.detector import detect_sensitive_data
from backend.injection_detector import detect_prompt_injection
from backend.risk_analyzer import analyze_risk
from backend.decision_engine import make_security_decision
from evaluation.evaluation import EVALUATION_DATASET


def percentage(numerator, denominator):
    """Return a percentage, or None when undefined."""
    if denominator == 0:
        return None
    return round(numerator / denominator * 100, 2)


def binary_metrics(expected, predicted):
    """Calculate confusion-matrix and classification metrics."""
    tp = sum(e and p for e, p in zip(expected, predicted))
    tn = sum(not e and not p for e, p in zip(expected, predicted))
    fp = sum(not e and p for e, p in zip(expected, predicted))
    fn = sum(e and not p for e, p in zip(expected, predicted))

    return {
        "tp": int(tp),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "accuracy": percentage(tp + tn, len(expected)),
        "precision": percentage(tp, tp + fp),
        "recall": percentage(tp, tp + fn),
        "false_positive_rate": percentage(fp, fp + tn),
    }


def build_analytics_report():
    """Evaluate the current dataset and build a dashboard report."""
    cases = []
    expected_sensitive = []
    predicted_sensitive = []
    expected_injection = []
    predicted_injection = []
    latencies = []
    decision_counts = {
        "ALLOW": 0,
        "SANITIZE": 0,
        "BLOCK": 0,
    }
    matched_decisions = 0

    for case in EVALUATION_DATASET:
        started = time.perf_counter()

        detected = detect_sensitive_data(case["prompt"])
        injection = detect_prompt_injection(case["prompt"])

        risk = analyze_risk(
            detected,
            injection.get("categories", []),
        )
        decision = make_security_decision(risk)

        latency_ms = (time.perf_counter() - started) * 1000
        latencies.append(latency_ms)

        sensitive_found = bool(detected)
        injection_found = bool(injection.get("detected", False))
        actual_decision = decision.get("action", "UNKNOWN")
        expected_decision = case["decision"]
        matched = actual_decision == expected_decision

        expected_sensitive.append(bool(case["sensitive"]))
        predicted_sensitive.append(sensitive_found)
        expected_injection.append(bool(case["injection"]))
        predicted_injection.append(injection_found)

        if actual_decision in decision_counts:
            decision_counts[actual_decision] += 1

        matched_decisions += int(matched)

        cases.append({
            "name": case["name"],
            "expected_decision": expected_decision,
            "actual_decision": actual_decision,
            "decision_match": matched,
            "sensitive_expected": bool(case["sensitive"]),
            "sensitive_detected": sensitive_found,
            "injection_expected": bool(case["injection"]),
            "injection_detected": injection_found,
            "latency_ms": round(latency_ms, 2),
        })

    total = len(EVALUATION_DATASET)

    return {
        "dataset_size": total,
        "sensitive_metrics": binary_metrics(
            expected_sensitive, predicted_sensitive
        ),
        "injection_metrics": binary_metrics(
            expected_injection, predicted_injection
        ),
        "decision_agreement": percentage(matched_decisions, total),
        "decisions_matched": matched_decisions,
        "decision_counts": decision_counts,
        "average_latency_ms": (
            round(sum(latencies) / len(latencies), 2)
            if latencies else 0
        ),
        "maximum_latency_ms": round(max(latencies), 2) if latencies else 0,
        "cases": cases,
        "limitations": [
            "Results reflect only the current labelled test dataset.",
            "Latency excludes external LLM inference.",
            "Results do not establish real-world security performance.",
        ],
    }