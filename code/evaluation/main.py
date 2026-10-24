"""
Oblivara - Evaluation Runner
Module: code.evaluation.main

Runs local benchmarks against sample datasets and validates ground truth metrics
without ever exposing ground truth to inference modules.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from code.identity_resolution import IdentityGraph, ResolutionStatus
from code.intent_classifier import IntentClassifier, RequestIntent


def evaluate_phase2(
    dataset_dir: str | Path = PROJECT_ROOT / "dataset",
    verbose: bool = True
) -> dict:
    dataset_path = Path(dataset_dir)
    sample_requests_csv = dataset_path / "sample_deletion_requests.csv"
    sample_output_csv = dataset_path / "sample_output.csv"
    identities_csv = dataset_path / "user_identities.csv"
    audit_log_csv = dataset_path / "user_audit_log.csv"

    if verbose:
        print("=" * 60)
        print("Oblivara - Local Development Evaluation (Phase 2)")
        print("=" * 60)

    # Load Identity Graph
    graph = IdentityGraph()
    graph.load_from_csv(identities_csv, audit_log_csv)

    # Load Classifier
    classifier = IntentClassifier()

    # Load Sample Requests (inference input only)
    with open(sample_requests_csv, "r", encoding="utf-8") as f:
        sample_requests = list(csv.DictReader(f))

    # Load Ground Truth Outputs (OFFLINE BENCHMARK ONLY)
    with open(sample_output_csv, "r", encoding="utf-8") as f:
        ground_truth = {r["case_id"]: r["deletion_status"] for r in csv.DictReader(f)}

    # Evaluate Resolution & Intent
    correct_intent_classifications = 0
    resolved_identities = 0

    for req in sample_requests:
        cid = req["case_id"]
        email = req["email"]
        text = req["request_text"]

        # Resolution check
        res = graph.resolve_email(cid, email)
        if res.status == ResolutionStatus.RESOLVED:
            resolved_identities += 1

        # Intent check
        intent_res = classifier.classify(cid, text)
        expected_status = ground_truth.get(cid)

        # In sample_output.csv, all 32 cases are COMPLETE or INCOMPLETE (meaning deletion was requested)
        if expected_status in ("COMPLETE", "INCOMPLETE"):
            if intent_res.intent == RequestIntent.DELETION_REQUESTED:
                correct_intent_classifications += 1
        elif expected_status == "NOT_APPLICABLE":
            if intent_res.intent == RequestIntent.NOT_APPLICABLE:
                correct_intent_classifications += 1

    total = len(sample_requests)
    metrics = {
        "sample_cases": total,
        "resolved_identities": resolved_identities,
        "resolution_accuracy": resolved_identities / total if total else 0.0,
        "intent_accuracy": correct_intent_classifications / total if total else 0.0,
    }

    if verbose:
        print(f"Sample Cases Evaluated:       {metrics['sample_cases']}")
        print(f"Identity Resolution Accuracy: {metrics['resolution_accuracy'] * 100:.1f}% ({resolved_identities}/{total})")
        print(f"Request Intent Accuracy:      {metrics['intent_accuracy'] * 100:.1f}% ({correct_intent_classifications}/{total})")
        print("=" * 60)

    return metrics


if __name__ == "__main__":
    evaluate_phase2()
