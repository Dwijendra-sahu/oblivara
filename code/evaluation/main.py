"""
Oblivara - Offline Evaluation Runner
Module: code.evaluation.main

Runs local benchmarks against sample datasets and validates ground truth metrics
without ever exposing ground truth to production inference modules.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from code.main import OblivaraPipeline


def evaluate_offline(
    dataset_dir: str | Path = PROJECT_ROOT / "dataset",
    verbose: bool = True,
) -> Dict[str, Any]:
    dataset_path = Path(dataset_dir)
    sample_requests_csv = dataset_path / "sample_deletion_requests.csv"
    sample_output_csv = dataset_path / "sample_output.csv"

    if verbose:
        print("=" * 70)
        print("Oblivara — Offline Evaluation Benchmark (Ground-Truth Isolated)")
        print("=" * 70)

    # 1. Run inference pipeline on sample requests ONLY
    pipeline = OblivaraPipeline(dataset_dir=dataset_path)
    pipeline.initialize(verbose=False)

    with open(sample_requests_csv, "r", encoding="utf-8") as f:
        sample_requests = list(csv.DictReader(f))

    predictions: Dict[str, Dict[str, Any]] = {}
    for req in sample_requests:
        cid = req["case_id"]
        out_row, decision, steps = pipeline.process_request(req)
        predictions[cid] = {
            "status": out_row["deletion_status"],
            "steps": json.loads(out_row["steps_json"]),
            "decision": decision,
        }

    # 2. Load ground truth outputs (OFFLINE EVALUATOR ONLY)
    with open(sample_output_csv, "r", encoding="utf-8") as f:
        ground_truth = {
            r["case_id"]: {
                "status": r["deletion_status"],
                "steps": json.loads(r["steps_json"]),
            }
            for r in csv.DictReader(f)
        }

    # 3. Compute benchmark metrics
    total_cases = len(sample_requests)
    status_matches = 0
    exact_step_matches = 0
    phase_order_matches = 0
    remediation_order_matches = 0

    per_case_results = []

    for req in sample_requests:
        cid = req["case_id"]
        pred = predictions[cid]
        truth = ground_truth[cid]

        pred_status = pred["status"]
        true_status = truth["status"]
        status_ok = (pred_status == true_status)
        if status_ok:
            status_matches += 1

        pred_steps = pred["steps"]
        true_steps = truth["steps"]

        # Step-level comparison
        steps_ok = False
        if len(pred_steps) == len(true_steps):
            mismatch = False
            for ps, ts in zip(pred_steps, true_steps):
                if (
                    ps.get("phase") != ts.get("phase")
                    or ps.get("system_id") != ts.get("system_id")
                    or ps.get("resource_id") != ts.get("resource_id")
                    or ps.get("operation") != ts.get("operation")
                    or ps.get("state") != ts.get("state")
                ):
                    mismatch = True
                    break
            if not mismatch:
                steps_ok = True
                exact_step_matches += 1

        # Phase sequence check
        pred_phases = [s.get("phase") for s in pred_steps]
        seen_phases = []
        for p in pred_phases:
            if not seen_phases or seen_phases[-1] != p:
                seen_phases.append(p)
        if pred_status == "COMPLETE" and (seen_phases == ["VERIFICATION"] or seen_phases == []):
            phase_order_matches += 1
        elif pred_status == "INCOMPLETE" and seen_phases == ["FINDING", "REMEDIATION", "VERIFICATION"]:
            phase_order_matches += 1
        elif pred_status == "NOT_APPLICABLE" and seen_phases == []:
            phase_order_matches += 1

        per_case_results.append({
            "case_id": cid,
            "predicted_status": pred_status,
            "expected_status": true_status,
            "status_match": status_ok,
            "pred_steps_count": len(pred_steps),
            "expected_steps_count": len(true_steps),
            "exact_steps_match": steps_ok,
        })

    status_accuracy = status_matches / total_cases if total_cases else 0.0

    metrics = {
        "total_sample_cases": total_cases,
        "status_matches": status_matches,
        "status_accuracy": status_accuracy,
        "phase_sequence_matches": phase_order_matches,
        "phase_sequence_accuracy": phase_order_matches / total_cases if total_cases else 0.0,
        "exact_step_matches": exact_step_matches,
        "per_case_results": per_case_results,
    }

    if verbose:
        print(f"Sample Cases Evaluated:           {total_cases}")
        print(f"Deletion Status Accuracy:         {status_accuracy * 100:.1f}% ({status_matches}/{total_cases})")
        print(f"Phase Sequence Validity:          {metrics['phase_sequence_accuracy'] * 100:.1f}% ({phase_order_matches}/{total_cases})")
        print("=" * 70)

        # Print failures if any
        failures = [r for r in per_case_results if not r["status_match"]]
        if failures:
            print("\nStatus Discrepancies:")
            for f in failures:
                print(f"  [{f['case_id']}] Predicted={f['predicted_status']}, Expected={f['expected_status']}")
        else:
            print("\nAll 32 sample cases matched expected deletion status!")

    return metrics


if __name__ == "__main__":
    evaluate_offline()
