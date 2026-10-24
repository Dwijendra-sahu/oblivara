"""
Oblivara - AI-Powered Deletion Audit Agent
Main Pipeline Entry Point
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from code.identity_resolution import IdentityGraph, ResolutionStatus
from code.intent_classifier import IntentClassifier, RequestIntent


def run_pipeline(
    dataset_dir: str | Path = PROJECT_ROOT / "dataset",
    verbose: bool = True
) -> dict:
    dataset_path = Path(dataset_dir)
    identities_csv = dataset_path / "user_identities.csv"
    audit_log_csv = dataset_path / "user_audit_log.csv"
    requests_csv = dataset_path / "deletion_requests.csv"

    if verbose:
        print("=" * 60)
        print("Oblivara - Deletion Audit Pipeline (Phase 2)")
        print("=" * 60)
        print(f"Loading identity graph from {identities_csv.name} & {audit_log_csv.name}...")

    # 1. Initialize and load Identity Graph
    graph = IdentityGraph()
    graph.load_from_csv(identities_csv, audit_log_csv)
    if verbose:
        print(f"Loaded {len(graph.users)} user identities.")

    # 2. Initialize Intent Classifier
    classifier = IntentClassifier()

    # 3. Process requests
    if verbose:
        print(f"Processing requests from {requests_csv.name}...")

    with open(requests_csv, "r", encoding="utf-8") as f:
        requests = list(csv.DictReader(f))

    resolved_count = 0
    deletion_intent_count = 0
    not_applicable_count = 0
    ambiguous_intent_count = 0

    for req in requests:
        cid = req["case_id"]
        email = req["email"]
        text = req["request_text"]

        id_res = graph.resolve_email(cid, email)
        if id_res.status == ResolutionStatus.RESOLVED:
            resolved_count += 1

        intent_res = classifier.classify(cid, text)
        if intent_res.intent == RequestIntent.DELETION_REQUESTED:
            deletion_intent_count += 1
        elif intent_res.intent == RequestIntent.NOT_APPLICABLE:
            not_applicable_count += 1
        else:
            ambiguous_intent_count += 1

    summary = {
        "total_requests": len(requests),
        "identities_resolved": resolved_count,
        "resolution_rate": resolved_count / len(requests) if requests else 0.0,
        "deletion_intents": deletion_intent_count,
        "not_applicable_intents": not_applicable_count,
        "ambiguous_intents": ambiguous_intent_count,
    }

    if verbose:
        print("\nPhase 2 Audit Pipeline Summary:")
        print(f"  Total Requests Processed:     {summary['total_requests']}")
        print(f"  Identities Resolved:          {summary['identities_resolved']} ({summary['resolution_rate'] * 100:.1f}%)")
        print(f"  Authorized Deletion Requests: {summary['deletion_intents']}")
        print(f"  Not Applicable (Non-Deletion):{summary['not_applicable_intents']}")
        print(f"  Ambiguous Requests:           {summary['ambiguous_intents']}")
        print("=" * 60)

    return summary


if __name__ == "__main__":
    run_pipeline()
