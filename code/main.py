"""
Oblivara - AI-Powered Deletion Audit Agent
Main End-to-End Pipeline & Output Generator
Module: code.main

Orchestrates Phase 1 through Phase 4:
1. Identity Resolution (IdentityGraph)
2. Request Intent Classification (IntentClassifier)
3. Multi-System Evidence Ingestion & State Reconstruction (EvidenceEngine)
4. Policy Evaluation (PolicyEngine)
5. Dependency-Aware Remediation Planning (RemediationPlanner)
6. Output Generation & Validation (output.csv)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from code.evidence_engine import EvidenceEngine
from code.identity_resolution import IdentityGraph, ResolutionStatus
from code.intent_classifier import IntentClassifier, RequestIntent
from code.policy_engine import DeletionStatus, PolicyDecision, PolicyEngine
from code.remediation_planner import RemediationPlanner, RemediationStep


class OblivaraPipeline:
    """
    End-to-end deletion verification and remediation planning pipeline.
    """

    def __init__(self, dataset_dir: Path | str = PROJECT_ROOT / "dataset") -> None:
        self.dataset_dir = Path(dataset_dir)
        self.identities_csv = self.dataset_dir / "user_identities.csv"
        self.audit_log_csv = self.dataset_dir / "user_audit_log.csv"
        self.deletion_rules_csv = self.dataset_dir / "deletion_rules.csv"
        self.evidence_files_csv = self.dataset_dir / "evidence_files.csv"
        self.system_activity_csv = self.dataset_dir / "system_activity.csv"

        # Core engines
        self.identity_graph = IdentityGraph()
        self.intent_classifier = IntentClassifier()
        self.evidence_engine = EvidenceEngine(
            dataset_dir=self.dataset_dir,
        )
        self.policy_engine = PolicyEngine(rules_path=self.deletion_rules_csv)
        self.remediation_planner = RemediationPlanner()
        self._is_initialized = False

    def initialize(self, verbose: bool = True) -> None:
        """Loads and pre-indexes all identity graph, evidence, and rules."""
        if self._is_initialized:
            return

        if verbose:
            print("=" * 70)
            print("Oblivara Deletion Audit Agent — Initializing Knowledge Fabric")
            print("=" * 70)
            print("1. Loading Identity Graph (snapshots + historical mutations)...")
        self.identity_graph.load_from_csv(self.identities_csv, self.audit_log_csv)
        if verbose:
            print(f"   -> Loaded {len(self.identity_graph.users)} canonical user identities.")

        if verbose:
            print("2. Ingesting Multi-System Evidence Across 9 Services...")
        self.evidence_engine.ingest_all()
        if verbose:
            print(f"   -> Ingested {len(self.evidence_engine.all_evidence_records)} normalized evidence records.")
            print(f"   -> Loaded {len(self.evidence_engine.activity_stream)} system activity events.")

        self._is_initialized = True
        if verbose:
            print("Pipeline initialization complete.\n")

    def process_request(self, request_row: Dict[str, str]) -> Tuple[Dict[str, Any], PolicyDecision, List[RemediationStep]]:
        """
        Processes an individual deletion request row end-to-end.
        Returns: (output_row_dict, policy_decision, planned_steps)
        """
        if not self._is_initialized:
            self.initialize(verbose=False)

        case_id = request_row["case_id"].strip()
        email = request_row["email"].strip()
        req_text = request_row["request_text"].strip()
        requested_at = request_row["requested_at"].strip()
        reported_at = request_row["reported_at"].strip()
        audit_at = request_row["audit_at"].strip()

        # Step 1: Classify intent
        intent_res = self.intent_classifier.classify(case_id, req_text)

        # Step 2: Resolve canonical identity
        id_res = self.identity_graph.resolve_email(case_id, email)
        user_id = id_res.canonical_user_id
        identity = id_res.identity

        # If intent is not applicable, return early per contract §6.3
        if intent_res.intent == RequestIntent.NOT_APPLICABLE:
            decision = self.policy_engine.evaluate_request(
                case_id=case_id,
                email=email,
                audit_at=audit_at,
                user_id=user_id,
                identity=identity,
                intent_result=intent_res,
                audit_state=None,
            )
            output_row = {
                "case_id": case_id,
                "deletion_status": DeletionStatus.NOT_APPLICABLE.value,
                "steps_json": "[]",
            }
            return output_row, decision, []

        # Step 3: Reconstruct multi-system state at audit_at cutoff
        request_window = (requested_at, reported_at)
        audit_state = self.evidence_engine.reconstruct_user_state(
            user_id=user_id or f"unresolved_{case_id}",
            identity=identity,
            audit_at=audit_at,
            request_window=request_window,
        )

        # Step 4: Evaluate platform deletion rules
        decision = self.policy_engine.evaluate_request(
            case_id=case_id,
            email=email,
            audit_at=audit_at,
            user_id=user_id,
            identity=identity,
            intent_result=intent_res,
            audit_state=audit_state,
        )

        # Step 5: Dependency-aware remediation and verification planning
        steps = self.remediation_planner.plan(decision, audit_state)

        # Step 6: Serialize steps_json per competition contract §6.3
        serialized_steps = [s.to_dict() for s in steps]
        steps_json_str = json.dumps(serialized_steps, separators=(",", ":"))

        output_row = {
            "case_id": case_id,
            "deletion_status": decision.deletion_status.value,
            "steps_json": steps_json_str,
        }
        return output_row, decision, steps

    def run(
        self,
        requests_csv_path: Optional[Path | str] = None,
        output_csv_path: Optional[Path | str] = None,
        verbose: bool = True,
    ) -> Dict[str, Any]:
        """
        Executes the full pipeline across all input requests and atomically generates output.csv.
        """
        req_path = Path(requests_csv_path) if requests_csv_path else self.dataset_dir / "deletion_requests.csv"
        out_path = Path(output_csv_path) if output_csv_path else PROJECT_ROOT / "output.csv"

        self.initialize(verbose=verbose)

        if verbose:
            print("=" * 70)
            print(f"Executing Oblivara Audit Pipeline on {req_path.name}")
            print(f"Target Submission Output: {out_path}")
            print("=" * 70)

        with open(req_path, "r", encoding="utf-8") as f:
            requests = list(csv.DictReader(f))

        total_requests = len(requests)
        output_rows: List[Dict[str, str]] = []
        status_counts = {
            DeletionStatus.COMPLETE.value: 0,
            DeletionStatus.INCOMPLETE.value: 0,
            DeletionStatus.NOT_APPLICABLE.value: 0,
        }
        total_steps_generated = 0

        for idx, req in enumerate(requests, start=1):
            out_row, decision, steps = self.process_request(req)
            output_rows.append(out_row)
            status_counts[out_row["deletion_status"]] = status_counts.get(out_row["deletion_status"], 0) + 1
            total_steps_generated += len(steps)

            if verbose and (idx % 50 == 0 or idx == total_requests):
                print(f"  Processed [{idx}/{total_requests}] requests... (Last: {out_row['case_id']} -> {out_row['deletion_status']})")

        # Sort strictly by case_id per contract §6.3
        output_rows.sort(key=lambda r: r["case_id"])

        # Validate rows before writing
        self._validate_output_contract(output_rows, expected_count=total_requests)

        # Atomic file write
        temp_file = out_path.with_suffix(".tmp")
        with open(temp_file, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["case_id", "deletion_status", "steps_json"],
                quoting=csv.QUOTE_MINIMAL,
            )
            writer.writeheader()
            for r in output_rows:
                writer.writerow(r)

        # Atomic rename
        if out_path.exists():
            out_path.unlink()
        temp_file.rename(out_path)

        summary = {
            "total_requests": total_requests,
            "output_rows": len(output_rows),
            "status_distribution": status_counts,
            "total_steps_generated": total_steps_generated,
            "output_path": str(out_path),
        }

        if verbose:
            print("\n" + "=" * 70)
            print("Oblivara Audit Pipeline Execution Summary:")
            print(f"  Total Input Requests Processed: {summary['total_requests']}")
            print(f"  Total Valid Rows Written:      {summary['output_rows']}")
            print(f"  Status COMPLETE:               {status_counts[DeletionStatus.COMPLETE.value]}")
            print(f"  Status INCOMPLETE:             {status_counts[DeletionStatus.INCOMPLETE.value]}")
            print(f"  Status NOT_APPLICABLE:         {status_counts[DeletionStatus.NOT_APPLICABLE.value]}")
            print(f"  Total Remediation Steps:       {summary['total_steps_generated']}")
            print(f"  Target File:                   {summary['output_path']}")
            print("=" * 70 + "\n")

        return summary

    def _validate_output_contract(self, rows: List[Dict[str, str]], expected_count: int) -> None:
        """Validates that the generated records strictly conform to the competition contract."""
        if len(rows) != expected_count:
            raise ValueError(f"Output row count mismatch: got {len(rows)}, expected {expected_count}")

        seen_cases: Set[str] = set()
        allowed_statuses = {s.value for s in DeletionStatus}

        for idx, r in enumerate(rows, start=1):
            cid = r.get("case_id", "")
            if not cid:
                raise ValueError(f"Row {idx} missing mandatory case_id.")
            if cid in seen_cases:
                raise ValueError(f"Duplicate case_id detected: {cid}")
            seen_cases.add(cid)

            st = r.get("deletion_status", "")
            if st not in allowed_statuses:
                raise ValueError(f"Invalid deletion_status '{st}' in row {idx} ({cid}).")

            steps_str = r.get("steps_json", "")
            try:
                steps = json.loads(steps_str)
                if not isinstance(steps, list):
                    raise ValueError(f"steps_json must be a JSON array in row {idx} ({cid}).")
                if st == DeletionStatus.NOT_APPLICABLE.value and steps != []:
                    raise ValueError(f"NOT_APPLICABLE case {cid} must have empty steps_json [].")
                for s_idx, s in enumerate(steps, start=1):
                    if s.get("step_no") != s_idx:
                        raise ValueError(f"Step {s_idx} out of order in {cid}: {s.get('step_no')}")
            except Exception as e:
                raise ValueError(f"Malformed steps_json in row {idx} ({cid}): {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Oblivara Deletion Audit Agent")
    parser.add_argument("--dataset-dir", default=str(PROJECT_ROOT / "dataset"), help="Path to dataset directory")
    parser.add_argument("--requests-csv", default=None, help="Path to input deletion requests CSV")
    parser.add_argument("--output-csv", default=None, help="Path to target output.csv")
    parser.add_argument("--sample", action="store_true", help="Run on sample_deletion_requests.csv instead")
    args = parser.parse_args()

    pipeline = OblivaraPipeline(dataset_dir=args.dataset_dir)

    requests_path = args.requests_csv
    if args.sample and not requests_path:
        requests_path = Path(args.dataset_dir) / "sample_deletion_requests.csv"

    pipeline.run(
        requests_csv_path=requests_path,
        output_csv_path=args.output_csv,
        verbose=True,
    )


if __name__ == "__main__":
    main()
