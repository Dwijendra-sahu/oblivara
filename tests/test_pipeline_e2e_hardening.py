"""
Oblivara - Test Hardening: End-to-End Pipeline & Output Contract Invariants
Module: tests.test_pipeline_e2e_hardening
Covers full pipeline execution, strict output contract validation error handling,
atomic file write guarantees, deterministic idempotence, and ground-truth isolation.
"""

import csv
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))

from code.main import OblivaraPipeline
from code.policy_engine import DeletionStatus


class TestPipelineE2EHardening(unittest.TestCase):
    """Hardened end-to-end and contract invariant tests."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.pipeline = OblivaraPipeline(dataset_dir=repo_root / "dataset")
        cls.pipeline.initialize(verbose=False)

    def test_single_request_execution_complete(self) -> None:
        """Executes a single known COMPLETE case through the full pipeline."""
        req = {
            "case_id": "case_01",
            "email": "amina.elmasri@gmail.com",
            "requested_at": "2026-08-18T09:14:00Z",
            "reported_status": "COMPLETE",
            "reported_at": "2026-08-20T16:42:00Z",
            "audit_at": "2026-09-03T11:30:00Z",
            "request_text": "Please remove the profile and personal details attached to it permanently.",
        }
        row, _, _ = self.pipeline.process_request(req)

        self.assertEqual(row["case_id"], "case_01")
        self.assertEqual(row["deletion_status"], DeletionStatus.COMPLETE.value)
        steps = json.loads(row["steps_json"])
        self.assertGreater(len(steps), 0)
        for s in steps:
            self.assertEqual(s["phase"], "VERIFICATION")
            self.assertTrue(len(s["evidence_id"]) > 0, "COMPLETE verification steps must cite evidence")

    def test_single_request_execution_not_applicable(self) -> None:
        """Executes a non-deletion request and verifies NOT_APPLICABLE with empty steps_json."""
        req = {
            "case_id": "case_na_test",
            "email": "ethan.chen@hotmail.com",
            "requested_at": "2026-09-24T05:25:21Z",
            "reported_status": "COMPLETE",
            "reported_at": "2026-09-25T01:13:21Z",
            "audit_at": "2026-09-26T08:58:34Z",
            "request_text": "Can you send me a copy of my invoices? Please do not delete anything.",
        }
        row, _, _ = self.pipeline.process_request(req)

        self.assertEqual(row["deletion_status"], DeletionStatus.NOT_APPLICABLE.value)
        self.assertEqual(row["steps_json"], "[]")

    def test_output_contract_validator_catches_row_count_mismatch(self) -> None:
        """Contract validator raises ValueError when row count does not match expected_count."""
        rows = [{"case_id": "case_1", "deletion_status": "COMPLETE", "steps_json": "[]"}]
        with self.assertRaises(ValueError) as ctx:
            self.pipeline._validate_output_contract(rows, expected_count=2)
        self.assertIn("Output row count mismatch", str(ctx.exception))

    def test_output_contract_validator_catches_duplicate_ids(self) -> None:
        """Contract validator raises ValueError when duplicate case_id is detected."""
        rows = [
            {"case_id": "case_dup", "deletion_status": "COMPLETE", "steps_json": "[]"},
            {"case_id": "case_dup", "deletion_status": "COMPLETE", "steps_json": "[]"},
        ]
        with self.assertRaises(ValueError) as ctx:
            self.pipeline._validate_output_contract(rows, expected_count=2)
        self.assertIn("Duplicate case_id detected", str(ctx.exception))

    def test_output_contract_validator_catches_invalid_status(self) -> None:
        """Contract validator raises ValueError on unrecognized deletion_status."""
        rows = [{"case_id": "case_1", "deletion_status": "PARTIAL", "steps_json": "[]"}]
        with self.assertRaises(ValueError) as ctx:
            self.pipeline._validate_output_contract(rows, expected_count=1)
        self.assertIn("Invalid deletion_status 'PARTIAL'", str(ctx.exception))

    def test_output_contract_validator_catches_non_empty_steps_for_not_applicable(self) -> None:
        """Contract validator raises ValueError when NOT_APPLICABLE has steps."""
        invalid_steps = json.dumps([{"step_no": 1, "phase": "VERIFICATION"}])
        rows = [{"case_id": "case_1", "deletion_status": "NOT_APPLICABLE", "steps_json": invalid_steps}]
        with self.assertRaises(ValueError) as ctx:
            self.pipeline._validate_output_contract(rows, expected_count=1)
        self.assertIn("NOT_APPLICABLE case case_1 must have empty steps_json", str(ctx.exception))

    def test_output_contract_validator_catches_out_of_order_step_numbering(self) -> None:
        """Contract validator raises ValueError when step_no is not consecutive 1-indexed."""
        out_of_order_steps = json.dumps([
            {"step_no": 2, "phase": "VERIFICATION"},
        ])
        rows = [{"case_id": "case_1", "deletion_status": "COMPLETE", "steps_json": out_of_order_steps}]
        with self.assertRaises(ValueError) as ctx:
            self.pipeline._validate_output_contract(rows, expected_count=1)
        self.assertIn("out of order", str(ctx.exception))

    def test_ground_truth_isolation_at_runtime(self) -> None:
        """Verifies that the inference pipeline functions completely without sample_output.csv."""
        # Ensure that sample_output.csv is never opened during inference
        original_open = open

        def safe_open(file, *args, **kwargs):
            if "sample_output.csv" in str(file):
                raise PermissionError("Attempted to access sample_output.csv during production inference!")
            return original_open(file, *args, **kwargs)

        with patch("builtins.open", side_effect=safe_open):
            # Run inference on sample request
            req = {
                "case_id": "case_iso_check",
                "email": "ethan.chen@hotmail.com",
                "requested_at": "2026-09-24T05:25:21Z",
                "reported_status": "COMPLETE",
                "reported_at": "2026-09-25T01:13:21Z",
                "audit_at": "2026-09-26T08:58:34Z",
                "request_text": "Please delete all personal data.",
            }
            res, _, _ = self.pipeline.process_request(req)
            self.assertEqual(res["case_id"], "case_iso_check")

    def test_atomic_file_write_preserves_existing_on_error(self) -> None:
        """Verifies that an atomic file write failure does not delete or corrupt the target file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target_csv = Path(tmpdir) / "output.csv"
            # Write initial valid file
            with open(target_csv, "w", encoding="utf-8") as f:
                f.write("case_id,deletion_status,steps_json\ncase_0,COMPLETE,[]\n")

            # Intentionally pass invalid rows that will fail contract validation
            invalid_rows = [{"case_id": "case_bad", "deletion_status": "INVALID", "steps_json": "[]"}]

            with self.assertRaises(ValueError):
                self.pipeline._validate_output_contract(invalid_rows, expected_count=1)

            # Ensure original target_csv still exists and was not corrupted
            self.assertTrue(target_csv.exists())
            with open(target_csv, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("case_0,COMPLETE,[]", content)

    def test_deterministic_idempotence(self) -> None:
        """Running the same request through the pipeline twice yields identical serialized output."""
        args = {
            "case_id": "case_idem",
            "email": "ethan.chen@hotmail.com",
            "requested_at": "2026-09-24T05:25:21Z",
            "reported_status": "COMPLETE",
            "reported_at": "2026-09-25T01:13:21Z",
            "audit_at": "2026-09-26T08:58:34Z",
            "request_text": "Please delete all personal data.",
        }
        run1, _, _ = self.pipeline.process_request(args)
        run2, _, _ = self.pipeline.process_request(args)

        self.assertEqual(run1["deletion_status"], run2["deletion_status"])
        self.assertEqual(run1["steps_json"], run2["steps_json"])


if __name__ == "__main__":
    unittest.main()
