"""
Offline validation test suite.
Validates the IdentityGraph and IntentClassifier across the actual dataset files
WITHOUT ever loading or exposing sample_output.csv to inference.
"""

import csv
import sys
import unittest
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))

from code.identity_resolution import (
    IdentityGraph,
    ResolutionStatus,
    ResolutionConfidence
)
from code.intent_classifier import (
    IntentClassifier,
    RequestIntent,
    IntentCategory
)


class TestOfflineValidation(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.graph = IdentityGraph()
        cls.graph.load_from_csv(
            repo_root / "dataset" / "user_identities.csv",
            repo_root / "dataset" / "user_audit_log.csv"
        )
        cls.classifier = IntentClassifier()

    def test_01_development_sample_requests_resolution(self) -> None:
        """Validates identity resolution on all 32 sample requests without sample_output.csv."""
        sample_path = repo_root / "dataset" / "sample_deletion_requests.csv"
        with open(sample_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            samples = list(reader)

        self.assertEqual(len(samples), 32)
        resolved_count = 0
        historical_resolved_count = 0

        for row in samples:
            cid = row["case_id"]
            email = row["email"]
            res = self.graph.resolve_email(cid, email)

            self.assertEqual(
                res.status,
                ResolutionStatus.RESOLVED,
                f"Failed to resolve sample case {cid} ({email})"
            )
            self.assertIsNotNone(res.canonical_user_id)
            resolved_count += 1
            if res.confidence == ResolutionConfidence.HISTORICAL_AUDIT:
                historical_resolved_count += 1

        self.assertEqual(resolved_count, 32, "All 32 sample requests should resolve cleanly")
        self.assertGreater(historical_resolved_count, 0, "Should resolve multiple historical mutations")

    def test_02_development_sample_requests_intent(self) -> None:
        """Validates that all 32 sample requests are recognized as valid deletion authorizations."""
        sample_path = repo_root / "dataset" / "sample_deletion_requests.csv"
        with open(sample_path, "r", encoding="utf-8") as f:
            samples = list(csv.DictReader(f))

        for row in samples:
            cid = row["case_id"]
            txt = row["request_text"]
            res = self.classifier.classify(cid, txt)
            self.assertEqual(
                res.intent,
                RequestIntent.DELETION_REQUESTED,
                f"Sample case {cid} incorrectly classified as {res.intent}: {txt}"
            )
            self.assertTrue(res.requires_audit)

    def test_03_full_eval_set_resolution_and_intent(self) -> None:
        """Validates all 518 evaluation requests without hardcoding customer data."""
        eval_path = repo_root / "dataset" / "deletion_requests.csv"
        with open(eval_path, "r", encoding="utf-8") as f:
            eval_requests = list(csv.DictReader(f))

        self.assertEqual(len(eval_requests), 518)

        resolved_count = 0
        current_resolved = 0
        historical_resolved = 0
        unresolved_cases = []

        deletion_count = 0
        not_applicable_count = 0
        ambiguous_intent_cases = []

        for row in eval_requests:
            cid = row["case_id"]
            email = row["email"]
            txt = row["request_text"]

            # Identity resolution
            id_res = self.graph.resolve_email(cid, email)
            if id_res.status == ResolutionStatus.RESOLVED:
                resolved_count += 1
                if id_res.confidence == ResolutionConfidence.CURRENT_PRIMARY:
                    current_resolved += 1
                elif id_res.confidence == ResolutionConfidence.HISTORICAL_AUDIT:
                    historical_resolved += 1
            else:
                unresolved_cases.append((cid, email, id_res.status, id_res.warnings))

            # Intent classification
            intent_res = self.classifier.classify(cid, txt)
            if intent_res.intent == RequestIntent.DELETION_REQUESTED:
                deletion_count += 1
            elif intent_res.intent == RequestIntent.NOT_APPLICABLE:
                not_applicable_count += 1
            else:
                ambiguous_intent_cases.append((cid, txt))

        # Assertions
        self.assertEqual(resolved_count, 518, f"Unresolved cases found: {unresolved_cases}")
        self.assertEqual(len(unresolved_cases), 0)
        self.assertEqual(len(ambiguous_intent_cases), 0, f"Ambiguous intents: {ambiguous_intent_cases}")
        self.assertEqual(not_applicable_count, 10, "Expected exactly 10 NOT_APPLICABLE cases")
        self.assertEqual(deletion_count, 508, "Expected exactly 508 DELETION_REQUESTED cases")


if __name__ == "__main__":
    unittest.main()
