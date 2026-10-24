"""
Unit tests for code.identity_resolution
Covers all required identity resolution cases including synthetic edge fixtures.
"""

import sys
import unittest
from pathlib import Path
import tempfile
import csv

# Add repo root to path
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))

from code.identity_resolution import (
    IdentityGraph,
    IdentifierType,
    ResolutionStatus,
    ResolutionConfidence,
    normalize_identifier,
)


class TestIdentityResolution(unittest.TestCase):

    def setUp(self) -> None:
        self.graph = IdentityGraph()
        self.user_identities_csv = repo_root / "dataset" / "user_identities.csv"
        self.user_audit_log_csv = repo_root / "dataset" / "user_audit_log.csv"
        self.graph.load_from_csv(self.user_identities_csv, self.user_audit_log_csv)

    def test_01_current_email_resolves_to_correct_user(self) -> None:
        """Requirement 1: Current email resolving to the correct user."""
        res = self.graph.resolve_email("test_req_01", "amina.elmasri@gmail.com")
        self.assertEqual(res.status, ResolutionStatus.RESOLVED)
        self.assertEqual(res.confidence, ResolutionConfidence.CURRENT_PRIMARY)
        self.assertEqual(res.canonical_user_id, "user_01")
        self.assertIsNotNone(res.identity)
        self.assertIn("user_identities.csv:user_01", res.provenance_chain)

    def test_02_historical_email_resolves_through_audit_mutation(self) -> None:
        """Requirement 2: Historical email resolving through a documented field mutation."""
        # user_10 has historical email nadia.ionescu@yahoo.com (from audit log), current is nadia.ionescu@gmail.com
        res = self.graph.resolve_email("test_req_02", "nadia.ionescu@yahoo.com")
        self.assertEqual(res.status, ResolutionStatus.RESOLVED)
        self.assertEqual(res.confidence, ResolutionConfidence.HISTORICAL_AUDIT)
        self.assertEqual(res.canonical_user_id, "user_10")
        self.assertIsNotNone(res.identity)
        self.assertTrue(any("user_audit_log.csv" in p for p in res.provenance_chain))

    def test_03_unknown_identifier_returns_unresolved(self) -> None:
        """Requirement 3: Unknown identifiers."""
        res = self.graph.resolve_email("test_req_03", "nonexistent.ghost.user.99999@domain.org")
        self.assertEqual(res.status, ResolutionStatus.UNRESOLVED)
        self.assertEqual(res.confidence, ResolutionConfidence.NONE)
        self.assertIsNone(res.canonical_user_id)
        self.assertTrue(len(res.warnings) > 0)

    def test_04_duplicate_conflicting_identifiers(self) -> None:
        """Requirement 4: Duplicate identifiers with conflicting ownership."""
        # Create a synthetic graph with conflicting email ownership
        with tempfile.TemporaryDirectory() as tmpdir:
            u_path = Path(tmpdir) / "users.csv"
            a_path = Path(tmpdir) / "audit.csv"

            # Two users with different current emails
            with open(u_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["user_id", "name", "email", "phone", "email_hash", "updated_at"])
                writer.writerow(["u_A", "Alice Smith", "alice.current@test.org", "+1 555 0101", "hash_a", "2026-01-01T00:00:00Z"])
                writer.writerow(["u_B", "Bob Jones", "bob.current@test.org", "+1 555 0102", "hash_b", "2026-01-01T00:00:00Z"])

            # Bob historically claimed alice.current@test.org
            with open(a_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"])
                writer.writerow(["audit_conflict", "u_B", "2025-05-01T00:00:00Z", "email", "alice.current@test.org", "bob.current@test.org"])

            synth_graph = IdentityGraph()
            synth_graph.load_from_csv(u_path, a_path)

            res = synth_graph.resolve_email("conflict_req", "alice.current@test.org")
            self.assertEqual(res.status, ResolutionStatus.AMBIGUOUS)
            self.assertEqual(res.confidence, ResolutionConfidence.CONFLICTING_OWNERSHIP)
            self.assertIsNone(res.canonical_user_id)
            self.assertTrue(any("Conflicting email ownership" in w for w in res.warnings))

    def test_05_multiple_historical_mutations_for_single_user(self) -> None:
        """Requirement 5: Multiple historical mutations for one user."""
        with tempfile.TemporaryDirectory() as tmpdir:
            u_path = Path(tmpdir) / "users.csv"
            a_path = Path(tmpdir) / "audit.csv"

            with open(u_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["user_id", "name", "email", "phone", "email_hash", "updated_at"])
                writer.writerow(["u_C", "Charlie Brown", "charlie.v3@test.org", "+1 555 0103", "hash_c", "2026-03-01T00:00:00Z"])

            with open(a_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"])
                writer.writerow(["aud_1", "u_C", "2025-01-01T00:00:00Z", "email", "charlie.v1@test.org", "charlie.v2@test.org"])
                writer.writerow(["aud_2", "u_C", "2025-06-01T00:00:00Z", "email", "charlie.v2@test.org", "charlie.v3@test.org"])

            synth_graph = IdentityGraph()
            synth_graph.load_from_csv(u_path, a_path)

            # Both v1 and v2 should resolve to u_C
            res1 = synth_graph.resolve_email("req_v1", "charlie.v1@test.org")
            res2 = synth_graph.resolve_email("req_v2", "charlie.v2@test.org")
            res3 = synth_graph.resolve_email("req_v3", "charlie.v3@test.org")

            self.assertEqual(res1.canonical_user_id, "u_C")
            self.assertEqual(res2.canonical_user_id, "u_C")
            self.assertEqual(res3.canonical_user_id, "u_C")
            self.assertEqual(res1.confidence, ResolutionConfidence.HISTORICAL_AUDIT)
            self.assertEqual(res3.confidence, ResolutionConfidence.CURRENT_PRIMARY)

    def test_06_shared_names_do_not_merge_users(self) -> None:
        """Requirement 6: Shared names that must not merge different users."""
        # Verified earlier: 'mateo rios', 'thandiwe ndlovu', 'gabriel costa' appear for multiple users
        thandiwe_users = self.graph.name_index.get("thandiwe ndlovu", set())
        self.assertGreaterEqual(len(thandiwe_users), 2, "Expected multiple users with name Thandiwe Ndlovu")

        # Resolving via email should uniquely identify the right user despite shared name
        for uid in thandiwe_users:
            user = self.graph.users[uid]
            res = self.graph.resolve_email("test_name_split", user.current_email.val_raw)
            self.assertEqual(res.status, ResolutionStatus.RESOLVED)
            self.assertEqual(res.canonical_user_id, uid)
            self.assertTrue(any("shares full name" in w for w in res.warnings))

    def test_07_normalization_preserves_raw_and_trims_whitespace(self) -> None:
        """Case insensitivity and whitespace handling."""
        res = self.graph.resolve_email("test_ws", "   AMINA.ELMASRI@GMAIL.COM  \n")
        self.assertEqual(res.status, ResolutionStatus.RESOLVED)
        self.assertEqual(res.canonical_user_id, "user_01")
        self.assertEqual(res.matched_record.val_normalized, "amina.elmasri@gmail.com")
        self.assertEqual(res.input_identifier, "   AMINA.ELMASRI@GMAIL.COM  \n")

    def test_08_missing_and_malformed_records(self) -> None:
        """Requirement 9: Missing or malformed identity records."""
        # Empty string
        res = self.graph.resolve_email("test_empty", "")
        self.assertEqual(res.status, ResolutionStatus.UNRESOLVED)
        self.assertEqual(res.confidence, ResolutionConfidence.NONE)

        # Missing input file raises error
        with self.assertRaises(FileNotFoundError):
            g = IdentityGraph()
            g.load_from_csv("nonexistent_users.csv", "nonexistent_audit.csv")

    def test_09_deterministic_and_reproducible_resolution(self) -> None:
        """Requirement 10: Reproducibility and deterministic results."""
        email = "amina.elmasri@gmail.com"
        first_run = self.graph.resolve_email("rep_1", email).to_dict()
        for i in range(20):
            subsequent_run = self.graph.resolve_email(f"rep_{i}", email).to_dict()
            subsequent_run["request_id"] = "rep_1"
            self.assertEqual(first_run, subsequent_run)


if __name__ == "__main__":
    unittest.main()
