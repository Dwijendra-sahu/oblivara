"""
Oblivara - Test Hardening: Evidence Parsing & State Reconstruction Edge Cases
Module: tests.test_evidence_state_hardening
Covers Phase 3 hardening: temporal cutoff enforcement, cross-user isolation,
tie-breaking logic, and resilience to corrupted/empty files.
"""

import sys
import tempfile
import unittest
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))

from code.evidence_engine import EvidenceEngine
from code.evidence_models import (
    NormalizedEvidenceRecord,
    OperationalState,
    ResourceStateSnapshot,
    SystemID,
    UserSystemAuditState,
)
from code.evidence_parsers import (
    DocumentParser,
    ImageMetadataParser,
    LogParser,
    SQLSnapshotParser,
    StructuredRecordParser,
)
from code.identity_resolution import CanonicalIdentity, IdentifierRecord, IdentifierType


class TestEvidenceStateHardening(unittest.TestCase):
    """Hardened edge-case tests for parsers and state reconstruction."""

    def test_strict_temporal_cutoff_quarantine(self) -> None:
        """Verifies that evidence observed strictly after audit_at is quarantined and never influences state."""
        cutoff = "2026-09-15T12:00:00Z"
        after_cutoff = "2026-09-15T12:00:01Z"
        before_cutoff = "2026-09-15T11:59:59Z"

        email = IdentifierRecord.create("target@example.com", IdentifierType.EMAIL, "identities")
        u = CanonicalIdentity(user_id="user_target", current_email=email)

        # Record before cutoff: PRESENT
        rec_before = NormalizedEvidenceRecord(
            evidence_id="ev_valid",
            source_file="logs/test.log",
            source_system="account_service",
            source_record_id="line_1",
            captured_at=before_cutoff,
            observed_at=before_cutoff,
            record_type="USER_PROFILE",
            system_id="account_service",
            resource_id="account_101",
            user_id="user_target",
            operational_state=OperationalState.PRESENT,
        )

        # Record after cutoff: ABSENT (simulating a future deletion)
        rec_after = NormalizedEvidenceRecord(
            evidence_id="ev_future",
            source_file="logs/test.log",
            source_system="account_service",
            source_record_id="line_2",
            captured_at=after_cutoff,
            observed_at=after_cutoff,
            record_type="USER_PROFILE",
            system_id="account_service",
            resource_id="account_101",
            user_id="user_target",
            operational_state=OperationalState.ABSENT,
        )

        engine = EvidenceEngine(dataset_dir=repo_root / "dataset")
        # Ingest candidates directly
        engine.all_evidence_records = [rec_before, rec_after]
        engine.by_user_id["user_target"] = [rec_before, rec_after]
        engine.by_resource_id["account_101"] = [rec_before, rec_after]

        audit_state = engine.reconstruct_user_state(
            user_id="user_target",
            identity=u,
            audit_at=cutoff,
        )

        # The future event must be in post_cutoff_evidence_ignored
        self.assertIn(rec_after, audit_state.post_cutoff_evidence_ignored)
        # Snapshot at cutoff must be PRESENT
        snap = audit_state.resources.get("account_101")
        self.assertIsNotNone(snap)
        self.assertEqual(snap.operational_state, OperationalState.PRESENT)
        self.assertEqual(snap.primary_evidence_id, "ev_valid")

    def test_concurrent_worker_cross_user_isolation(self) -> None:
        """Verifies that an unrelated user's activity appearing during concurrent execution is isolated."""
        e_target = IdentifierRecord.create("target@example.com", IdentifierType.EMAIL, "identities")
        u_target = CanonicalIdentity(user_id="user_target", current_email=e_target)

        # Target record
        rec_target = NormalizedEvidenceRecord(
            evidence_id="ev_t",
            source_file="logs/app.log",
            source_system="account_service",
            source_record_id="1",
            captured_at="2026-09-15T10:00:00Z",
            observed_at="2026-09-15T10:00:00Z",
            record_type="USER_PROFILE",
            system_id="account_service",
            resource_id="account_target_01",
            user_id="user_target",
            operational_state=OperationalState.PRESENT,
        )

        # Unrelated user's record
        rec_other = NormalizedEvidenceRecord(
            evidence_id="ev_o",
            source_file="logs/app.log",
            source_system="account_service",
            source_record_id="2",
            captured_at="2026-09-15T10:00:05Z",
            observed_at="2026-09-15T10:00:05Z",
            record_type="SEARCH_INDEX_ENTRY",
            system_id="search_service",
            resource_id="search_unrelated_99",
            user_id="user_other",
            operational_state=OperationalState.PRESENT,
        )

        engine = EvidenceEngine(dataset_dir=repo_root / "dataset")
        engine.all_evidence_records = [rec_target, rec_other]
        engine.by_user_id["user_target"] = [rec_target]
        engine.by_user_id["user_other"] = [rec_other]

        audit_state = engine.reconstruct_user_state(
            user_id="user_target",
            identity=u_target,
            audit_at="2026-09-15T12:00:00Z",
        )

        all_res_ids = set(audit_state.resources.keys())
        self.assertIn("account_target_01", all_res_ids)
        self.assertNotIn("search_unrelated_99", all_res_ids)

    def test_query_start_vs_completion_tie_break(self) -> None:
        """When lookup_started and lookup_completed rows=0 occur at the exact same timestamp, ABSENT wins."""
        ts = "2026-09-15T12:00:00Z"
        rec_start = NormalizedEvidenceRecord(
            evidence_id="ev_01",
            source_file="logs/app.log",
            source_system="account_service",
            source_record_id="1",
            captured_at=ts,
            observed_at=ts,
            record_type="profile_lookup_started",
            system_id="account_service",
            resource_id="account_999",
            operational_state=OperationalState.PRESENT,
        )
        rec_complete = NormalizedEvidenceRecord(
            evidence_id="ev_02",
            source_file="logs/app.log",
            source_system="account_service",
            source_record_id="2",
            captured_at=ts,
            observed_at=ts,
            record_type="profile_lookup_completed",
            system_id="account_service",
            resource_id="account_999",
            operational_state=OperationalState.ABSENT,
        )

        engine = EvidenceEngine(dataset_dir=repo_root / "dataset")
        snap = engine._evaluate_resource_snapshot(
            system_id="account_service",
            resource_id="account_999",
            records=[rec_start, rec_complete],
            identity=None,
            audit_at="2026-09-15T13:00:00Z",
        )

        self.assertIsNotNone(snap)
        self.assertEqual(snap.operational_state, OperationalState.ABSENT)
        self.assertEqual(snap.primary_evidence_id, "ev_02")

    def test_corrupted_and_empty_sql_resilience(self) -> None:
        """SQLSnapshotParser safely parses empty or syntactically invalid SQL content."""
        parser = SQLSnapshotParser()
        with tempfile.TemporaryDirectory() as tmpdir:
            empty_file = Path(tmpdir) / "empty.sql"
            empty_file.write_text("", encoding="utf-8")
            res_empty = parser.parse_file(empty_file, file_id="ev_sql_empty", origin="test", captured_at="2026-09-01T00:00:00Z")
            self.assertEqual(res_empty, [])

            bad_file = Path(tmpdir) / "corrupt.sql"
            bad_file.write_text("THIS IS NOT VALID SQL; INSERT INTO table VALUES (;;;);", encoding="utf-8")
            res_corrupt = parser.parse_file(bad_file, file_id="ev_sql_bad", origin="test", captured_at="2026-09-01T00:00:00Z")
            self.assertEqual(res_corrupt, [])

    def test_malformed_json_resilience(self) -> None:
        """StructuredRecordParser safely handles truncated or malformed JSON exports."""
        parser = StructuredRecordParser()
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_json = Path(tmpdir) / "bad.json"
            bad_json.write_text('{"records": [{"id": 1, "status": "active"', encoding="utf-8")
            res = parser.parse_file(bad_json, file_id="ev_json_bad", origin="test", captured_at="2026-09-01T00:00:00Z")
            self.assertEqual(res, [])

    def test_pdf_decompression_error_handling(self) -> None:
        """DocumentParser gracefully handles non-PDF or corrupt binary streams without crashing."""
        parser = DocumentParser()
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_pdf = Path(tmpdir) / "bad.pdf"
            bad_pdf.write_bytes(b"\x00\xff\xfe\x01\x44\x32\x99")
            res = parser.parse_file(bad_pdf, file_id="ev_pdf_bad", origin="test", captured_at="2026-09-01T00:00:00Z")
            self.assertEqual(res, [])


if __name__ == "__main__":
    unittest.main()
