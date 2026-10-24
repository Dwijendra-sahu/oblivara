"""
Oblivara - Phase 3 Test Suite: Evidence Parsers
File: tests/test_evidence_parsers.py

Validates parsing logic, error handling, malformed payloads,
and format-specific nuances for all supported evidence types:
SQL, JSON, TXT, LOG, PDF, and PNG.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from code.evidence_models import OperationalState, SystemID
from code.evidence_parsers import (
    DocumentParser,
    ImageMetadataParser,
    LogParser,
    SQLSnapshotParser,
    StructuredRecordParser,
    _infer_system_from_resource,
    _normalize_iso_timestamp,
)


class TestEvidenceParsers(unittest.TestCase):

    def setUp(self) -> None:
        self.dataset_dir = Path("dataset")

    def test_01_sql_parser_in_memory_execution(self) -> None:
        """Verifies SQLSnapshotParser creates isolated in-memory tables and extracts rows."""
        sql_path = self.dataset_dir / "evidence/databases/customer_accounts_failover_replica_20260902.sql"
        if not sql_path.exists():
            self.skipTest("Evidence database file not found")

        records = SQLSnapshotParser.parse_file(
            file_path=sql_path,
            file_id="evidence_54",
            origin="customer_account_failover_replica_capture",
            captured_at="2026-09-02T23:00:00Z"
        )
        self.assertGreater(len(records), 0)
        # Verify Leila Haddad (user_05) is present in failover replica
        leila_records = [r for r in records if r.user_id == "user_05" or r.resource_id == "account_005"]
        self.assertEqual(len(leila_records), 1)
        self.assertEqual(leila_records[0].operational_state, OperationalState.PRESENT)
        self.assertEqual(leila_records[0].system_id, SystemID.ACCOUNT_SERVICE.value)

    def test_02_sql_parser_malformed_syntax_resilience(self) -> None:
        """Verifies SQLSnapshotParser safely handles malformed SQL without crashing."""
        with tempfile.NamedTemporaryFile("w", suffix=".sql", delete=False, encoding="utf-8") as tf:
            tf.write("CREATE TABLE broken (id INT; INSERT INTO broken VALUES (1);")
            temp_path = tf.name

        try:
            records = SQLSnapshotParser.parse_file(
                file_path=temp_path,
                file_id="test_malformed_sql",
                origin="test_origin",
                captured_at="2026-09-01T00:00:00Z"
            )
            self.assertEqual(records, [])
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_03_structured_json_parser_snapshot_bundles(self) -> None:
        """Verifies StructuredRecordParser extracts multi-collection snapshot bundles."""
        json_path = self.dataset_dir / "evidence/records/customer_data_snapshot_bundle_20260915.json"
        if not json_path.exists():
            self.skipTest("Snapshot bundle not found")

        records = StructuredRecordParser.parse_file(
            file_path=json_path,
            file_id="evidence_51",
            origin="records_assurance_snapshot_bundle",
            captured_at="2026-09-15T12:00:00Z"
        )
        self.assertGreater(len(records), 0)

        # Check tombstone_440 (redacted) vs tombstone_9178 (exposed PII)
        t440 = next((r for r in records if r.resource_id == "tombstone_440"), None)
        self.assertIsNotNone(t440)
        self.assertEqual(t440.operational_state, OperationalState.REDACTED)

        t9178 = next((r for r in records if r.resource_id == "tombstone_9178"), None)
        self.assertIsNotNone(t9178)
        self.assertEqual(t9178.operational_state, OperationalState.PRESENT)

    def test_04_structured_txt_handover_report(self) -> None:
        """Verifies StructuredRecordParser parses pipe-delimited shift handover reports."""
        txt_path = self.dataset_dir / "evidence/records/customer_account_handover_20261001.txt"
        if not txt_path.exists():
            self.skipTest("TXT handover report not found")

        records = StructuredRecordParser.parse_file(
            file_path=txt_path,
            file_id="evidence_03",
            origin="customer_account_service",
            captured_at="2026-10-01T12:00:00Z"
        )
        self.assertGreater(len(records), 0)
        r0 = records[0]
        self.assertEqual(r0.system_id, SystemID.ACCOUNT_SERVICE.value)
        self.assertEqual(r0.operational_state, OperationalState.ABSENT)

    def test_05_log_parser_trace_correlation(self) -> None:
        """Verifies LogParser correlates distributed traces across multi-line logs."""
        log_path = self.dataset_dir / "evidence/logs/resource_lookup_trace_20260926_103856.log"
        if not log_path.exists():
            self.skipTest("Log trace file not found")

        records = LogParser.parse_file(
            file_path=log_path,
            file_id="evidence_94",
            origin="service_readback_logs",
            captured_at="2026-09-26T10:38:56Z"
        )
        self.assertGreater(len(records), 0)

        # Verify audit_record_2016 enriched with user_43
        rec2016 = next((r for r in records if r.resource_id == "audit_record_2016"), None)
        self.assertIsNotNone(rec2016)
        self.assertEqual(rec2016.user_id, "user_43")
        self.assertEqual(rec2016.system_id, SystemID.SECURITY_SERVICE.value)

    def test_06_log_parser_malformed_lines(self) -> None:
        """Verifies LogParser gracefully ignores garbled text and corrupted tokens."""
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8") as tf:
            tf.write("!!!GARBLED NOISE WITHOUT DELIMITERS???\n")
            tf.write("random words not matching format\n")
            tf.write("2026-09-01T12:00:00Z trace_id=tr-01 resource_id=account_999 lookup_key=user_99\n")
            temp_path = tf.name

        try:
            records = LogParser.parse_file(
                file_path=temp_path,
                file_id="test_log",
                origin="test_logs",
                captured_at="2026-09-01T12:00:00Z"
            )
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].resource_id, "account_999")
            self.assertEqual(records[0].user_id, "user_99")
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_07_pdf_parser_stream_decompression(self) -> None:
        """Verifies DocumentParser decompresses PDF streams and extracts references."""
        pdf_path = self.dataset_dir / "evidence/documents/delivery_correction_attachment.pdf"
        if not pdf_path.exists():
            self.skipTest("PDF document not found")

        records = DocumentParser.parse_file(
            file_path=pdf_path,
            file_id="evidence_58",
            origin="support_platform",
            captured_at="2026-09-12T07:30:00Z"
        )
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertEqual(r.resource_id, "support_001")
        self.assertEqual(r.system_id, SystemID.SUPPORT_PLATFORM.value)
        self.assertEqual(r.user_id, "user_07")
        self.assertEqual(r.operational_state, OperationalState.PRESENT)

    def test_08_png_metadata_parser(self) -> None:
        """Verifies ImageMetadataParser inspects binary PNG headers without external libraries."""
        png_path = self.dataset_dir / "evidence/images/account_admin_console_20260926.png"
        if not png_path.exists():
            self.skipTest("PNG image not found")

        records = ImageMetadataParser.parse_file(
            file_path=png_path,
            file_id="evidence_04",
            origin="account_admin_portal",
            captured_at="2026-09-26T11:00:00Z"
        )
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertEqual(r.system_id, SystemID.ACCOUNT_SERVICE.value)
        self.assertEqual(r.data_attributes["bit_depth"], 8)
        self.assertGreater(r.data_attributes["width"], 0)

    def test_09_timestamp_normalization(self) -> None:
        """Verifies ISO-8601 timestamp normalization across timezone representations."""
        self.assertEqual(_normalize_iso_timestamp("2026-09-01T12:00:00Z"), "2026-09-01T12:00:00Z")
        self.assertEqual(_normalize_iso_timestamp("2026-09-01T12:00:00+00:00"), "2026-09-01T12:00:00Z")
        self.assertEqual(_normalize_iso_timestamp("2026-09-01T12:00:00"), "2026-09-01T12:00:00Z")
        self.assertEqual(_normalize_iso_timestamp(None), "1970-01-01T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
