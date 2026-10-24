"""
Oblivara - Phase 3 Test Suite: Evidence Engine & State Reconstruction
File: tests/test_evidence_engine.py

Validates temporal cutoff enforcement, cross-system resource state reconstruction,
replication drift detection, active data flows, and restore risks.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from code.evidence_engine import EvidenceEngine, _parse_utc_iso
from code.evidence_models import OperationalState, SystemID
from code.identity_resolution import (
    CanonicalIdentity,
    IdentifierRecord,
    IdentifierType,
    IdentityGraph,
)


class TestEvidenceEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = EvidenceEngine("dataset")
        cls.engine.ingest_all()

        cls.graph = IdentityGraph()
        cls.graph.load_from_csv(
            user_identities_path="dataset/user_identities.csv",
            user_audit_log_path="dataset/user_audit_log.csv"
        )

    def test_01_manifest_coverage(self) -> None:
        """Verifies all 94 evidence files from the manifest are ingested without omission."""
        self.assertEqual(len(self.engine.manifest_rows), 94)
        self.assertGreater(len(self.engine.all_evidence_records), 3000)
        # Verify all 94 file_ids exist in by_evidence_id index
        for m in self.engine.manifest_rows:
            fid = m["file_id"]
            self.assertIn(fid, self.engine.by_evidence_id, f"File {fid} missing from parsed evidence")

    def test_02_temporal_cutoff_strict_enforcement(self) -> None:
        """Verifies evidence strictly after audit_at is quarantined and never influences decisions."""
        user_id = "user_05"
        identity = self.graph.users[user_id]

        # Case 05 has cutoff 2026-09-08T13:40:00Z
        cutoff = "2026-09-08T13:40:00Z"
        valid, post_cutoff = self.engine.get_user_evidence(user_id, identity, cutoff)

        cutoff_dt = _parse_utc_iso(cutoff)
        for r in valid:
            self.assertLessEqual(_parse_utc_iso(r.captured_at), cutoff_dt)
            self.assertLessEqual(_parse_utc_iso(r.observed_at), cutoff_dt)

        # When setting an earlier cutoff before evidence_54 capture (2026-09-02T23:00:00Z)
        early_cutoff = "2026-09-01T00:00:00Z"
        early_valid, early_post = self.engine.get_user_evidence(user_id, identity, early_cutoff)
        # All evidence_54 records must be quarantined to early_post
        ev54_in_early_valid = any(r.evidence_id == "evidence_54" for r in early_valid)
        self.assertFalse(ev54_in_early_valid, "Evidence captured after early cutoff was improperly included")

    def test_03_replication_drift_detection(self) -> None:
        """Verifies replication drift: primary reported deleted but failover replica still active."""
        user_id = "user_05"
        identity = self.graph.users[user_id]
        audit_at = "2026-09-08T13:40:00Z"

        state = self.engine.reconstruct_user_state(user_id, identity, audit_at)
        # account_005 was deleted from primary but present in failover replica (evidence_54)
        self.assertIn("account_005", state.resources)
        snap = state.resources["account_005"]
        self.assertEqual(snap.operational_state, OperationalState.PRESENT)
        self.assertEqual(len(state.remaining_records), 1)

    def test_04_active_data_flow_reconstruction(self) -> None:
        """Verifies data flows are identified as ACTIVE when enabled or DISABLED when stopped."""
        user_id = "user_26"
        identity = self.graph.users[user_id]
        audit_at = "2026-09-15T12:00:00Z"

        state = self.engine.reconstruct_user_state(user_id, identity, audit_at)
        # data_flow_6244 is stopped / enabled=False in evidence_92
        self.assertIn("data_flow_6244", state.resources)
        flow_snap = state.resources["data_flow_6244"]
        self.assertEqual(flow_snap.operational_state, OperationalState.DISABLED)

    def test_05_backup_restore_risk_reconstruction(self) -> None:
        """Verifies backup restore paths distinguish BLOCKED restore access from ACTIVE restore risk."""
        # user_26 backup_3120 has restore_allowed=False
        user_26 = "user_26"
        id_26 = self.graph.users[user_26]
        state_26 = self.engine.reconstruct_user_state(user_26, id_26, "2026-09-15T12:00:00Z")
        self.assertIn("backup_3120", state_26.resources)
        self.assertEqual(state_26.resources["backup_3120"].operational_state, OperationalState.BLOCKED)

        # user_61 backup_4978 in evidence_93 has restore_allowed=True
        user_61 = "user_61"
        id_61 = self.graph.users[user_61]
        state_61 = self.engine.reconstruct_user_state(user_61, id_61, "2026-09-16T12:00:00Z")
        self.assertIn("backup_4978", state_61.resources)
        self.assertEqual(state_61.resources["backup_4978"].operational_state, OperationalState.ACTIVE)
        self.assertTrue(state_61.resources["backup_4978"].is_restore_risk)

    def test_06_historical_identifier_correlation(self) -> None:
        """Verifies historical email and hash from audit log correlate to older evidence."""
        # user_12 has historical email_hash 44a65154... in evidence_01
        user_12 = "user_12"
        id_12 = self.graph.users[user_12]
        audit_at = "2026-09-16T12:00:00Z"

        state_12 = self.engine.reconstruct_user_state(user_12, id_12, audit_at)
        # Must match analytics_9914 via historical email_hash correlation_key
        self.assertIn("analytics_9914", state_12.resources)
        snap = state_12.resources["analytics_9914"]
        self.assertEqual(snap.primary_evidence_id, "evidence_01")

    def test_07_deterministic_repeatability(self) -> None:
        """Verifies running state reconstruction multiple times yields identical results."""
        user_id = "user_26"
        identity = self.graph.users[user_id]
        audit_at = "2026-09-15T12:00:00Z"

        run1 = self.engine.reconstruct_user_state(user_id, identity, audit_at).to_dict()
        run2 = self.engine.reconstruct_user_state(user_id, identity, audit_at).to_dict()
        self.assertEqual(run1, run2)


if __name__ == "__main__":
    unittest.main()
