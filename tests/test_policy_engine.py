"""
Oblivara - Phase 4 Unit Tests: Policy Engine
Module: tests.test_policy_engine
"""

import unittest
from datetime import datetime
from pathlib import Path

from code.evidence_models import (
    NormalizedEvidenceRecord,
    OperationalState,
    ResourceStateSnapshot,
    SystemID,
    UserSystemAuditState,
)
from code.identity_resolution import CanonicalIdentity, IdentifierRecord, IdentifierType
from code.intent_classifier import IntentClassificationResult, RequestIntent
from code.policy_engine import DeletionStatus, FindingOperation, PolicyEngine


class TestPolicyEngine(unittest.TestCase):
    """Unit tests for the policy evaluation engine."""

    def setUp(self) -> None:
        self.policy_engine = PolicyEngine()
        email_rec = IdentifierRecord.create("test.user@example.com", IdentifierType.EMAIL, "test")
        self.identity = CanonicalIdentity(user_id="user_999", current_email=email_rec)

    def _create_intent(self, intent: RequestIntent) -> IntentClassificationResult:
        from code.intent_classifier import IntentCategory
        return IntentClassificationResult(
            request_id="case_test",
            intent=intent,
            category=IntentCategory.ACCOUNT_DELETION if intent == RequestIntent.DELETION_REQUESTED else IntentCategory.RECTIFICATION_CORRECTION,
            confidence=1.0,
            matched_signals=["test_signal"],
        )

    def test_not_applicable_intent(self) -> None:
        """Requests with non-deletion intent must immediately return NOT_APPLICABLE."""
        intent = self._create_intent(RequestIntent.NOT_APPLICABLE)
        decision = self.policy_engine.evaluate_request(
            case_id="case_na",
            email="test.user@example.com",
            audit_at="2026-09-15T12:00:00Z",
            user_id="user_999",
            identity=self.identity,
            intent_result=intent,
            audit_state=None,
        )
        self.assertEqual(decision.deletion_status, DeletionStatus.NOT_APPLICABLE)
        self.assertEqual(len(decision.findings), 0)
        self.assertIn("NON_DELETION_INTENT_NOT_APPLICABLE", decision.reason_codes)

    def test_unresolved_user_identity(self) -> None:
        """Requests where canonical identity could not be resolved."""
        intent = self._create_intent(RequestIntent.DELETION_REQUESTED)
        decision = self.policy_engine.evaluate_request(
            case_id="case_unresolved",
            email="unknown@example.com",
            audit_at="2026-09-15T12:00:00Z",
            user_id=None,
            identity=None,
            intent_result=intent,
            audit_state=None,
        )
        self.assertEqual(decision.deletion_status, DeletionStatus.NOT_APPLICABLE)
        self.assertIn("UNRESOLVED_USER_IDENTITY", decision.reason_codes)

    def test_fully_compliant_deletion(self) -> None:
        """When all resources are absent/anonymized and retentions present, status is COMPLETE."""
        intent = self._create_intent(RequestIntent.DELETION_REQUESTED)
        snap1 = ResourceStateSnapshot(
            resource_id="account_999",
            system_id=SystemID.ACCOUNT_SERVICE.value,
            record_type="USER_PROFILE",
            operational_state=OperationalState.ABSENT,
            primary_evidence_id="evidence_54",
            effective_timestamp="2026-09-15T12:00:00Z",
        )
        snap2 = ResourceStateSnapshot(
            resource_id="audit_record_999",
            system_id=SystemID.SECURITY_SERVICE.value,
            record_type="SECURITY_AUDIT_LOG",
            operational_state=OperationalState.PRESENT,
            primary_evidence_id="evidence_54",
            effective_timestamp="2026-09-15T12:00:00Z",
            is_policy_retained=True,
        )
        audit_state = UserSystemAuditState(
            user_id="user_999",
            audit_at="2026-09-15T12:00:00Z",
            cutoff_enforced=True,
            verified_compliant_records=[snap1, snap2],
        )

        decision = self.policy_engine.evaluate_request(
            case_id="case_comp",
            email="test.user@example.com",
            audit_at="2026-09-15T12:00:00Z",
            user_id="user_999",
            identity=self.identity,
            intent_result=intent,
            audit_state=audit_state,
        )
        self.assertEqual(decision.deletion_status, DeletionStatus.COMPLETE)
        self.assertEqual(len(decision.findings), 0)
        self.assertIn("ALL_DELETION_RULES_SATISFIED", decision.reason_codes)
        self.assertIn("evidence_54", decision.evidence_citations)

    def test_remaining_record_violation(self) -> None:
        """When a record required to be deleted is PRESENT, it generates a REPORT_REMAINING_RECORD finding."""
        intent = self._create_intent(RequestIntent.DELETION_REQUESTED)
        snap = ResourceStateSnapshot(
            resource_id="search_101",
            system_id=SystemID.SEARCH_SERVICE.value,
            record_type="SEARCH_INDEX_ENTRY",
            operational_state=OperationalState.PRESENT,
            primary_evidence_id="evidence_03",
            effective_timestamp="2026-09-15T12:00:00Z",
        )
        audit_state = UserSystemAuditState(
            user_id="user_999",
            audit_at="2026-09-15T12:00:00Z",
            cutoff_enforced=True,
            remaining_records=[snap],
        )

        decision = self.policy_engine.evaluate_request(
            case_id="case_incomp",
            email="test.user@example.com",
            audit_at="2026-09-15T12:00:00Z",
            user_id="user_999",
            identity=self.identity,
            intent_result=intent,
            audit_state=audit_state,
        )
        self.assertEqual(decision.deletion_status, DeletionStatus.INCOMPLETE)
        self.assertEqual(len(decision.findings), 1)
        self.assertEqual(decision.findings[0].operation, FindingOperation.REPORT_REMAINING_RECORD.value)
        self.assertEqual(decision.findings[0].evidence_id, "evidence_03")

    def test_exposed_pii_violation(self) -> None:
        """Records with exposed PII generate REPORT_EXPOSED_PII findings."""
        intent = self._create_intent(RequestIntent.DELETION_REQUESTED)
        snap = ResourceStateSnapshot(
            resource_id="analytics_555",
            system_id=SystemID.ANALYTICS_PLATFORM.value,
            record_type="ANALYTICS_PROFILE",
            operational_state=OperationalState.PRESENT,
            primary_evidence_id="evidence_92",
            effective_timestamp="2026-09-15T12:00:00Z",
            has_exposed_pii=True,
        )
        audit_state = UserSystemAuditState(
            user_id="user_999",
            audit_at="2026-09-15T12:00:00Z",
            cutoff_enforced=True,
            exposed_pii_records=[snap],
        )

        decision = self.policy_engine.evaluate_request(
            case_id="case_pii",
            email="test.user@example.com",
            audit_at="2026-09-15T12:00:00Z",
            user_id="user_999",
            identity=self.identity,
            intent_result=intent,
            audit_state=audit_state,
        )
        self.assertEqual(decision.deletion_status, DeletionStatus.INCOMPLETE)
        self.assertEqual(decision.findings[0].operation, FindingOperation.REPORT_EXPOSED_PII.value)
        self.assertEqual(decision.findings[0].resource_id, "analytics_555")

    def test_active_data_flow_and_restore_risk(self) -> None:
        """Active sync flows and unblocked backups generate active risk findings."""
        intent = self._create_intent(RequestIntent.DELETION_REQUESTED)
        flow_snap = ResourceStateSnapshot(
            resource_id="data_flow_888",
            system_id=SystemID.INTEGRATION_SERVICE.value,
            record_type="DATA_FLOW",
            operational_state=OperationalState.ACTIVE,
            primary_evidence_id="evidence_92",
            effective_timestamp="2026-09-15T12:00:00Z",
            is_active_flow=True,
        )
        backup_snap = ResourceStateSnapshot(
            resource_id="backup_777",
            system_id=SystemID.BACKUP_SERVICE.value,
            record_type="BACKUP_ARCHIVE",
            operational_state=OperationalState.ACTIVE,
            primary_evidence_id="evidence_92",
            effective_timestamp="2026-09-15T12:00:00Z",
            is_restore_risk=True,
        )
        audit_state = UserSystemAuditState(
            user_id="user_999",
            audit_at="2026-09-15T12:00:00Z",
            cutoff_enforced=True,
            active_data_flows=[flow_snap],
            restore_risks=[backup_snap],
        )

        decision = self.policy_engine.evaluate_request(
            case_id="case_risks",
            email="test.user@example.com",
            audit_at="2026-09-15T12:00:00Z",
            user_id="user_999",
            identity=self.identity,
            intent_result=intent,
            audit_state=audit_state,
        )
        self.assertEqual(decision.deletion_status, DeletionStatus.INCOMPLETE)
        ops = {f.operation for f in decision.findings}
        self.assertIn(FindingOperation.REPORT_ACTIVE_DATA_FLOW.value, ops)
        self.assertIn(FindingOperation.REPORT_RESTORE_RISK.value, ops)

    def test_deterministic_evaluation(self) -> None:
        """Repeated evaluation under identical inputs produces identical results."""
        intent = self._create_intent(RequestIntent.DELETION_REQUESTED)
        snap1 = ResourceStateSnapshot(
            resource_id="search_001",
            system_id=SystemID.SEARCH_SERVICE.value,
            record_type="SEARCH_INDEX_ENTRY",
            operational_state=OperationalState.PRESENT,
            primary_evidence_id="evidence_01",
            effective_timestamp="2026-09-15T12:00:00Z",
        )
        snap2 = ResourceStateSnapshot(
            resource_id="support_001",
            system_id=SystemID.SUPPORT_PLATFORM.value,
            record_type="SUPPORT_MESSAGE",
            operational_state=OperationalState.PRESENT,
            primary_evidence_id="evidence_01",
            effective_timestamp="2026-09-15T12:00:00Z",
            has_exposed_pii=True,
        )
        audit_state = UserSystemAuditState(
            user_id="user_999",
            audit_at="2026-09-15T12:00:00Z",
            cutoff_enforced=True,
            remaining_records=[snap1],
            exposed_pii_records=[snap2],
        )

        dec1 = self.policy_engine.evaluate_request(
            "case_det", "test.user@example.com", "2026-09-15T12:00:00Z", "user_999", self.identity, intent, audit_state
        )
        dec2 = self.policy_engine.evaluate_request(
            "case_det", "test.user@example.com", "2026-09-15T12:00:00Z", "user_999", self.identity, intent, audit_state
        )

        self.assertEqual(dec1.to_dict(), dec2.to_dict())


if __name__ == "__main__":
    unittest.main()
