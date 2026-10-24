"""
Oblivara - Test Hardening: Policy Engine & Remediation Planner Edge Cases
Module: tests.test_policy_remediation_hardening
Covers Phase 4 hardening: tombstone preservation, legal hold & security retention,
complex multi-node DAG cycle detection, and tie-breaking invariants.
"""

import sys
import unittest
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))

from code.evidence_models import (
    OperationalState,
    ResourceStateSnapshot,
    SystemID,
    UserSystemAuditState,
)
from code.identity_resolution import CanonicalIdentity, IdentifierRecord, IdentifierType
from code.intent_classifier import IntentClassificationResult, RequestIntent
from code.policy_engine import DeletionStatus, FindingOperation, PolicyEngine
from code.remediation_planner import (
    DependencyGraph,
    RemediationOperation,
    RemediationPlanner,
    RemediationStep,
    StepPhase,
    VerificationOperation,
)


class TestPolicyRemediationHardening(unittest.TestCase):
    """Hardened edge-case tests for PolicyEngine and RemediationPlanner."""

    def setUp(self) -> None:
        self.policy_engine = PolicyEngine()
        self.planner = RemediationPlanner()
        email_rec = IdentifierRecord.create("test@example.com", IdentifierType.EMAIL, "test")
        self.identity = CanonicalIdentity(user_id="user_hd", current_email=email_rec)

    def _create_intent(self) -> IntentClassificationResult:
        from code.intent_classifier import IntentCategory
        return IntentClassificationResult(
            request_id="case_hd",
            intent=RequestIntent.DELETION_REQUESTED,
            category=IntentCategory.ACCOUNT_DELETION,
            confidence=1.0,
            matched_signals=["delete_account"],
        )

    def test_tombstone_preservation_policy(self) -> None:
        """Verifies that an account tombstone with redacted PII is treated as compliant and not reported as a violation."""
        snap_tombstone = ResourceStateSnapshot(
            resource_id="account_tombstone_99",
            system_id=SystemID.IDENTITY_SERVICE.value,
            record_type="ACCOUNT_TOMBSTONE",
            operational_state=OperationalState.REDACTED,
            primary_evidence_id="ev_tomb",
            effective_timestamp="2026-09-15T12:00:00Z",
            is_policy_retained=True,
            has_exposed_pii=False,
        )

        audit_state = UserSystemAuditState(
            user_id="user_hd",
            audit_at="2026-09-15T12:00:00Z",
            cutoff_enforced=True,
            verified_compliant_records=[snap_tombstone],
        )

        decision = self.policy_engine.evaluate_request(
            case_id="case_tomb",
            email="test@example.com",
            audit_at="2026-09-15T12:00:00Z",
            user_id="user_hd",
            identity=self.identity,
            intent_result=self._create_intent(),
            audit_state=audit_state,
        )

        # Tombstone must not trigger REPORT_REMAINING_RECORD
        self.assertEqual(decision.deletion_status, DeletionStatus.COMPLETE)
        self.assertEqual(len(decision.findings), 0)

        # Planner emits VERIFY_RECORD_REDACTED citing evidence
        steps = self.planner.plan(decision, audit_state)
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0].operation, VerificationOperation.VERIFY_RECORD_REDACTED.value)
        self.assertEqual(steps[0].state, "REDACTED")
        self.assertEqual(steps[0].evidence_id, "ev_tomb")

    def test_security_audit_and_legal_hold_retention(self) -> None:
        """Verifies that security audit logs and legal hold records remain present and compliant."""
        snap_sec = ResourceStateSnapshot(
            resource_id="audit_record_123",
            system_id=SystemID.SECURITY_SERVICE.value,
            record_type="SECURITY_AUDIT_LOG",
            operational_state=OperationalState.PRESENT,
            primary_evidence_id="ev_sec",
            effective_timestamp="2026-09-15T12:00:00Z",
            is_policy_retained=True,
        )
        snap_legal = ResourceStateSnapshot(
            resource_id="legal_hold_456",
            system_id=SystemID.SECURITY_SERVICE.value,
            record_type="LEGAL_HOLD_RECORD",
            operational_state=OperationalState.PRESENT,
            primary_evidence_id="ev_legal",
            effective_timestamp="2026-09-15T12:00:00Z",
            is_policy_retained=True,
        )

        audit_state = UserSystemAuditState(
            user_id="user_hd",
            audit_at="2026-09-15T12:00:00Z",
            cutoff_enforced=True,
            verified_compliant_records=[snap_sec, snap_legal],
        )

        decision = self.policy_engine.evaluate_request(
            case_id="case_ret",
            email="test@example.com",
            audit_at="2026-09-15T12:00:00Z",
            user_id="user_hd",
            identity=self.identity,
            intent_result=self._create_intent(),
            audit_state=audit_state,
        )

        self.assertEqual(decision.deletion_status, DeletionStatus.COMPLETE)
        self.assertEqual(len(decision.findings), 0)

        steps = self.planner.plan(decision, audit_state)
        self.assertEqual(len(steps), 2)
        for s in steps:
            self.assertEqual(s.phase, StepPhase.VERIFICATION.value)
            self.assertEqual(s.operation, VerificationOperation.VERIFY_RECORD_PRESENT.value)
            self.assertEqual(s.state, "PRESENT")

    def test_complex_multi_node_dag_cycle_detection(self) -> None:
        """Verifies Kahn's algorithm cycle detection on a 3-node cycle and self-dependency."""
        # 1. 3-node cycle: A -> B -> C -> A
        dag_3 = DependencyGraph()
        dag_3.add_node("A", RemediationStep(1, StepPhase.REMEDIATION.value, "sys", "A", "DELETE_RECORD", "ABSENT"))
        dag_3.add_node("B", RemediationStep(2, StepPhase.REMEDIATION.value, "sys", "B", "DELETE_RECORD", "ABSENT"))
        dag_3.add_node("C", RemediationStep(3, StepPhase.REMEDIATION.value, "sys", "C", "DELETE_RECORD", "ABSENT"))

        dag_3.add_dependency("A", "B")
        dag_3.add_dependency("B", "C")
        dag_3.add_dependency("C", "A")

        self.assertTrue(dag_3.detect_cycles())
        with self.assertRaises(ValueError):
            dag_3.topological_sort(self.planner.PRECEDENCE)

        # 2. Self-loop: A -> A
        dag_self = DependencyGraph()
        dag_self.add_node("A", RemediationStep(1, StepPhase.REMEDIATION.value, "sys", "A", "DELETE_RECORD", "ABSENT"))
        dag_self.add_dependency("A", "A")

        self.assertTrue(dag_self.detect_cycles())
        with self.assertRaises(ValueError):
            dag_self.topological_sort(self.planner.PRECEDENCE)

    def test_dag_deterministic_tie_breaking(self) -> None:
        """Verifies that actions at the same precedence level are deterministically sorted by system_id then resource_id."""
        dag = DependencyGraph()
        # Three independent DELETE_RECORD actions across different systems and IDs
        step_z = RemediationStep(1, StepPhase.REMEDIATION.value, "search_service", "search_zebra", "DELETE_RECORD", "ABSENT")
        step_a = RemediationStep(2, StepPhase.REMEDIATION.value, "account_service", "account_alpha", "DELETE_RECORD", "ABSENT")
        step_b = RemediationStep(3, StepPhase.REMEDIATION.value, "account_service", "account_beta", "DELETE_RECORD", "ABSENT")

        dag.add_node("search_zebra", step_z)
        dag.add_node("account_alpha", step_a)
        dag.add_node("account_beta", step_b)

        # Topological sort with no edges must use deterministic tie-breaking:
        # 1. precedence rank (all are DELETE_RECORD rank 3)
        # 2. system_id: account_service < search_service
        # 3. resource_id: account_alpha < account_beta
        sorted_steps = dag.topological_sort(self.planner.PRECEDENCE)
        self.assertEqual([s.resource_id for s in sorted_steps], ["account_alpha", "account_beta", "search_zebra"])


if __name__ == "__main__":
    unittest.main()
