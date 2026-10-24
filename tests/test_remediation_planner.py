"""
Oblivara - Phase 4 Unit Tests: Remediation Planner
Module: tests.test_remediation_planner
"""

import unittest

from code.evidence_models import OperationalState, ResourceStateSnapshot, SystemID, UserSystemAuditState
from code.policy_engine import DeletionStatus, FindingOperation, PolicyDecision, PolicyFinding
from code.remediation_planner import (
    DependencyGraph,
    RemediationOperation,
    RemediationPlanner,
    RemediationStep,
    StepPhase,
    VerificationOperation,
)


class TestRemediationPlanner(unittest.TestCase):
    """Unit tests for the dependency-aware remediation planner."""

    def setUp(self) -> None:
        self.planner = RemediationPlanner()

    def test_dag_cycle_detection(self) -> None:
        """Cycle detection in DependencyGraph."""
        dag = DependencyGraph()
        step_a = RemediationStep(1, StepPhase.REMEDIATION.value, "sys_a", "res_a", "DELETE_RECORD", "ABSENT")
        step_b = RemediationStep(2, StepPhase.REMEDIATION.value, "sys_b", "res_b", "DELETE_RECORD", "ABSENT")

        dag.add_node("res_a", step_a)
        dag.add_node("res_b", step_b)
        dag.add_dependency("res_a", "res_b")
        dag.add_dependency("res_b", "res_a")

        self.assertTrue(dag.detect_cycles())
        with self.assertRaises(ValueError):
            dag.topological_sort(self.planner.PRECEDENCE)

    def test_not_applicable_plan_empty(self) -> None:
        """Requests with NOT_APPLICABLE status must produce empty steps array."""
        decision = PolicyDecision(
            case_id="case_na",
            canonical_user_id="user_1",
            deletion_status=DeletionStatus.NOT_APPLICABLE,
        )
        steps = self.planner.plan(decision)
        self.assertEqual(steps, [])

    def test_complete_plan_only_verification_with_evidence(self) -> None:
        """COMPLETE cases produce ONLY VERIFICATION steps citing evidence."""
        snap1 = ResourceStateSnapshot(
            resource_id="account_001",
            system_id=SystemID.ACCOUNT_SERVICE.value,
            record_type="USER_PROFILE",
            operational_state=OperationalState.ABSENT,
            primary_evidence_id="evidence_54",
            effective_timestamp="2026-09-15T12:00:00Z",
        )
        snap2 = ResourceStateSnapshot(
            resource_id="audit_record_001",
            system_id=SystemID.SECURITY_SERVICE.value,
            record_type="SECURITY_AUDIT_LOG",
            operational_state=OperationalState.PRESENT,
            primary_evidence_id="evidence_54",
            effective_timestamp="2026-09-15T12:00:00Z",
            is_policy_retained=True,
        )
        audit_state = UserSystemAuditState(
            user_id="user_01",
            audit_at="2026-09-15T12:00:00Z",
            cutoff_enforced=True,
            verified_compliant_records=[snap1, snap2],
        )
        decision = PolicyDecision(
            case_id="case_c1",
            canonical_user_id="user_01",
            deletion_status=DeletionStatus.COMPLETE,
        )

        steps = self.planner.plan(decision, audit_state)
        self.assertEqual(len(steps), 2)
        for s in steps:
            self.assertEqual(s.phase, StepPhase.VERIFICATION.value)
            self.assertEqual(s.evidence_id, "evidence_54")

        # Step numbering must be consecutive starting at 1
        self.assertEqual(steps[0].step_no, 1)
        self.assertEqual(steps[1].step_no, 2)

    def test_incomplete_plan_phase_order_and_dependencies(self) -> None:
        """INCOMPLETE cases produce FINDING -> REMEDIATION -> VERIFICATION with dependencies."""
        f_flow = PolicyFinding(
            rule_id="FLOW",
            system_id=SystemID.INTEGRATION_SERVICE.value,
            resource_id="data_flow_1",
            operation=FindingOperation.REPORT_ACTIVE_DATA_FLOW.value,
            state="ACTIVE",
            evidence_id="evidence_03",
            reason="flow active",
        )
        f_search = PolicyFinding(
            rule_id="SEARCH",
            system_id=SystemID.SEARCH_SERVICE.value,
            resource_id="search_1",
            operation=FindingOperation.REPORT_REMAINING_RECORD.value,
            state="PRESENT",
            evidence_id="evidence_03",
            reason="record remains",
        )
        f_support = PolicyFinding(
            rule_id="SUPPORT",
            system_id=SystemID.SUPPORT_PLATFORM.value,
            resource_id="support_1",
            operation=FindingOperation.REPORT_EXPOSED_PII.value,
            state="PRESENT",
            evidence_id="evidence_03",
            reason="pii exposed",
        )
        f_analytics = PolicyFinding(
            rule_id="ANALYTICS",
            system_id=SystemID.ANALYTICS_PLATFORM.value,
            resource_id="analytics_1",
            operation=FindingOperation.REPORT_EXPOSED_PII.value,
            state="PRESENT",
            evidence_id="evidence_03",
            reason="pii exposed",
        )

        decision = PolicyDecision(
            case_id="case_inc",
            canonical_user_id="user_1",
            deletion_status=DeletionStatus.INCOMPLETE,
            findings=[f_flow, f_search, f_support, f_analytics],
        )

        account_snap = ResourceStateSnapshot(
            resource_id="account_001",
            system_id=SystemID.ACCOUNT_SERVICE.value,
            record_type="USER_PROFILE",
            operational_state=OperationalState.ABSENT,
            primary_evidence_id="evidence_03",
            effective_timestamp="2026-09-15T12:00:00Z",
        )
        audit_state = UserSystemAuditState(
            user_id="user_1",
            audit_at="2026-09-15T12:00:00Z",
            cutoff_enforced=True,
            verified_compliant_records=[account_snap],
        )

        steps = self.planner.plan(decision, audit_state)

        # 1. Phase sequence check
        phases = [s.phase for s in steps]
        seen_phases = []
        for p in phases:
            if not seen_phases or seen_phases[-1] != p:
                seen_phases.append(p)
        self.assertEqual(seen_phases, ["FINDING", "REMEDIATION", "VERIFICATION"])

        # 2. Check remediation operation precedence:
        # DISABLE_DATA_FLOW must come before DELETE_RECORD, REDACT_RECORD, ANONYMIZE_RECORD
        rem_steps = [s for s in steps if s.phase == StepPhase.REMEDIATION.value]
        rem_ops = [s.operation for s in rem_steps]
        self.assertEqual(rem_ops[0], RemediationOperation.DISABLE_DATA_FLOW.value)
        self.assertEqual(rem_ops[1], RemediationOperation.DELETE_RECORD.value)
        self.assertEqual(rem_ops[2], RemediationOperation.REDACT_RECORD.value)
        self.assertEqual(rem_ops[3], RemediationOperation.ANONYMIZE_RECORD.value)

        # 3. Check evidence_id rules:
        # Findings must have evidence_id; remediation and post-remediation verification must have evidence_id=""
        for s in steps:
            if s.phase == StepPhase.FINDING.value:
                self.assertEqual(s.evidence_id, "evidence_03")
            else:
                self.assertEqual(s.evidence_id, "")

        # 4. Check step numbering consecutively
        for idx, s in enumerate(steps, start=1):
            self.assertEqual(s.step_no, idx)


if __name__ == "__main__":
    unittest.main()
