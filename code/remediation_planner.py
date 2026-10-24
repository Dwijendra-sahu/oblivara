"""
Oblivara - Phase 4: Dependency-Aware Remediation Planner
Module: code.remediation_planner

Translates policy decisions and findings into a dependency-ordered remediation plan
and complete evidence-backed verification steps conforming to the official competition contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from code.evidence_models import OperationalState, ResourceStateSnapshot, SystemID, UserSystemAuditState
from code.policy_engine import DeletionStatus, PolicyDecision, PolicyFinding


class StepPhase(str, Enum):
    """Competition contract phases in mandatory execution order."""
    FINDING = "FINDING"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"


class RemediationOperation(str, Enum):
    """Allowed remediation operations per problem_statement.md §6.4."""
    DISABLE_DATA_FLOW = "DISABLE_DATA_FLOW"
    BLOCK_RESTORE = "BLOCK_RESTORE"
    DELETE_RECORD = "DELETE_RECORD"
    REDACT_RECORD = "REDACT_RECORD"
    ANONYMIZE_RECORD = "ANONYMIZE_RECORD"


class VerificationOperation(str, Enum):
    """Allowed verification operations per problem_statement.md §6.4."""
    VERIFY_RECORD_ABSENT = "VERIFY_RECORD_ABSENT"
    VERIFY_RECORD_PRESENT = "VERIFY_RECORD_PRESENT"
    VERIFY_RECORD_REDACTED = "VERIFY_RECORD_REDACTED"
    VERIFY_RECORD_ANONYMIZED = "VERIFY_RECORD_ANONYMIZED"
    VERIFY_DATA_FLOW_DISABLED = "VERIFY_DATA_FLOW_DISABLED"
    VERIFY_RESTORE_BLOCKED = "VERIFY_RESTORE_BLOCKED"


@dataclass
class RemediationStep:
    """An individual step in the serialized steps_json array."""
    step_no: int
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_no": self.step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }


class DependencyGraph:
    """
    Directed Acyclic Graph (DAG) for dependency-aware remediation scheduling.
    Ensures data flows are disabled and restores are blocked before modifying records.
    """

    def __init__(self) -> None:
        self.nodes: Dict[str, RemediationStep] = {}
        self.edges: Dict[str, Set[str]] = {}  # node -> set of nodes it depends on (prerequisites)
        self.reverse_edges: Dict[str, Set[str]] = {}  # node -> set of nodes depending on it

    def add_node(self, node_id: str, step: RemediationStep) -> None:
        self.nodes[node_id] = step
        if node_id not in self.edges:
            self.edges[node_id] = set()
        if node_id not in self.reverse_edges:
            self.reverse_edges[node_id] = set()

    def add_dependency(self, node_id: str, depends_on_id: str) -> None:
        """Declares that node_id requires depends_on_id to complete first."""
        if node_id not in self.nodes or depends_on_id not in self.nodes:
            raise KeyError(f"Both nodes must exist before adding dependency: {node_id} -> {depends_on_id}")
        self.edges[node_id].add(depends_on_id)
        self.reverse_edges[depends_on_id].add(node_id)

    def detect_cycles(self) -> bool:
        """Detects if any dependency cycle exists using Kahn's algorithm."""
        in_degree = {n: len(self.edges[n]) for n in self.nodes}
        queue = [n for n, deg in in_degree.items() if deg == 0]
        visited_count = 0

        while queue:
            curr = queue.pop(0)
            visited_count += 1
            for dependent in self.reverse_edges[curr]:
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)

        return visited_count < len(self.nodes)

    def topological_sort(self, tie_break_order: Dict[str, int]) -> List[RemediationStep]:
        """
        Produces a deterministic, topologically sorted execution sequence.
        tie_break_order maps operation names or system IDs to secondary priorities.
        """
        if self.detect_cycles():
            raise ValueError("Dependency cycle detected in remediation action graph.")

        in_degree = {n: len(self.edges[n]) for n in self.nodes}
        # Available nodes: in_degree == 0
        sorted_steps: List[RemediationStep] = []

        while len(sorted_steps) < len(self.nodes):
            available = [n for n, deg in in_degree.items() if deg == 0 and n not in [s.resource_id for s in sorted_steps]]
            if not available:
                break
            # Deterministic tie-breaking: by tie_break_order rank, then system_id, then resource_id
            available.sort(key=lambda n: (
                tie_break_order.get(self.nodes[n].operation, 99),
                self.nodes[n].system_id,
                n
            ))
            chosen = available[0]
            sorted_steps.append(self.nodes[chosen])
            in_degree[chosen] = -1  # marked as processed
            for dependent in self.reverse_edges[chosen]:
                in_degree[dependent] -= 1

        return sorted_steps


class RemediationPlanner:
    """
    Plans findings, remediation actions, and post-remediation verification checks.
    """

    # Authoritative operation precedence levels (§6.5)
    PRECEDENCE = {
        RemediationOperation.DISABLE_DATA_FLOW.value: 1,
        RemediationOperation.BLOCK_RESTORE.value: 2,
        RemediationOperation.DELETE_RECORD.value: 3,
        RemediationOperation.REDACT_RECORD.value: 4,
        RemediationOperation.ANONYMIZE_RECORD.value: 5,
    }

    # Standard system sequence for verification steps
    VERIFICATION_SYSTEM_ORDER = {
        SystemID.ACCOUNT_SERVICE.value: 1,
        SystemID.SEARCH_SERVICE.value: 2,
        SystemID.SECURITY_SERVICE.value: 3,
        SystemID.SUPPORT_PLATFORM.value: 4,
        SystemID.ANALYTICS_PLATFORM.value: 5,
        SystemID.INTEGRATION_SERVICE.value: 6,
        SystemID.BACKUP_SERVICE.value: 7,
        SystemID.EXPORT_SERVICE.value: 8,
        SystemID.IDENTITY_SERVICE.value: 9,
    }

    def plan(
        self,
        decision: PolicyDecision,
        audit_state: Optional[UserSystemAuditState] = None,
    ) -> List[RemediationStep]:
        """
        Generates the complete, ordered steps according to the official contract.
        """
        if decision.deletion_status == DeletionStatus.NOT_APPLICABLE:
            return []

        if decision.deletion_status == DeletionStatus.COMPLETE:
            return self._plan_complete_verification(decision, audit_state)

        # DeletionStatus.INCOMPLETE: FINDING -> REMEDIATION -> VERIFICATION
        return self._plan_incomplete_remediation(decision, audit_state)

    def _plan_complete_verification(
        self,
        decision: PolicyDecision,
        audit_state: Optional[UserSystemAuditState],
    ) -> List[RemediationStep]:
        """
        For COMPLETE cases: Emit ONLY VERIFICATION steps, all citing evidence proving compliant state.
        """
        if not audit_state or not audit_state.verified_compliant_records:
            return []

        # Deduplicate by (system_id, resource_id)
        seen_res: Set[Tuple[str, str]] = set()
        unique_snaps: List[ResourceStateSnapshot] = []
        for s in audit_state.verified_compliant_records:
            key = (s.system_id, s.resource_id)
            if key not in seen_res:
                seen_res.add(key)
                unique_snaps.append(s)

        # Sort in standard system order
        unique_snaps.sort(key=lambda s: (
            self.VERIFICATION_SYSTEM_ORDER.get(s.system_id, 99),
            s.resource_id
        ))

        steps: List[RemediationStep] = []
        for idx, snap in enumerate(unique_snaps, start=1):
            op, st = self._map_verification_operation(snap)
            step = RemediationStep(
                step_no=idx,
                phase=StepPhase.VERIFICATION.value,
                system_id=snap.system_id,
                resource_id=snap.resource_id,
                operation=op,
                state=st,
                evidence_id=snap.primary_evidence_id,
            )
            steps.append(step)

        return steps

    def _plan_incomplete_remediation(
        self,
        decision: PolicyDecision,
        audit_state: Optional[UserSystemAuditState],
    ) -> List[RemediationStep]:
        """
        For INCOMPLETE cases: Emit FINDING -> REMEDIATION -> VERIFICATION.
        """
        steps: List[RemediationStep] = []
        current_step_no = 1

        # Phase 1: FINDING (cites participant-visible evidence)
        for finding in decision.findings:
            f_step = RemediationStep(
                step_no=current_step_no,
                phase=StepPhase.FINDING.value,
                system_id=finding.system_id,
                resource_id=finding.resource_id,
                operation=finding.operation,
                state=finding.state,
                evidence_id=finding.evidence_id,
            )
            steps.append(f_step)
            current_step_no += 1

        # Phase 2: REMEDIATION (dependency-aware graph ordering, evidence_id="")
        dag = DependencyGraph()
        remediation_actions: List[RemediationStep] = []

        for finding in decision.findings:
            rem_op, rem_state = self._map_remediation_operation(finding)
            r_step = RemediationStep(
                step_no=0,  # will be assigned consecutively after sorting
                phase=StepPhase.REMEDIATION.value,
                system_id=finding.system_id,
                resource_id=finding.resource_id,
                operation=rem_op,
                state=rem_state,
                evidence_id="",  # Future remediation has empty evidence_id
            )
            dag.add_node(finding.resource_id, r_step)
            remediation_actions.append(r_step)

        # Build dependency edges:
        # Data flows and restore blocks must be executed before dependent records are modified
        flow_and_backup_nodes = [
            a.resource_id for a in remediation_actions
            if a.operation in (RemediationOperation.DISABLE_DATA_FLOW.value, RemediationOperation.BLOCK_RESTORE.value)
        ]
        record_nodes = [
            a.resource_id for a in remediation_actions
            if a.operation in (RemediationOperation.DELETE_RECORD.value, RemediationOperation.REDACT_RECORD.value, RemediationOperation.ANONYMIZE_RECORD.value)
        ]

        for r_node in record_nodes:
            for fb_node in flow_and_backup_nodes:
                dag.add_dependency(r_node, fb_node)

        # Topologically sort remediation actions
        sorted_rem = dag.topological_sort(self.PRECEDENCE)
        for act in sorted_rem:
            act.step_no = current_step_no
            steps.append(act)
            current_step_no += 1

        # Phase 3: VERIFICATION (post-remediation verification covering all resources, evidence_id="")
        # Gathers all resources involved in this user's state:
        # Both remediated resources and existing verified compliant resources
        verification_candidates: Dict[Tuple[str, str], Tuple[str, str]] = {}

        # 1. Remediated resources must be verified
        for act in sorted_rem:
            v_op, v_state = self._map_post_remediation_verification(act)
            verification_candidates[(act.system_id, act.resource_id)] = (v_op, v_state)

        # 2. Compliant resources (e.g. absent account profile, present security audit log)
        if audit_state:
            for snap in audit_state.verified_compliant_records:
                key = (snap.system_id, snap.resource_id)
                if key not in verification_candidates:
                    v_op, v_state = self._map_verification_operation(snap)
                    verification_candidates[key] = (v_op, v_state)

        # Sort verification checks by standard system order
        sorted_verif_keys = sorted(
            verification_candidates.keys(),
            key=lambda k: (self.VERIFICATION_SYSTEM_ORDER.get(k[0], 99), k[1])
        )

        for sys_id, res_id in sorted_verif_keys:
            v_op, v_state = verification_candidates[(sys_id, res_id)]
            v_step = RemediationStep(
                step_no=current_step_no,
                phase=StepPhase.VERIFICATION.value,
                system_id=sys_id,
                resource_id=res_id,
                operation=v_op,
                state=v_state,
                evidence_id="",  # Future post-remediation verification has empty evidence_id
            )
            steps.append(v_step)
            current_step_no += 1

        return steps

    def _map_remediation_operation(self, finding: PolicyFinding) -> Tuple[str, str]:
        """Maps a finding to its corresponding remediation operation and target state."""
        if finding.operation == "REPORT_ACTIVE_DATA_FLOW":
            return RemediationOperation.DISABLE_DATA_FLOW.value, "DISABLED"
        if finding.operation == "REPORT_RESTORE_RISK":
            return RemediationOperation.BLOCK_RESTORE.value, "BLOCKED"
        if finding.operation == "REPORT_EXPOSED_PII":
            if finding.system_id == SystemID.ANALYTICS_PLATFORM.value or "analytics_" in finding.resource_id:
                return RemediationOperation.ANONYMIZE_RECORD.value, "ANONYMIZED"
            return RemediationOperation.REDACT_RECORD.value, "REDACTED"
        # Default for REPORT_REMAINING_RECORD
        return RemediationOperation.DELETE_RECORD.value, "ABSENT"

    def _map_post_remediation_verification(self, remediation: RemediationStep) -> Tuple[str, str]:
        """Maps a remediation action to its post-remediation verification check."""
        op = remediation.operation
        if op == RemediationOperation.DISABLE_DATA_FLOW.value:
            return VerificationOperation.VERIFY_DATA_FLOW_DISABLED.value, "DISABLED"
        if op == RemediationOperation.BLOCK_RESTORE.value:
            return VerificationOperation.VERIFY_RESTORE_BLOCKED.value, "BLOCKED"
        if op == RemediationOperation.REDACT_RECORD.value:
            return VerificationOperation.VERIFY_RECORD_REDACTED.value, "REDACTED"
        if op == RemediationOperation.ANONYMIZE_RECORD.value:
            return VerificationOperation.VERIFY_RECORD_ANONYMIZED.value, "ANONYMIZED"
        return VerificationOperation.VERIFY_RECORD_ABSENT.value, "ABSENT"

    def _map_verification_operation(self, snapshot: ResourceStateSnapshot) -> Tuple[str, str]:
        """Maps a compliant resource snapshot to its verification operation and state."""
        st = snapshot.operational_state
        sys_id = snapshot.system_id

        if st == OperationalState.ABSENT:
            return VerificationOperation.VERIFY_RECORD_ABSENT.value, "ABSENT"
        if st == OperationalState.REDACTED:
            return VerificationOperation.VERIFY_RECORD_REDACTED.value, "REDACTED"
        if st == OperationalState.ANONYMIZED:
            return VerificationOperation.VERIFY_RECORD_ANONYMIZED.value, "ANONYMIZED"
        if st == OperationalState.DISABLED:
            return VerificationOperation.VERIFY_DATA_FLOW_DISABLED.value, "DISABLED"
        if st == OperationalState.BLOCKED:
            return VerificationOperation.VERIFY_RESTORE_BLOCKED.value, "BLOCKED"
        if snapshot.is_policy_retained or st == OperationalState.PRESENT:
            return VerificationOperation.VERIFY_RECORD_PRESENT.value, "PRESENT"

        return VerificationOperation.VERIFY_RECORD_ABSENT.value, "ABSENT"
