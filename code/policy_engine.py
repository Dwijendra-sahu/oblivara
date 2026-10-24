"""
Oblivara - Phase 4: Policy Engine
Module: code.policy_engine

Authoritative policy evaluation engine that enforces data deletion rules
across all platform services, detecting remaining records, exposed PII,
active data replication flows, and restore risks at the audit cutoff.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from code.evidence_models import (
    NormalizedEvidenceRecord,
    OperationalState,
    ResourceStateSnapshot,
    SystemID,
    UserSystemAuditState,
)
from code.identity_resolution import CanonicalIdentity
from code.intent_classifier import IntentClassificationResult, RequestIntent


class DeletionStatus(str, Enum):
    """Competition-contract deletion status."""
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class PolicyAction(str, Enum):
    """Required policy action defined in deletion_rules.csv."""
    DELETE = "DELETE"
    REDACT = "REDACT"
    ANONYMIZE = "ANONYMIZE"
    RETAIN = "RETAIN"


class FindingOperation(str, Enum):
    """Allowed finding operations per problem_statement.md §6.4."""
    REPORT_REMAINING_RECORD = "REPORT_REMAINING_RECORD"
    REPORT_EXPOSED_PII = "REPORT_EXPOSED_PII"
    REPORT_ACTIVE_DATA_FLOW = "REPORT_ACTIVE_DATA_FLOW"
    REPORT_RESTORE_RISK = "REPORT_RESTORE_RISK"


@dataclass(frozen=True)
class DeletionRule:
    """An individual policy rule loaded from deletion_rules.csv."""
    rule_id: str
    data_category: str
    condition: str
    required_action: PolicyAction


@dataclass
class PolicyFinding:
    """A verified policy violation supported by evidence."""
    rule_id: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str
    reason: str
    severity: str = "HIGH"
    data_category: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
            "reason": self.reason,
            "severity": self.severity,
            "data_category": self.data_category,
        }


@dataclass
class PolicyDecision:
    """Complete, traceable policy outcome for a deletion request."""
    case_id: str
    canonical_user_id: Optional[str]
    deletion_status: DeletionStatus
    findings: List[PolicyFinding] = field(default_factory=list)
    applicable_rule_ids: List[str] = field(default_factory=list)
    evidence_citations: Set[str] = field(default_factory=set)
    reason_codes: List[str] = field(default_factory=list)
    unresolved_conditions: List[str] = field(default_factory=list)
    audit_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "canonical_user_id": self.canonical_user_id,
            "deletion_status": self.deletion_status.value,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "applicable_rules": sorted(self.applicable_rule_ids),
            "evidence_citations": sorted(list(self.evidence_citations)),
            "reason_codes": self.reason_codes,
            "unresolved_conditions": self.unresolved_conditions,
            "audit_at": self.audit_at,
        }


class PolicyEngine:
    """
    Evaluates multi-system reconstructed states against platform deletion rules.
    Strictly deterministic and ground-truth isolated.
    """

    def __init__(self, rules_path: Optional[Path | str] = None) -> None:
        self.rules_path = Path(rules_path) if rules_path else Path("dataset/deletion_rules.csv")
        self.rules: Dict[str, DeletionRule] = {}
        self.rules_by_category: Dict[str, List[DeletionRule]] = {}
        self._load_rules()

    def _load_rules(self) -> None:
        """Loads and parses deletion_rules.csv."""
        if not self.rules_path.exists():
            # Fallback to default in-repo path if invoked from a different working dir
            alt = Path(__file__).resolve().parent.parent / "dataset" / "deletion_rules.csv"
            if alt.exists():
                self.rules_path = alt
            else:
                raise FileNotFoundError(f"Deletion rules file not found: {self.rules_path}")

        with open(self.rules_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rid = row["rule_id"].strip()
                cat = row["data_category"].strip()
                cond = row["condition"].strip()
                act_str = row["required_action"].strip().upper()
                action = PolicyAction(act_str)
                rule = DeletionRule(
                    rule_id=rid,
                    data_category=cat,
                    condition=cond,
                    required_action=action,
                )
                self.rules[rid] = rule
                if cat not in self.rules_by_category:
                    self.rules_by_category[cat] = []
                self.rules_by_category[cat].append(rule)

    def evaluate_request(
        self,
        case_id: str,
        email: str,
        audit_at: str,
        user_id: Optional[str],
        identity: Optional[CanonicalIdentity],
        intent_result: IntentClassificationResult,
        audit_state: Optional[UserSystemAuditState] = None,
    ) -> PolicyDecision:
        """
        Evaluates a request end-to-end, producing a traceable PolicyDecision.
        """
        # 1. Input validation & intent check
        if intent_result.intent == RequestIntent.NOT_APPLICABLE:
            return PolicyDecision(
                case_id=case_id,
                canonical_user_id=user_id,
                deletion_status=DeletionStatus.NOT_APPLICABLE,
                findings=[],
                applicable_rule_ids=[],
                evidence_citations=set(),
                reason_codes=["NON_DELETION_INTENT_NOT_APPLICABLE"],
                audit_at=audit_at,
            )

        if not user_id:
            return PolicyDecision(
                case_id=case_id,
                canonical_user_id=None,
                deletion_status=DeletionStatus.NOT_APPLICABLE,
                findings=[],
                applicable_rule_ids=[],
                evidence_citations=set(),
                reason_codes=["UNRESOLVED_USER_IDENTITY"],
                unresolved_conditions=["No canonical user identity resolved for email."],
                audit_at=audit_at,
            )

        if not audit_state:
            return PolicyDecision(
                case_id=case_id,
                canonical_user_id=user_id,
                deletion_status=DeletionStatus.INCOMPLETE,
                findings=[],
                applicable_rule_ids=[],
                evidence_citations=set(),
                reason_codes=["MISSING_AUDIT_STATE"],
                unresolved_conditions=["No multi-system audit state provided for evaluation."],
                audit_at=audit_at,
            )

        # 2. Evaluate policy against reconstructed resources
        findings: List[PolicyFinding] = []
        applicable_rules: Set[str] = set()
        citations: Set[str] = set()
        reason_codes: List[str] = []

        # System sorting priority for deterministic findings order
        system_finding_order = {
            SystemID.SEARCH_SERVICE.value: 1,
            SystemID.ANALYTICS_PLATFORM.value: 2,
            SystemID.SUPPORT_PLATFORM.value: 3,
            SystemID.EXPORT_SERVICE.value: 4,
            SystemID.INTEGRATION_SERVICE.value: 5,
            SystemID.BACKUP_SERVICE.value: 6,
            SystemID.ACCOUNT_SERVICE.value: 7,
            SystemID.IDENTITY_SERVICE.value: 8,
            SystemID.SECURITY_SERVICE.value: 9,
        }

        # A. Evaluate remaining records (records required to be deleted but still PRESENT)
        for snap in audit_state.remaining_records:
            rule = self._match_rule_for_resource(snap)
            if rule:
                applicable_rules.add(rule.rule_id)
            finding = PolicyFinding(
                rule_id=rule.rule_id if rule else "rule_01",
                system_id=snap.system_id,
                resource_id=snap.resource_id,
                operation=FindingOperation.REPORT_REMAINING_RECORD.value,
                state="PRESENT",
                evidence_id=snap.primary_evidence_id,
                reason=f"Record {snap.resource_id} in {snap.system_id} still exists at audit cutoff.",
                data_category=snap.record_type,
            )
            findings.append(finding)
            if snap.primary_evidence_id:
                citations.add(snap.primary_evidence_id)

        # B. Evaluate exposed PII (records where policy requires redaction/anonymization, but PII remains)
        for snap in audit_state.exposed_pii_records:
            rule = self._match_rule_for_resource(snap)
            if rule:
                applicable_rules.add(rule.rule_id)
            finding = PolicyFinding(
                rule_id=rule.rule_id if rule else "rule_05",
                system_id=snap.system_id,
                resource_id=snap.resource_id,
                operation=FindingOperation.REPORT_EXPOSED_PII.value,
                state="PRESENT",
                evidence_id=snap.primary_evidence_id,
                reason=f"Record {snap.resource_id} in {snap.system_id} exposes personal identifiers contrary to policy.",
                data_category=snap.record_type,
            )
            findings.append(finding)
            if snap.primary_evidence_id:
                citations.add(snap.primary_evidence_id)

        # C. Evaluate active data replication flows (integration_service)
        for snap in audit_state.active_data_flows:
            applicable_rules.add("DATA_FLOW_SYNC_POLICY")
            finding = PolicyFinding(
                rule_id="DATA_FLOW_SYNC_POLICY",
                system_id=snap.system_id,
                resource_id=snap.resource_id,
                operation=FindingOperation.REPORT_ACTIVE_DATA_FLOW.value,
                state="ACTIVE",
                evidence_id=snap.primary_evidence_id,
                reason=f"Active connector {snap.resource_id} can synchronize or recreate user data downstream.",
                data_category="DATA_FLOW",
            )
            findings.append(finding)
            if snap.primary_evidence_id:
                citations.add(snap.primary_evidence_id)

        # D. Evaluate backup restoration risks (backup_service)
        for snap in audit_state.restore_risks:
            applicable_rules.add("rule_14")
            finding = PolicyFinding(
                rule_id="rule_14",
                system_id=snap.system_id,
                resource_id=snap.resource_id,
                operation=FindingOperation.REPORT_RESTORE_RISK.value,
                state="ACTIVE",
                evidence_id=snap.primary_evidence_id,
                reason=f"Backup archive {snap.resource_id} allows restoration of deleted user records.",
                data_category="BACKUP_ARCHIVE",
            )
            findings.append(finding)
            if snap.primary_evidence_id:
                citations.add(snap.primary_evidence_id)

        # Sort findings deterministically by (system_order, resource_id)
        findings.sort(key=lambda f: (system_finding_order.get(f.system_id, 99), f.resource_id))

        # 3. Determine final status
        if findings:
            status = DeletionStatus.INCOMPLETE
            reason_codes.append(f"INCOMPLETE_POLICY_VIOLATIONS_FOUND_{len(findings)}")
        else:
            status = DeletionStatus.COMPLETE
            reason_codes.append("ALL_DELETION_RULES_SATISFIED")
            # For complete cases, citations come from verified compliant snapshots
            for snap in audit_state.verified_compliant_records:
                if snap.primary_evidence_id:
                    citations.add(snap.primary_evidence_id)

        return PolicyDecision(
            case_id=case_id,
            canonical_user_id=user_id,
            deletion_status=status,
            findings=findings,
            applicable_rule_ids=list(applicable_rules),
            evidence_citations=citations,
            reason_codes=reason_codes,
            unresolved_conditions=audit_state.warnings,
            audit_at=audit_at,
        )

    def _match_rule_for_resource(self, snapshot: ResourceStateSnapshot) -> Optional[DeletionRule]:
        """Matches a resource snapshot to its authoritative deletion rule."""
        rtype = snapshot.record_type.upper()
        res_id = snapshot.resource_id.lower()
        sys_id = snapshot.system_id.lower()

        if "tombstone" in res_id or rtype == "ACCOUNT_TOMBSTONE":
            return self.rules.get("rule_15")
        if "audit_record_" in res_id or rtype == "SECURITY_AUDIT_LOG" or sys_id == "security_service":
            return self.rules.get("rule_12")
        if "legal_hold_" in res_id or rtype == "LEGAL_HOLD_RECORD":
            return self.rules.get("rule_13")
        if "backup_" in res_id or rtype == "BACKUP_ARCHIVE" or sys_id == "backup_service":
            return self.rules.get("rule_14")
        if "export_" in res_id or rtype == "USER_EXPORT" or sys_id == "export_service":
            return self.rules.get("rule_09")
        if "search_" in res_id or rtype == "SEARCH_INDEX_ENTRY" or sys_id == "search_service":
            return self.rules.get("rule_03")
        if "analytics_" in res_id or rtype in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY") or sys_id == "analytics_platform":
            return self.rules.get("rule_07")
        if "support_" in res_id or sys_id == "support_platform":
            if "attachment" in rtype or "attachment" in res_id:
                return self.rules.get("rule_06")
            return self.rules.get("rule_05")
        if "account_" in res_id or rtype == "USER_PROFILE" or sys_id == "account_service":
            return self.rules.get("rule_01")

        # Fallback by category
        if rtype in self.rules_by_category and self.rules_by_category[rtype]:
            return self.rules_by_category[rtype][0]

        return None
