"""
Oblivara - Phase 3: Evidence Ingestion & Multi-System State Reconstruction
Module: code.evidence_models

Defines the normalized evidence representation, operational state enums,
and resource state snapshots across all 9 connected platform systems.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class OperationalState(str, Enum):
    """Normalized operational state of a resource or data copy."""
    PRESENT = "PRESENT"          # Record physically exists in datastore/index/log
    ABSENT = "ABSENT"            # Confirmed absent (404, 0 rows, not found, deleted)
    REDACTED = "REDACTED"        # Present but identifying fields removed/masked
    ANONYMIZED = "ANONYMIZED"    # Present but unlinked from user identity
    ACTIVE = "ACTIVE"            # Active sync flow or unblocked restore risk
    DISABLED = "DISABLED"        # Data connector / flow confirmed stopped
    BLOCKED = "BLOCKED"          # Backup restore access confirmed blocked
    UNKNOWN = "UNKNOWN"          # Indeterminate state


class SystemID(str, Enum):
    """The 9 authoritative platform systems supported by Oblivara."""
    ACCOUNT_SERVICE = "account_service"
    SEARCH_SERVICE = "search_service"
    SUPPORT_PLATFORM = "support_platform"
    ANALYTICS_PLATFORM = "analytics_platform"
    BACKUP_SERVICE = "backup_service"
    INTEGRATION_SERVICE = "integration_service"
    EXPORT_SERVICE = "export_service"
    IDENTITY_SERVICE = "identity_service"
    SECURITY_SERVICE = "security_service"


class EvidenceFileType(str, Enum):
    """Format classification of evidence files."""
    SQL = "SQL"
    JSON = "JSON"
    LOG = "LOG"
    PDF = "PDF"
    PNG = "PNG"
    TXT = "TXT"


@dataclass
class NormalizedEvidenceRecord:
    """
    Unified canonical representation of a parsed evidence observation.
    Captures raw datastore/log attributes, temporal anchors, and evidentiary provenance.
    """
    evidence_id: str                          # e.g., 'evidence_54'
    source_file: str                          # e.g., 'evidence/databases/customer_accounts_failover_replica_20260902.sql'
    source_system: str                        # e.g., 'customer_account_failover_replica_capture'
    source_record_id: str                     # row index, table name, line number, or page
    captured_at: str                          # Manifest capture timestamp (ISO-8601 UTC)
    observed_at: str                          # Row/event timestamp (ISO-8601 UTC)
    record_type: str                          # e.g. 'USER_PROFILE', 'SEARCH_INDEX_ENTRY', 'DATA_FLOW', etc.
    resource_id: str                          # e.g., 'account_005', 'search_001', 'data_flow_3827'
    system_id: str                            # Authoritative SystemID string
    user_id: Optional[str] = None             # Matched user_id if resolved
    matched_identifier: Optional[str] = None  # Exact email, phone, or hash that triggered match
    data_attributes: Dict[str, Any] = field(default_factory=dict)
    operational_state: OperationalState = OperationalState.UNKNOWN
    provenance: str = ""
    confidence: float = 1.0
    raw_data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source_file": self.source_file,
            "source_system": self.source_system,
            "source_record_id": self.source_record_id,
            "captured_at": self.captured_at,
            "observed_at": self.observed_at,
            "record_type": self.record_type,
            "resource_id": self.resource_id,
            "system_id": self.system_id,
            "user_id": self.user_id,
            "matched_identifier": self.matched_identifier,
            "data_attributes": self.data_attributes,
            "operational_state": self.operational_state.value,
            "provenance": self.provenance,
            "confidence": self.confidence
        }


@dataclass
class ResourceStateSnapshot:
    """
    Reconstructed state of an individual system resource for a user
    at a specific audit timestamp cutoff.
    """
    resource_id: str
    system_id: str
    record_type: str
    operational_state: OperationalState
    primary_evidence_id: str
    effective_timestamp: str
    has_exposed_pii: bool = False
    is_active_flow: bool = False
    is_restore_risk: bool = False
    is_tombstone: bool = False
    is_policy_retained: bool = False
    supporting_evidence: List[NormalizedEvidenceRecord] = field(default_factory=list)
    recreation_sources: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "system_id": self.system_id,
            "record_type": self.record_type,
            "operational_state": self.operational_state.value,
            "primary_evidence_id": self.primary_evidence_id,
            "effective_timestamp": self.effective_timestamp,
            "has_exposed_pii": self.has_exposed_pii,
            "is_active_flow": self.is_active_flow,
            "is_restore_risk": self.is_restore_risk,
            "is_tombstone": self.is_tombstone,
            "is_policy_retained": self.is_policy_retained,
            "supporting_evidence_count": len(self.supporting_evidence),
            "recreation_sources": self.recreation_sources
        }


@dataclass
class UserSystemAuditState:
    """
    Multi-system state reconstruction for a user at an audit timestamp.
    Aggregates all discovered resources, remaining records, flows, and restore risks.
    """
    user_id: str
    audit_at: str
    cutoff_enforced: bool
    resources: Dict[str, ResourceStateSnapshot] = field(default_factory=dict)
    remaining_records: List[ResourceStateSnapshot] = field(default_factory=list)
    exposed_pii_records: List[ResourceStateSnapshot] = field(default_factory=list)
    active_data_flows: List[ResourceStateSnapshot] = field(default_factory=list)
    restore_risks: List[ResourceStateSnapshot] = field(default_factory=list)
    verified_compliant_records: List[ResourceStateSnapshot] = field(default_factory=list)
    all_evidence_considered: List[NormalizedEvidenceRecord] = field(default_factory=list)
    post_cutoff_evidence_ignored: List[NormalizedEvidenceRecord] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "audit_at": self.audit_at,
            "cutoff_enforced": self.cutoff_enforced,
            "resource_count": len(self.resources),
            "remaining_records_count": len(self.remaining_records),
            "exposed_pii_count": len(self.exposed_pii_records),
            "active_data_flows_count": len(self.active_data_flows),
            "restore_risks_count": len(self.restore_risks),
            "verified_compliant_count": len(self.verified_compliant_records),
            "evidence_count": len(self.all_evidence_considered),
            "post_cutoff_count": len(self.post_cutoff_evidence_ignored),
            "warnings": self.warnings
        }
