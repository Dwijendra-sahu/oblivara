"""
Oblivara - Phase 3: Multi-System Evidence & State Reconstruction Engine
Module: code.evidence_engine

Coordinates ingestion, normalization, indexing, temporal cutoff enforcement,
and multi-system state reconstruction across all 9 connected platform systems.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from code.evidence_models import (
    EvidenceFileType,
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
    _infer_system_from_resource,
    _normalize_iso_timestamp,
)
from code.identity_resolution import CanonicalIdentity, IdentityGraph


def _parse_utc_iso(ts_str: str) -> datetime:
    """Parses an ISO-8601 timestamp string into a timezone-aware UTC datetime."""
    clean = _normalize_iso_timestamp(ts_str)
    if clean.endswith("Z"):
        clean = clean[:-1] + "+00:00"
    return datetime.fromisoformat(clean)


class EvidenceEngine:
    """
    Evidence-driven multi-system audit engine.
    Ingests all participant-visible evidence files, indexes records across systems,
    enforces strict temporal cutoffs, and reconstructs historical resource states.
    """

    def __init__(self, dataset_dir: Path | str = "dataset") -> None:
        self.dataset_dir = Path(dataset_dir)
        self.manifest_path = self.dataset_dir / "evidence_files.csv"
        self.system_activity_path = self.dataset_dir / "system_activity.csv"

        self.manifest_rows: List[Dict[str, str]] = []
        self.all_evidence_records: List[NormalizedEvidenceRecord] = []
        self.activity_stream: List[Dict[str, str]] = []

        # Secondary indexes for rapid retrieval
        self.by_user_id: Dict[str, List[NormalizedEvidenceRecord]] = defaultdict(list)
        self.by_identifier: Dict[str, List[NormalizedEvidenceRecord]] = defaultdict(list)
        self.by_resource_id: Dict[str, List[NormalizedEvidenceRecord]] = defaultdict(list)
        self.by_evidence_id: Dict[str, List[NormalizedEvidenceRecord]] = defaultdict(list)
        self.activities_by_resource: Dict[str, List[Dict[str, str]]] = defaultdict(list)

        self._is_ingested: bool = False

    def ingest_all(self) -> None:
        """Ingests and indexes all 94 manifest evidence files and the global activity stream."""
        if self._is_ingested:
            return

        # 1. Load manifest
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"Manifest not found: {self.manifest_path}")

        with open(self.manifest_path, "r", encoding="utf-8") as f:
            self.manifest_rows = list(csv.DictReader(f))

        # 2. Ingest and parse each evidence file
        for item in self.manifest_rows:
            fid = item["file_id"]
            _ = self.by_evidence_id[fid]  # Ensure key exists in defaultdict for all manifest files
            rel_path = item["file_path"]
            fpath = self.dataset_dir / rel_path
            orig = item["origin"]
            cap_time = _normalize_iso_timestamp(item["captured_at"])
            ext = fpath.suffix.lower()

            recs: List[NormalizedEvidenceRecord] = []
            if ext == ".sql":
                recs = SQLSnapshotParser.parse_file(fpath, fid, orig, cap_time)
            elif ext in (".json", ".txt"):
                recs = StructuredRecordParser.parse_file(fpath, fid, orig, cap_time)
            elif ext == ".log":
                recs = LogParser.parse_file(fpath, fid, orig, cap_time)
            elif ext == ".pdf":
                recs = DocumentParser.parse_file(fpath, fid, orig, cap_time)
            elif ext == ".png":
                recs = ImageMetadataParser.parse_file(fpath, fid, orig, cap_time)

            for r in recs:
                self.all_evidence_records.append(r)
                self.by_evidence_id[r.evidence_id].append(r)
                if r.user_id:
                    self.by_user_id[r.user_id].append(r)
                if r.matched_identifier:
                    self.by_identifier[r.matched_identifier.lower().strip()].append(r)
                if r.resource_id:
                    self.by_resource_id[r.resource_id].append(r)

        # 3. Load system activity stream
        if self.system_activity_path.exists():
            with open(self.system_activity_path, "r", encoding="utf-8") as f:
                self.activity_stream = list(csv.DictReader(f))
                for act in self.activity_stream:
                    res_id = act.get("resource_id", "")
                    if res_id:
                        self.activities_by_resource[res_id].append(act)

        self._is_ingested = True

    def get_user_evidence(
        self,
        user_id: str,
        identity: Optional[CanonicalIdentity],
        audit_at: str,
        request_window: Optional[Tuple[str, str]] = None
    ) -> Tuple[List[NormalizedEvidenceRecord], List[NormalizedEvidenceRecord]]:
        """
        Retrieves all evidence associated with a user, strictly partitioned by audit_at cutoff.
        Optionally correlates deletion worker target resources within request_window (requested_at, reported_at).
        Returns: (valid_historical_evidence, post_cutoff_quarantined_evidence)
        """
        if not self._is_ingested:
            self.ingest_all()

        audit_dt = _parse_utc_iso(audit_at)
        candidate_records: Set[int] = set()

        # 1. Gather by canonical user_id
        for r in self.by_user_id.get(user_id, []):
            candidate_records.add(id(r))

        # 2. Gather by all current and historical identifiers
        if identity:
            for em in identity.all_emails():
                for r in self.by_identifier.get(em.lower().strip(), []):
                    candidate_records.add(id(r))
            for ph in identity.all_phones():
                for r in self.by_identifier.get(ph.strip(), []):
                    candidate_records.add(id(r))
            for h in identity.all_email_hashes():
                for r in self.by_identifier.get(h.lower().strip(), []):
                    candidate_records.add(id(r))

        # 3. Optional: Correlate target resources from deletion worker activity stream within request window
        target_resources: Set[str] = set()
        if user_id.startswith("user_"):
            parts = user_id.split("_")
            if len(parts) > 1 and parts[1].isdigit():
                target_resources.add(f"account_{parts[1].zfill(3)}")

        if request_window:
            req_t, rep_t = request_window
            t_req = _parse_utc_iso(req_t)
            t_rep = _parse_utc_iso(rep_t)
            from datetime import timedelta
            user_emails = identity.all_emails() if identity else set()
            user_phones = identity.all_phones() if identity else set()
            user_hashes = identity.all_email_hashes() if identity else set()

            for act in self.activity_stream:
                if act.get("source_system") == "deletion_worker":
                    act_t = _parse_utc_iso(act["event_time"])
                    if (t_req - timedelta(minutes=15)) <= act_t <= (t_rep + timedelta(minutes=15)):
                        target_res = act.get("resource_id")
                        if target_res:
                            # Verify target_res does not belong to a different user
                            res_recs = self.by_resource_id.get(target_res, [])
                            other_user = False
                            for r in res_recs:
                                if r.user_id and r.user_id != user_id:
                                    other_user = True
                                    break
                                if r.matched_identifier:
                                    mid = r.matched_identifier.strip()
                                    if "@" in mid and mid.lower() not in user_emails:
                                        other_user = True
                                        break
                                    if mid.startswith("+") and mid not in user_phones:
                                        other_user = True
                                        break
                            if not other_user:
                                target_resources.add(target_res)
                                for r in res_recs:
                                    candidate_records.add(id(r))

        # 4. Partition candidate records strictly by audit_at with cross-user guard
        id_map = {id(r): r for r in self.all_evidence_records}
        valid_records: List[NormalizedEvidenceRecord] = []
        post_cutoff_records: List[NormalizedEvidenceRecord] = []

        user_emails = identity.all_emails() if identity else set()
        user_phones = identity.all_phones() if identity else set()

        for rec_id in candidate_records:
            rec = id_map[rec_id]
            # Cross-user contamination guard
            if rec.user_id and rec.user_id != user_id:
                continue
            if rec.matched_identifier:
                mid = rec.matched_identifier.strip()
                if "@" in mid and mid.lower() not in user_emails:
                    continue
                if mid.startswith("+") and mid not in user_phones:
                    continue

            cap_dt = _parse_utc_iso(rec.captured_at)
            obs_dt = _parse_utc_iso(rec.observed_at)

            # Contract §6.2: Evidence strictly after audit_at must NOT influence the decision
            if cap_dt <= audit_dt and obs_dt <= audit_dt:
                valid_records.append(rec)
            else:
                post_cutoff_records.append(rec)

        # 5. For target resources from workflow activity that are absent from evidence up to audit_at:
        # Verify absence against the latest replica/assurance snapshot available at or before audit_at
        present_res_ids = {r.resource_id for r in valid_records if r.operational_state == OperationalState.PRESENT}
        already_covered_ids = {r.resource_id for r in valid_records}
        for tr in target_resources:
            if tr not in already_covered_ids and tr not in present_res_ids:
                sys_id = _infer_system_from_resource(tr)
                # Find latest evidence snapshot covering this service at or before audit_at
                best_ev = self._find_latest_assurance_evidence(sys_id, audit_dt)
                if best_ev:
                    synth_rec = NormalizedEvidenceRecord(
                        evidence_id=best_ev["file_id"],
                        source_file=best_ev["file_path"],
                        source_system=best_ev["origin"],
                        source_record_id=f"replica_absence:{tr}",
                        captured_at=best_ev["captured_at"],
                        observed_at=best_ev["captured_at"],
                        record_type="USER_PROFILE" if sys_id == "account_service" else "RECORD",
                        resource_id=tr,
                        system_id=sys_id,
                        user_id=user_id,
                        operational_state=OperationalState.ABSENT,
                        provenance=f"REPLICA_ABSENCE:{best_ev['file_id']}:{tr}",
                        confidence=1.0
                    )
                    valid_records.append(synth_rec)

        # Sort valid records chronologically
        valid_records.sort(key=lambda x: (x.observed_at, x.captured_at, x.evidence_id))
        return valid_records, post_cutoff_records

    def _find_latest_assurance_evidence(self, system_id: str, audit_dt: datetime) -> Optional[Dict[str, str]]:
        """Finds the most authoritative datastore replica or export snapshot captured at or before audit_dt."""
        candidates = []
        for m in self.manifest_rows:
            cap_dt = _parse_utc_iso(m["captured_at"])
            if cap_dt <= audit_dt:
                path_lower = m["file_path"].lower()
                origin_lower = m["origin"].lower()
                score = 0
                if system_id == "account_service":
                    if "replica" in path_lower or "replica" in origin_lower:
                        score = 10
                    elif "service_resource_export" in path_lower or "snapshot_bundle" in path_lower:
                        score = 8
                    elif "handover" in path_lower:
                        score = 7
                else:
                    if "service_resource_export" in path_lower:
                        score = 10
                    elif "snapshot_bundle" in path_lower:
                        score = 8
                    elif "inventory" in path_lower:
                        score = 6
                if score > 0:
                    candidates.append((score, cap_dt, m))

        if candidates:
            candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)
            return candidates[0][2]
        return None

    def reconstruct_user_state(
        self,
        user_id: str,
        identity: Optional[CanonicalIdentity],
        audit_at: str,
        request_window: Optional[Tuple[str, str]] = None
    ) -> UserSystemAuditState:
        """
        Reconstructs the multi-system data and operational state of a user at audit_at.
        Evaluates resource existence, replication drift, active sync flows, and restore risks.
        """
        valid_records, post_cutoff = self.get_user_evidence(
            user_id=user_id,
            identity=identity,
            audit_at=audit_at,
            request_window=request_window
        )

        # Group valid records by (system_id, resource_id)
        resource_evidence_map: Dict[Tuple[str, str], List[NormalizedEvidenceRecord]] = defaultdict(list)
        for r in valid_records:
            if r.resource_id:
                resource_evidence_map[(r.system_id, r.resource_id)].append(r)

        audit_state = UserSystemAuditState(
            user_id=user_id,
            audit_at=audit_at,
            cutoff_enforced=True,
            all_evidence_considered=valid_records,
            post_cutoff_evidence_ignored=post_cutoff
        )

        for (sys_id, res_id), recs in sorted(resource_evidence_map.items()):
            snapshot = self._evaluate_resource_snapshot(
                system_id=sys_id,
                resource_id=res_id,
                records=recs,
                identity=identity,
                audit_at=audit_at
            )
            audit_state.resources[res_id] = snapshot

            # Categorize into state buckets for downstream auditing
            if snapshot.operational_state == OperationalState.PRESENT:
                if snapshot.is_policy_retained:
                    audit_state.verified_compliant_records.append(snapshot)
                elif snapshot.has_exposed_pii:
                    audit_state.exposed_pii_records.append(snapshot)
                else:
                    audit_state.remaining_records.append(snapshot)

            elif snapshot.operational_state == OperationalState.ACTIVE:
                if snapshot.is_active_flow:
                    audit_state.active_data_flows.append(snapshot)
                elif snapshot.is_restore_risk:
                    audit_state.restore_risks.append(snapshot)

            elif snapshot.operational_state in (
                OperationalState.ABSENT,
                OperationalState.REDACTED,
                OperationalState.ANONYMIZED,
                OperationalState.DISABLED,
                OperationalState.BLOCKED
            ):
                audit_state.verified_compliant_records.append(snapshot)

        return audit_state

    def _evaluate_resource_snapshot(
        self,
        system_id: str,
        resource_id: str,
        records: List[NormalizedEvidenceRecord],
        identity: Optional[CanonicalIdentity],
        audit_at: str
    ) -> ResourceStateSnapshot:
        """
        Evaluates the net state of a specific resource across all its replicas and log traces.
        Handles replication drift (e.g. absent in primary, present in failover/read replica).
        """
        # Sort latest evidence first, prioritizing definitive status events over start events at the same timestamp
        def _sort_key(r: NormalizedEvidenceRecord):
            is_definitive = 1 if (r.operational_state != OperationalState.PRESENT or "completed" in r.record_type.lower()) else 0
            return (r.observed_at, r.captured_at, is_definitive)

        sorted_recs = sorted(records, key=_sort_key, reverse=True)
        primary_rec = sorted_recs[0]
        rec_type = primary_rec.record_type

        # Check for any replica proving the record is still physically present
        any_replica_present = any(
            r.operational_state == OperationalState.PRESENT and "replica" in r.source_file.lower()
            for r in records
        )
        any_replica_absent = any(
            r.operational_state == OperationalState.ABSENT
            for r in records
        )

        # Base operational state
        op_state = primary_rec.operational_state

        # If primary claims absent but a replica snapshot contains the record -> REPLICATION DRIFT (PRESENT)
        if any_replica_present:
            op_state = OperationalState.PRESENT

        # Flags
        has_exposed_pii = False
        is_active_flow = False
        is_restore_risk = False
        is_tombstone = "tombstone" in resource_id or rec_type == "ACCOUNT_TOMBSTONE"
        is_policy_retained = (
            rec_type in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD", "BACKUP_ARCHIVE") or
            resource_id.startswith("audit_record_") or
            resource_id.startswith("legal_hold_") or
            system_id == SystemID.SECURITY_SERVICE.value
        )
        if resource_id.startswith("audit_record_"):
            rec_type = "SECURITY_AUDIT_LOG"

        # System-specific state refinement
        if system_id == SystemID.INTEGRATION_SERVICE.value or resource_id.startswith("data_flow_"):
            is_active = any(
                r.operational_state == OperationalState.ACTIVE or
                str(r.data_attributes.get("enabled")).lower() in ("true", "1")
                for r in records
            )
            is_disabled = any(
                r.operational_state == OperationalState.DISABLED or
                str(r.data_attributes.get("enabled")).lower() in ("false", "0")
                for r in records
            )
            if is_active:
                op_state = OperationalState.ACTIVE
                is_active_flow = True
            elif is_disabled:
                op_state = OperationalState.DISABLED

        elif system_id == SystemID.BACKUP_SERVICE.value or resource_id.startswith("backup_"):
            is_active = any(
                r.operational_state == OperationalState.ACTIVE or
                str(r.data_attributes.get("restore_allowed")).lower() in ("true", "1")
                for r in records
            )
            is_blocked = any(
                r.operational_state == OperationalState.BLOCKED or
                str(r.data_attributes.get("restore_allowed")).lower() in ("false", "0")
                for r in records
            )
            if is_active:
                op_state = OperationalState.ACTIVE
                is_restore_risk = True
            elif is_blocked:
                op_state = OperationalState.BLOCKED

        elif system_id == SystemID.ANALYTICS_PLATFORM.value or resource_id.startswith("analytics_"):
            # Check if this is a marketing / contact record (Rule 10: DELETE -> REPORT_REMAINING_RECORD)
            # or an analytics profile / telemetry (Rule 07/08: ANONYMIZE -> REPORT_EXPOSED_PII)
            is_marketing_contact = any(
                r.data_attributes.get("event") == "contact_lookup_completed" or
                r.data_attributes.get("email_opt_in") is not None
                for r in records
            )
            is_anon = any(r.operational_state == OperationalState.ANONYMIZED for r in records)
            has_ident = any(
                r.matched_identifier or
                (r.data_attributes.get("email") and str(r.data_attributes.get("email")).lower() not in ("none", "null", "")) or
                (r.data_attributes.get("phone") and str(r.data_attributes.get("phone")).lower() not in ("none", "null", "")) or
                (r.data_attributes.get("email_hash") and str(r.data_attributes.get("email_hash")).lower() not in ("none", "null", ""))
                for r in records
            )
            if is_anon and not has_ident:
                op_state = OperationalState.ANONYMIZED
            elif has_ident and op_state != OperationalState.ABSENT:
                if not is_marketing_contact:
                    has_exposed_pii = True
                op_state = OperationalState.PRESENT

        elif system_id == SystemID.SUPPORT_PLATFORM.value or resource_id.startswith("support_"):
            # Check if this support resource was targeted for full deletion (DELETE_RECORD) or redaction (REDACT_RECORD)
            worker_ops = [
                act.get("event_type")
                for act in self.activities_by_resource.get(resource_id, [])
                if act.get("source_system") == "deletion_worker"
            ]
            is_full_deletion = (
                "DELETE_RECORD" in worker_ops or
                rec_type == "SUPPORT_ATTACHMENT" or
                any(r.data_attributes.get("source") == "legacy_contact_index" for r in records)
            )
            has_contact = any(
                r.matched_identifier or
                (r.data_attributes.get("requester_email") and str(r.data_attributes.get("requester_email")).lower() not in ("none", "null", "")) or
                (r.data_attributes.get("requester_phone") and str(r.data_attributes.get("requester_phone")).lower() not in ("none", "null", "")) or
                r.data_attributes.get("result") == "IDENTIFIABLE" or
                r.data_attributes.get("event") == "message_pii_scan"
                for r in records
            )
            if has_contact and op_state != OperationalState.ABSENT:
                if not is_full_deletion:
                    has_exposed_pii = True
                op_state = OperationalState.PRESENT
            elif not is_full_deletion and op_state != OperationalState.ABSENT:
                op_state = OperationalState.REDACTED

        elif is_tombstone:
            has_direct_pii = any(
                r.matched_identifier or r.data_attributes.get("email") or r.data_attributes.get("phone")
                for r in records
            )
            if has_direct_pii:
                has_exposed_pii = True
                op_state = OperationalState.PRESENT
            else:
                op_state = OperationalState.REDACTED

        return ResourceStateSnapshot(
            resource_id=resource_id,
            system_id=system_id,
            record_type=rec_type,
            operational_state=op_state,
            primary_evidence_id=primary_rec.evidence_id,
            effective_timestamp=primary_rec.observed_at,
            has_exposed_pii=has_exposed_pii,
            is_active_flow=is_active_flow,
            is_restore_risk=is_restore_risk,
            is_tombstone=is_tombstone,
            is_policy_retained=is_policy_retained,
            supporting_evidence=records
        )
