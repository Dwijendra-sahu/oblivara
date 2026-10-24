"""
Oblivara - Phase 2: Identity Graph Engine
Module: code.identity_resolution

Responsible for:
1. Constructing a unified, type-safe entity identity graph from current snapshots
   (user_identities.csv) and historical audit events (user_audit_log.csv).
2. Resolving inbound deletion request identifiers (e.g. emails) to canonical user_id
   values with strict provenance tracking.
3. Distinguishing current primary identifiers from verified historical mutations.
4. Detecting duplicate identifiers, conflicting ownership, and avoiding false merges
   across users with shared names or phones.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class IdentifierType(str, Enum):
    """Categorization of individual identity attributes."""
    USER_ID = "USER_ID"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    NAME = "NAME"
    EMAIL_HASH = "EMAIL_HASH"


class ResolutionStatus(str, Enum):
    """Status of resolving an identity key to a canonical user."""
    RESOLVED = "RESOLVED"
    AMBIGUOUS = "AMBIGUOUS"
    UNRESOLVED = "UNRESOLVED"


class ResolutionConfidence(str, Enum):
    """Level of evidentiary certainty in the resolution."""
    CURRENT_PRIMARY = "CURRENT_PRIMARY"       # Verified in current identity snapshot
    HISTORICAL_AUDIT = "HISTORICAL_AUDIT"     # Verified through documented mutation in audit log
    CONFLICTING_OWNERSHIP = "CONFLICTING"     # Multiple users claim this identifier
    NONE = "NONE"                             # No valid relationship found


@dataclass(frozen=True)
class IdentifierRecord:
    """An immutable record of a specific identity attribute with full provenance."""
    val_raw: str
    val_normalized: str
    id_type: IdentifierType
    provenance_source: str      # e.g., 'user_identities.csv:user_01'
    event_time: Optional[str] = None
    is_current: bool = True

    @classmethod
    def create(
        cls,
        val: str,
        id_type: IdentifierType,
        source: str,
        event_time: Optional[str] = None,
        is_current: bool = True
    ) -> IdentifierRecord:
        raw = val.strip() if val else ""
        norm = normalize_identifier(raw, id_type)
        return cls(
            val_raw=raw,
            val_normalized=norm,
            id_type=id_type,
            provenance_source=source,
            event_time=event_time,
            is_current=is_current
        )


def normalize_identifier(val: str, id_type: IdentifierType) -> str:
    """Deterministic normalization for matching while preserving the raw value."""
    if not val:
        return ""
    v = val.strip()
    if id_type in (IdentifierType.EMAIL, IdentifierType.EMAIL_HASH):
        return v.lower()
    if id_type == IdentifierType.PHONE:
        # Normalize whitespace in phone numbers but preserve international prefix
        return re.sub(r'\s+', ' ', v)
    if id_type == IdentifierType.NAME:
        # Lowercase, collapse spaces
        return re.sub(r'\s+', ' ', v.lower())
    return v


@dataclass
class CanonicalIdentity:
    """A canonical user entity containing current and historical identifier lineage."""
    user_id: str
    current_email: IdentifierRecord
    current_name: Optional[IdentifierRecord] = None
    current_phone: Optional[IdentifierRecord] = None
    current_email_hash: Optional[IdentifierRecord] = None
    
    historical_emails: List[IdentifierRecord] = field(default_factory=list)
    historical_phones: List[IdentifierRecord] = field(default_factory=list)
    historical_names: List[IdentifierRecord] = field(default_factory=list)
    historical_email_hashes: List[IdentifierRecord] = field(default_factory=list)

    def all_emails(self) -> Set[str]:
        """Returns all normalized current and historical emails."""
        emails = {self.current_email.val_normalized}
        for rec in self.historical_emails:
            if rec.val_normalized:
                emails.add(rec.val_normalized)
        return emails

    def all_phones(self) -> Set[str]:
        """Returns all normalized current and historical phones."""
        phones = set()
        if self.current_phone and self.current_phone.val_normalized:
            phones.add(self.current_phone.val_normalized)
        for rec in self.historical_phones:
            if rec.val_normalized:
                phones.add(rec.val_normalized)
        return phones

    def all_email_hashes(self) -> Set[str]:
        """Returns all normalized current and historical email hashes."""
        hashes = set()
        if self.current_email_hash and self.current_email_hash.val_normalized:
            hashes.add(self.current_email_hash.val_normalized)
        for rec in self.historical_email_hashes:
            if rec.val_normalized:
                hashes.add(rec.val_normalized)
        return hashes

    def get_summary_identifiers(self) -> Dict[str, List[str]]:
        """Returns a structured dictionary of all identifiers for reporting."""
        return {
            "user_id": [self.user_id],
            "emails": sorted(list(self.all_emails())),
            "phones": sorted(list(self.all_phones())),
            "email_hashes": sorted(list(self.all_email_hashes())),
            "names": [self.current_name.val_raw] if self.current_name else []
        }


@dataclass
class IdentityResolutionResult:
    """Structured output from attempting to resolve a request to a canonical identity."""
    request_id: str
    input_identifier: str
    input_type: IdentifierType
    status: ResolutionStatus
    confidence: ResolutionConfidence
    canonical_user_id: Optional[str] = None
    matched_record: Optional[IdentifierRecord] = None
    identity: Optional[CanonicalIdentity] = None
    provenance_chain: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "input_identifier": self.input_identifier,
            "input_type": self.input_type.value,
            "status": self.status.value,
            "confidence": self.confidence.value,
            "canonical_user_id": self.canonical_user_id,
            "matched_record": (
                {
                    "raw": self.matched_record.val_raw,
                    "normalized": self.matched_record.val_normalized,
                    "provenance": self.matched_record.provenance_source,
                    "is_current": self.matched_record.is_current,
                    "event_time": self.matched_record.event_time
                }
                if self.matched_record else None
            ),
            "known_identifiers": self.identity.get_summary_identifiers() if self.identity else {},
            "provenance_chain": self.provenance_chain,
            "warnings": self.warnings
        }


class IdentityGraph:
    """
    In-memory identity graph that tracks all user identifiers, historical mutations,
    and handles deterministic resolution without hardcoded customer identifiers.
    """

    def __init__(self) -> None:
        self.users: Dict[str, CanonicalIdentity] = {}
        # Exact lookup indexes (normalized identifier -> set of user_ids)
        self.current_email_index: Dict[str, str] = {}
        self.historical_email_index: Dict[str, Dict[str, IdentifierRecord]] = {} # email -> {user_id: record}
        self.phone_index: Dict[str, Set[str]] = {}
        self.email_hash_index: Dict[str, Set[str]] = {}
        self.name_index: Dict[str, Set[str]] = {}
        self.conflicts: List[str] = []

    def load_from_csv(
        self,
        user_identities_path: str | Path,
        user_audit_log_path: str | Path
    ) -> None:
        """Loads and builds the identity graph from CSV files."""
        self._load_current_identities(user_identities_path)
        self._load_audit_mutations(user_audit_log_path)

    def _load_current_identities(self, path: str | Path) -> None:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Identity file not found: {p}")

        with open(p, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            required = {"user_id", "name", "email", "phone", "email_hash", "updated_at"}
            if not required.issubset(set(reader.fieldnames or [])):
                raise ValueError(f"Missing required columns in {path}: {required - set(reader.fieldnames or [])}")

            for row in reader:
                uid = row["user_id"].strip()
                if not uid:
                    continue

                email_rec = IdentifierRecord.create(
                    val=row["email"],
                    id_type=IdentifierType.EMAIL,
                    source=f"user_identities.csv:{uid}",
                    event_time=row["updated_at"].strip(),
                    is_current=True
                )
                name_rec = IdentifierRecord.create(
                    val=row["name"],
                    id_type=IdentifierType.NAME,
                    source=f"user_identities.csv:{uid}",
                    event_time=row["updated_at"].strip(),
                    is_current=True
                ) if row.get("name") else None

                phone_rec = IdentifierRecord.create(
                    val=row["phone"],
                    id_type=IdentifierType.PHONE,
                    source=f"user_identities.csv:{uid}",
                    event_time=row["updated_at"].strip(),
                    is_current=True
                ) if row.get("phone") else None

                hash_rec = IdentifierRecord.create(
                    val=row["email_hash"],
                    id_type=IdentifierType.EMAIL_HASH,
                    source=f"user_identities.csv:{uid}",
                    event_time=row["updated_at"].strip(),
                    is_current=True
                ) if row.get("email_hash") else None

                # Build user model
                user = CanonicalIdentity(
                    user_id=uid,
                    current_email=email_rec,
                    current_name=name_rec,
                    current_phone=phone_rec,
                    current_email_hash=hash_rec
                )
                self.users[uid] = user

                # Index primary email
                norm_email = email_rec.val_normalized
                if norm_email in self.current_email_index:
                    prev_uid = self.current_email_index[norm_email]
                    self.conflicts.append(f"Duplicate current email '{norm_email}' between {prev_uid} and {uid}")
                else:
                    self.current_email_index[norm_email] = uid

                # Index phone (supporting many-to-many check)
                if phone_rec and phone_rec.val_normalized:
                    self.phone_index.setdefault(phone_rec.val_normalized, set()).add(uid)

                # Index hash
                if hash_rec and hash_rec.val_normalized:
                    self.email_hash_index.setdefault(hash_rec.val_normalized, set()).add(uid)

                # Index name (to track shared names)
                if name_rec and name_rec.val_normalized:
                    self.name_index.setdefault(name_rec.val_normalized, set()).add(uid)

    def _load_audit_mutations(self, path: str | Path) -> None:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Audit log file not found: {p}")

        with open(p, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            required = {"audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"}
            if not required.issubset(set(reader.fieldnames or [])):
                raise ValueError(f"Missing required columns in {path}: {required - set(reader.fieldnames or [])}")

            for row in reader:
                audit_id = row["audit_id"].strip()
                uid = row["user_id"].strip()
                event_time = row["event_time"].strip()
                field_name = row["field_name"].strip()
                old_val = row.get("old_value", "").strip()

                if uid not in self.users or not old_val:
                    continue

                user = self.users[uid]

                if field_name == "email":
                    rec = IdentifierRecord.create(
                        val=old_val,
                        id_type=IdentifierType.EMAIL,
                        source=f"user_audit_log.csv:{audit_id}",
                        event_time=event_time,
                        is_current=False
                    )
                    user.historical_emails.append(rec)
                    self.historical_email_index.setdefault(rec.val_normalized, {})[uid] = rec

                elif field_name == "phone":
                    rec = IdentifierRecord.create(
                        val=old_val,
                        id_type=IdentifierType.PHONE,
                        source=f"user_audit_log.csv:{audit_id}",
                        event_time=event_time,
                        is_current=False
                    )
                    user.historical_phones.append(rec)
                    self.phone_index.setdefault(rec.val_normalized, set()).add(uid)

                elif field_name == "name":
                    rec = IdentifierRecord.create(
                        val=old_val,
                        id_type=IdentifierType.NAME,
                        source=f"user_audit_log.csv:{audit_id}",
                        event_time=event_time,
                        is_current=False
                    )
                    user.historical_names.append(rec)
                    self.name_index.setdefault(rec.val_normalized, set()).add(uid)

                elif field_name == "email_hash":
                    rec = IdentifierRecord.create(
                        val=old_val,
                        id_type=IdentifierType.EMAIL_HASH,
                        source=f"user_audit_log.csv:{audit_id}",
                        event_time=event_time,
                        is_current=False
                    )
                    user.historical_email_hashes.append(rec)
                    self.email_hash_index.setdefault(rec.val_normalized, set()).add(uid)

    def resolve_email(self, request_id: str, email: str) -> IdentityResolutionResult:
        """
        Resolves an email from a deletion request to a canonical user_id.
        Matching Precedence:
        1. Exact match against current_email_index (Confidence: CURRENT_PRIMARY).
        2. Exact match against historical_email_index (Confidence: HISTORICAL_AUDIT).
        3. If multiple users claim this email -> AMBIGUOUS (Confidence: CONFLICTING_OWNERSHIP).
        4. If not found -> UNRESOLVED (Confidence: NONE).
        """
        raw_email = email if email is not None else ""
        norm_email = normalize_identifier(raw_email, IdentifierType.EMAIL)

        if not norm_email:
            return IdentityResolutionResult(
                request_id=request_id,
                input_identifier=raw_email,
                input_type=IdentifierType.EMAIL,
                status=ResolutionStatus.UNRESOLVED,
                confidence=ResolutionConfidence.NONE,
                warnings=["Empty email identifier provided"]
            )

        # Step 1: Check Current Email Index
        current_uid = self.current_email_index.get(norm_email)
        historical_uids_map = self.historical_email_index.get(norm_email, {})
        historical_uids = set(historical_uids_map.keys())

        # Check for conflicting ownership (different users claiming current vs historical or multiple historicals)
        all_claiming_uids = set()
        if current_uid:
            all_claiming_uids.add(current_uid)
        all_claiming_uids.update(historical_uids)

        if len(all_claiming_uids) > 1:
            return IdentityResolutionResult(
                request_id=request_id,
                input_identifier=raw_email,
                input_type=IdentifierType.EMAIL,
                status=ResolutionStatus.AMBIGUOUS,
                confidence=ResolutionConfidence.CONFLICTING_OWNERSHIP,
                canonical_user_id=None,
                warnings=[
                    f"Conflicting email ownership: '{raw_email}' claimed by multiple users: {sorted(list(all_claiming_uids))}"
                ]
            )

        # Unique current match
        if current_uid:
            user = self.users[current_uid]
            warnings = []
            # Check if user's name is shared with other users
            if user.current_name and len(self.name_index.get(user.current_name.val_normalized, set())) > 1:
                warnings.append(
                    f"User '{current_uid}' shares full name '{user.current_name.val_raw}' with other users. "
                    "Name was not used for resolution."
                )

            return IdentityResolutionResult(
                request_id=request_id,
                input_identifier=raw_email,
                input_type=IdentifierType.EMAIL,
                status=ResolutionStatus.RESOLVED,
                confidence=ResolutionConfidence.CURRENT_PRIMARY,
                canonical_user_id=current_uid,
                matched_record=user.current_email,
                identity=user,
                provenance_chain=[user.current_email.provenance_source],
                warnings=warnings
            )

        # Step 2: Unique Historical Match
        if len(historical_uids) == 1:
            hist_uid = next(iter(historical_uids))
            user = self.users[hist_uid]
            matched_rec = historical_uids_map[hist_uid]
            warnings = [
                f"Resolved via historical audit log mutation at {matched_rec.event_time}. "
                f"Current email on account is '{user.current_email.val_raw}'."
            ]
            if user.current_name and len(self.name_index.get(user.current_name.val_normalized, set())) > 1:
                warnings.append(
                    f"User '{hist_uid}' shares full name '{user.current_name.val_raw}' with other users. "
                    "Name was not used for resolution."
                )

            return IdentityResolutionResult(
                request_id=request_id,
                input_identifier=raw_email,
                input_type=IdentifierType.EMAIL,
                status=ResolutionStatus.RESOLVED,
                confidence=ResolutionConfidence.HISTORICAL_AUDIT,
                canonical_user_id=hist_uid,
                matched_record=matched_rec,
                identity=user,
                provenance_chain=[matched_rec.provenance_source, user.current_email.provenance_source],
                warnings=warnings
            )

        # Step 3: Unresolved
        return IdentityResolutionResult(
            request_id=request_id,
            input_identifier=raw_email,
            input_type=IdentifierType.EMAIL,
            status=ResolutionStatus.UNRESOLVED,
            confidence=ResolutionConfidence.NONE,
            canonical_user_id=None,
            warnings=[f"Identifier '{raw_email}' not found in current profiles or audit mutation logs."]
        )
