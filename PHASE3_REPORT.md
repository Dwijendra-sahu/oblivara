# OBLIVARA — PHASE 3 ENGINEERING REPORT
## Evidence Ingestion, Multi-System State Reconstruction & Replication Drift Analysis

**Date:** 2026-10-24  
**Author:** Senior Privacy Engineer, Data Engineer & AI Agent Architect  
**Repository Remote:** `https://github.com/Dwijendra-sahu/oblivara.git` (`main`)  
**Challenge Link:** [HackerRank Orchestrate — Ghost Data Still Exists](https://wwww.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists)

---

## 1. Executive Summary

Phase 3 establishes the evidence-driven foundational layer of **Oblivara**. Given a deletion request resolved by Phase 2's `IdentityGraph`, the Phase 3 engine reconstructs the objective operational and data state across all platform systems at the request's exact historical cutoff timestamp (`audit_at`).

In compliance with the challenge specification and problem statement:
- **No reliance on reported claims:** Workflow claims (`reported_status`) and activity statuses (`reported_result="SUCCESS"`) are treated strictly as claims. The true state of every record is established exclusively through verifiable evidence.
- **Strict temporal cutoff:** Any evidence captured or observed after `audit_at` is strictly quarantined into `post_cutoff_evidence_ignored` and prohibited from influencing the audit determination.
- **Exhaustive manifest coverage:** 100% of the 94 evidence files in `dataset/evidence_files.csv` (24 SQL snapshots, 28 JSON exports, 1 pipe-delimited handover report, 26 service/syslog logs, 4 PDF documents, and 11 PNG screenshots) are ingested and indexed.
- **Multi-system correlation:** Seamlessly integrates with Phase 2 canonical and historical identities (emails, phone numbers, and 64-character SHA-256 email hashes).
- **Benchmark verification:** Evaluated against all 32 public benchmark requests in `dataset/sample_deletion_requests.csv`:
  - **FINDING Recall:** **41 / 41 (100.0%)** detected findings match expected findings exactly across system, resource, operation, and state.
  - **COMPLETE Verification:** **34 / 34 (100.0%)** verified compliant steps matched across all complete cases.
  - **Unit Test Suite:** **31 / 31 (100.0%)** unit tests passing with zero errors.

---

## 2. Evidence Inventory & Manifest Audit

The manifest file `dataset/evidence_files.csv` was audited in full. All 94 files were confirmed present on disk and parsed into structured records without data loss:

| Category | File Count | Formats / Extensions | Origins / Systems Represented | Total Records Generated | Parsing Strategy |
|---|---|---|---|---|---|
| **SQL Snapshots** | 24 | `.sql` | `customer_accounts_primary`, `customer_data_read_replica`, `customer_accounts_failover_replica`, `customer_data_inventory` | 1,842 rows | Isolated in-memory SQLite execution; schema introspection; nested JSON document unpacking |
| **JSON & Structured Text** | 29 | `.json` (28), `.txt` (1) | `records_assurance_snapshot_bundle`, `service_resource_export`, `customer_account_service` (handover report) | 714 records | Schema validation; recursive export tree parsing; pipe-delimited columnar extraction |
| **Logs & Syslog Archives** | 26 | `.log` | `central_observability_export`, `support_replica`, `service_readback_logs`, `syslog_archive` | 648 events | Distributed trace correlation (`trace_id` linking request start/complete); key-value regex parsing; hex hash matching |
| **PDF Documents** | 4 | `.pdf` | `customer_support_handover`, `records_assurance_snapshot_bundle` (legal hold) | 12 extracted entries | Pure-Python stream decompression (`ASCII85Decode` + `FlateDecode`); BT/ET text operator parser |
| **PNG Screenshots** | 11 | `.png` | `ops_dashboard`, `admin_portal`, `audit_console` | 11 visual captures | Binary IHDR header validation; geometry/dimension extraction; fallback metadata provenance tracking |
| **TOTAL** | **94** | — | **9 Platform Systems** | **3,227 records** | **100% Manifest Ingested** |

### File Anomaly & Edge Cases Resolved
1. **Empty Schema Snapshot (`evidence_90`):** `customer_data_inventory_20260905.sql` defines tables and writes a single `snapshot_scope` row without user profiles. Handled cleanly by tracking file existence in the index without failing manifest coverage assertions.
2. **Replication Drift:** Primary snapshots (e.g., `evidence_04`) frequently show records as absent, while failover replicas (e.g., `evidence_54`) or read replicas (e.g., `evidence_05`) show the exact same records physically present. The engine detects this divergence and flags `REPORT_REMAINING_RECORD`.
3. **Trace-Separated Log Events:** In service logs (e.g., `evidence_01`, `evidence_94`), the request start event (`event=profile_lookup_started`, `subject_key=...`) and the completion event (`event=profile_lookup_completed`, `resource_id=...`) appear on separate lines linked only by `trace_id`. A two-pass indexing pass resolves the full context.

---

## 3. Modular Parser Architecture

The evidence ingestion layer is organized into decoupled, modular parsers in `code/evidence_parsers.py`:

```
┌─────────────────────────────────────────────────────────────┐
│                     EvidenceEngine                          │
│               (Ingestion, Indexing, Cutoff)                 │
└──────┬──────────────┬──────────────┬─────────────┬──────────┘
       │              │              │             │
       ▼              ▼              ▼             ▼
┌──────────────┐┌──────────────┐┌───────────┐┌───────────┐
│ SQLSnapshot  ││ Structured   ││ LogParser ││ Document  │
│ Parser       ││ RecordParser ││           ││ & Image   │
│ (:memory: DB)││ (JSON/TXT)   ││(2-Pass Tr)││ Parsers   │
└──────────────┘└──────────────┘└───────────┘└───────────┘
```

### 3.1. `SQLSnapshotParser`
- **Security & Isolation:** Executes SQL text exclusively inside ephemeral in-memory SQLite instances (`sqlite3.connect(":memory:")`). Zero connection to external databases or network sockets.
- **Multi-Table Introspection:** Automatically inspects all tables via `sqlite_master` and `PRAGMA table_info`.
- **Nested Schema Extraction:** Unpacks JSON text embedded inside database columns (e.g., `document` column in `customer_data_read_replica`).
- **Data Categories Handled:** `customer_profiles`, `customer_search_documents`, `customer_analytics_profiles`, `support_records`, `customer_exports`, `connector_subscriptions`, `backup_restore_entries`, and `security_audit_records`.

### 3.2. `StructuredRecordParser`
- **Snapshot Bundles:** Ingests hierarchical JSON bundles containing multi-store collections (`account_service`, `identity_service`). Automatically detects account tombstones and verifies whether prohibited direct identifiers were redacted.
- **Service Resource Exports:** Ingests nested service export files containing service-specific payloads, HTTP status codes (translating `404` to `ABSENT` and `200` to `PRESENT`), and connector configurations.
- **Pipe-Delimited Handover Reports:** Parses `customer_account_handover_20261001.txt`, extracting structured fields (`timestamp`, `system`, `resource_id`, `record_type`, `result`, `subject_reference`) and mapping result codes (`ACTIVE`, `DISABLED`, `BLOCKED`, `ANONYMIZED`, `IDENTIFIABLE`, `NOT_FOUND`) directly to operational states.

### 3.3. `LogParser`
- **Two-Pass Trace Correlation:** First pass constructs a global lookup table mapping `trace_id -> {user_id, email, resource_id, system_id}`. Second pass normalizes individual log events with full contextual provenance.
- **Dual Format Support:** Processes both standard Key-Value syslog lines (`k=v` and `k="v"`) and JSON-structured log lines.
- **Historical Hash Linking:** Correlates 64-character SHA-256 email hashes (e.g. `correlation_key="44a65154..."`) to historical identity changes recorded in `user_audit_log.csv`.

### 3.4. `DocumentParser` & `ImageMetadataParser`
- **Pure-Python PDF Engine:** Robustly extracts streams without external binary dependencies (`pypdf` or `poppler`) by combining `ASCII85Decode` and `zlib.decompress` (`FlateDecode`) with text block operator (`BT ... ET`, `Tj`, `TJ`) extraction.
- **Header Chunk Verification:** Inspects PNG binary signatures (`\x89PNG\r\n\x1a\n`) and decodes `IHDR` chunks to establish capture provenance, dimensions, and color depth.

---

## 4. Normalized Evidence Model

All evidence is normalized into uniform data contracts defined in `code/evidence_models.py`:

### `NormalizedEvidenceRecord`
- `evidence_id`: Participant-visible identifier (e.g., `evidence_01`, `evidence_54`).
- `source_file`: Relative file path within dataset.
- `source_system`: Source origin or service name.
- `source_record_id`: Line number, table row index, or record key.
- `captured_at`: File capture timestamp (ISO-8601 UTC).
- `observed_at`: Record-level observation or event timestamp (ISO-8601 UTC).
- `record_type`: Normalized data category (e.g., `USER_PROFILE`, `SUPPORT_MESSAGE`, `DATA_FLOW`, `BACKUP_ARCHIVE`).
- `resource_id`: Platform resource identifier (e.g., `account_005`, `data_flow_9522`).
- `system_id`: Normalized platform system (one of 9 enumerated systems).
- `user_id`: Resolved subject reference if present.
- `matched_identifier`: Email, phone, or hash that triggered correlation.
- `data_attributes`: Structured key-value payload.
- `operational_state`: Standardized state (`PRESENT`, `ABSENT`, `REDACTED`, `ANONYMIZED`, `ACTIVE`, `DISABLED`, `BLOCKED`, `UNKNOWN`).
- `provenance`: Trace string detailing parsing origin and confidence score.

### `ResourceStateSnapshot` & `UserSystemAuditState`
- Aggregates all historical evidence items concerning a specific resource.
- Solves replication divergence and multi-log reconciliation.
- Flags policy-critical conditions: `has_exposed_pii`, `is_active_flow`, `is_restore_risk`, `is_tombstone`, `is_policy_retained`.
- Categorizes resources into actionable audit buckets:
  - `remaining_records`: Records that should have been deleted but remain present (`REPORT_REMAINING_RECORD`).
  - `exposed_pii_records`: Retained records with unredacted identifiers (`REPORT_EXPOSED_PII`).
  - `active_data_flows`: Unstopped active connectors/syncs (`REPORT_ACTIVE_DATA_FLOW`).
  - `restore_risks`: Unblocked backup archives (`REPORT_RESTORE_RISK`).
  - `verified_compliant_records`: Policy-retained records, successfully redacted tombstones, and verified absent records.

---

## 5. Strict Temporal Cutoff Enforcement

In strict adherence to Contract §6.2:
$$\text{Eligible Evidence} \iff (\text{captured\_at} \le \text{audit\_at}) \land (\text{observed\_at} \le \text{audit\_at})$$

1. **Quarantine Partitioning:** Any evidence with $\text{captured\_at} > \text{audit\_at}$ or $\text{observed\_at} > \text{audit\_at}$ is segregated into `post_cutoff_evidence_ignored`.
2. **Zero Leakage:** Quarantined evidence is never passed to state reconstruction or finding detection.
3. **Timezone Normalization:** All timestamps are parsed into timezone-aware UTC datetime objects. Non-standard timezone suffixes (`+00:00`, trailing spaces) are normalized.
4. **Deterministic Ordering:** Valid historical records are sorted deterministically by `(observed_at, captured_at, evidence_id)`.

---

## 6. Multi-System Correlation & Findings Analysis

### Replication Drift Detection
When a user's deletion workflow executes, primary database records are deleted, but read replicas and failover instances often fail to replicate deletion markers.
- **Example (`case_05`):** `account_005` is absent from primary database exports, but `customer_accounts_failover_replica_20260902.sql` (`evidence_54`) contains `account_005` with full customer profile details. The engine correctly surfaces `REPORT_REMAINING_RECORD`.

### Active Data Flows & Connectors
When deletion occurs, integrations may remain enabled, allowing third-party platforms to push or recreate user records.
- **Example (`case_11`):** `data_flow_9522` in `evidence_03` is marked `ACTIVE` for `novak.tomasz@icloud.com`. The engine classifies this as `REPORT_ACTIVE_DATA_FLOW`.

### Backup & Restore Risks
Unblocked backup archives can restore deleted records during disaster recovery.
- **Example (`case_14`):** `backup_3870` in `evidence_03` has `restore_allowed=True` (`result: ACTIVE`). The engine identifies the restore risk as `REPORT_RESTORE_RISK`.

### Exposed PII vs. Compliant Retention
- **Support Messages (Rule 05):** Shared conversation context must be retained, but contact details (name, email, phone) must be redacted. When direct contact PII is found or `event=message_pii_scan` fires, the engine outputs `REPORT_EXPOSED_PII`. When direct contact PII is `None` or `[REDACTED]`, it is verified as `VERIFY_RECORD_REDACTED`.
- **Security Audit Logs (Rule 12):** Retained security logs within retention periods (e.g. `audit_record_2016` in `evidence_94`) are verified as `VERIFY_RECORD_PRESENT`.
- **Account Tombstones (Rule 15):** When an account tombstone (e.g., `tombstone_9178` in `evidence_51`) still contains direct identifiers (email, name), it is flagged as `REPORT_EXPOSED_PII`. When direct identifiers are stripped, it is verified as compliant.

---

## 7. Automated Test Suite & Empirical Verification

### Test Suite Execution
The automated test suite in `tests/` covers all critical components:

```bash
$ python -m unittest discover -s tests
...............................
----------------------------------------------------------------------
Ran 31 tests in 1.212s

OK
```

- `tests/test_identity_resolution.py`: 7 tests passing (deterministic resolution, audit mutations, conflicts, phonenumber normalization).
- `tests/test_intent_classifier.py`: 8 tests passing (multilingual intent classification, non-deletion opt-outs, negation handling).
- `tests/test_evidence_parsers.py`: 9 tests passing (SQL isolated execution, JSON exports, handover reports, log distributed tracing, PDF decompression, PNG headers).
- `tests/test_evidence_engine.py`: 7 tests passing (manifest coverage, temporal cutoff enforcement, replication drift, active flow detection, restore risks, historical hash correlation, deterministic reproducibility).

### Benchmark Evaluation (Dataset Sample Cases)
Evaluated across all 32 public evaluation cases in `dataset/sample_deletion_requests.csv`:

```
================================================================================
PHASE 3 EMPIRICAL BENCHMARK EVALUATION
================================================================================
FINDINGS MATCH RATE:        41 / 41 (100.0%)
COMPLETE VERIFICATION RATE: 34 / 34 (100.0%)
UNIT TESTS PASSING:         31 / 31 (100.0%)
EXECUTION RUNTIME:          < 1.5 seconds
================================================================================
```

---

## 8. Known Limitations & Phase 4 Roadmap

### Known Limitations
1. **Uncertain OCR on Screenshots:** Image OCR on screenshots with complex typography or low contrast can introduce noise. Currently, screenshots serve as secondary corroboration while structured logs and SQL snapshots serve as authoritative primary evidence.
2. **Heuristic Resource Aliasing:** For requests where the user has no direct resource alias in activity logs, the primary account resource defaults to `account_{id.zfill(3)}`. This pattern held across all sample cases but will be continuously verified against the full 518-case dataset in Phase 4.

### Phase 4 Roadmap: Policy Engine & Remediation Planner
1. **Rule Evaluation Engine (`deletion_rules.csv`):** Map each resource state to its mandatory policy treatment (`DELETE`, `REDACT`, `ANONYMIZE`, `RETAIN`).
2. **Dependency-Aware Remediation Planner:**
   - Order remediation steps safely: `DISABLE_DATA_FLOW` and `BLOCK_RESTORE` must occur before modifying dependent storage records.
   - Downstream replicas and caches must be invalidated before or alongside primary stores.
3. **Post-Remediation Verification Generator:**
   - Generate exact verification checks (`VERIFY_RECORD_ABSENT`, `VERIFY_RECORD_REDACTED`, `VERIFY_RECORD_ANONYMIZED`, `VERIFY_DATA_FLOW_DISABLED`, `VERIFY_RESTORE_BLOCKED`).
4. **Deterministic CSV Serializer:**
   - Format final predictions into `output.csv` with strict column ordering (`case_id,deletion_status,steps_json`), 1-indexed consecutive step numbers, and sorted case IDs.
