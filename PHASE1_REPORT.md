# Oblivara: Phase 1 Repository and Dataset Audit Report

**Author:** Oblivara Engineering Team  
**Date:** October 24, 2026  
**Challenge:** HackerRank Orchestrate (October 2026) — Ghost Data Still Exists  
**Target Repository:** `https://github.com/Dwijendra-sahu/oblivara.git`  
**Status:** Completed & Validated

---

## 1. Repository Structure

The repository contains the starter environment, dataset, evaluation manifests, and governance configuration:

```text
oblivara/
├── .gitignore                     # Ignores Python bytecode, venvs, and submission archives
├── AGENTS.md                      # Governance contract, turn logging rules, session lifecycle
├── CLAUDE.md                      # Pointer to AGENTS.md
├── README.md                      # Participant instructions, packaging specifications, quickstart
├── problem_statement.md           # Business specification, operations, allowed states, grading contract
├── agent_trace_instructions.md    # Packaging instructions for IDE transcripts
├── log.txt                        # Live audit log of all development turns (submitted as chat_transcript)
├── code/
│   ├── main.py                    # Primary entry point (currently 0 bytes, to be implemented)
│   └── evaluation/
│       └── main.py                # Local benchmark & report runner (currently 0 bytes, to be implemented)
└── dataset/
    ├── deletion_requests.csv       # 518 evaluation cases (the inference target)
    ├── sample_deletion_requests.csv# 32 public sample cases
    ├── sample_output.csv          # Canonical reference answers for the 32 sample cases
    ├── user_identities.csv        # 850 current user profile snapshots
    ├── user_audit_log.csv         # 306 historical identity mutations (emails, phones, names)
    ├── system_activity.csv        # 4,011 operational events across services
    ├── deletion_rules.csv         # 15 data category deletion/retention policies
    ├── evidence_files.csv         # Manifest of 94 evidence files
    ├── output.csv                 # Blank submission template (3 columns, 0 data rows)
    └── evidence/                  # 94 physical evidence files (2.81 MB total)
        ├── databases/             # 24 point-in-time SQL snapshot exports (.sql)
        ├── documents/             # 4 business/legal reports (.pdf)
        ├── images/                # 11 administrative console screenshots (.png)
        ├── logs/                  # 26 service and syslog exports (.log)
        └── records/               # 29 snapshot bundles and exports (28 .json, 1 .txt)
```

---

## 2. Input File Inventory & Reference Separation

| File | Rows | Role | Contains Ground Truth? | Usage Rule |
| :--- | :---: | :--- | :---: | :--- |
| `dataset/deletion_requests.csv` | 518 | **Evaluation Target** | No | Primary evaluation input. Must produce exactly 518 rows in root `output.csv`. |
| `dataset/sample_deletion_requests.csv` | 32 | **Development Set** | No | Public cases used to build, validate, and benchmark the pipeline locally. |
| `dataset/sample_output.csv` | 32 | **Reference Answers** | **Yes** | Ground truth for the 32 sample cases. **Must never be used for test predictions.** |
| `dataset/user_identities.csv` | 850 | Identity Snapshot | No | Grounding current names, emails, phones, and email hashes to `user_id`. |
| `dataset/user_audit_log.csv` | 306 | Identity History | No | Resolving historical emails, previous phone numbers, and name updates. |
| `dataset/system_activity.csv` | 4,011 | Activity Stream | No | Unverified claims of deletion, export, sync, indexing, and backup events. |
| `dataset/deletion_rules.csv` | 15 | Policy Matrix | No | Authoritative organizational retention, deletion, redaction, and tombstone rules. |
| `dataset/evidence_files.csv` | 94 | Evidence Manifest | No | Metadata linking `file_id` to file paths, system origins, and capture times. |
| `dataset/output.csv` | 0 | Output Template | No | Reference format template for the output schema. |

> **Ground Truth Separation Principle:**  
> `dataset/sample_output.csv` is strictly isolated as a local benchmark evaluator target. Neither sample answers nor customer identifiers are hardcoded into production inference logic.

---

## 3. CSV Schema Summary & Data Profiling

Every CSV in `dataset/` was audited. **Zero missing values (nulls/empty strings) were found across all fields in the entire dataset.**

### 3.1 `deletion_requests.csv` (Evaluation Set)
- **Row count:** 518
- **Missing values:** 0
- **Columns & Types:**
  - `case_id` (`str`): Unique case identifier (`case_33` to `case_550`).
  - `email` (`str`): Request email (can be current or historical address).
  - `requested_at` (`iso_date`): Request timestamp.
  - `reported_status` (`str`): Workflow claim (`COMPLETE`, `PARTIALLY_COMPLETE`, `NOT_STARTED`).
  - `reported_at` (`iso_date`): Workflow completion claim timestamp.
  - `audit_at` (`iso_date`): **Temporal cutoff.** Ignore evidence captured after this timestamp.
  - `request_text` (`str`): Multilingual user request text.
- **Sanitized Sample:**
  ```text
  case_33 | [REDACTED_EMAIL] | 2026-07-16T08:00:00Z | COMPLETE | 2026-07-18T02:00:00Z | 2026-07-19T13:00:00Z | "Please close my account and process the associated personal-data deletion..."
  ```

### 3.2 `sample_deletion_requests.csv` (Sample Set)
- **Row count:** 32
- **Missing values:** 0
- **Columns & Types:** Identical to `deletion_requests.csv` (`case_01` to `case_32`).
- **Sanitized Sample:**
  ```text
  case_01 | [REDACTED_EMAIL] | 2026-08-18T09:14:00Z | COMPLETE | 2026-08-20T16:42:00Z | 2026-09-03T11:30:00Z | "Hi, I haven't used this account in years and would like it closed..."
  ```

### 3.3 `sample_output.csv` (Reference Answers)
- **Row count:** 32 (10 `COMPLETE`, 22 `INCOMPLETE`)
- **Missing values:** 0
- **Columns & Types:**
  - `case_id` (`str`): e.g., `case_01`.
  - `deletion_status` (`str`): `COMPLETE` or `INCOMPLETE`.
  - `steps_json` (`json_array`): Serialized JSON array of ordered step objects.
- **Sanitized Sample (`case_01`):**
  ```text
  case_01 | COMPLETE | [{"evidence_id":"evidence_54","operation":"VERIFY_RECORD_ABSENT","phase":"VERIFICATION","resource_id":"account_001","state":"ABSENT","step_no":1,"system_id":"account_service"}]
  ```

### 3.4 `user_identities.csv` (Current Snapshot)
- **Row count:** 850
- **Missing values:** 0
- **Columns & Types:**
  - `user_id` (`str`): Stable identifier (`user_01` to `user_850`).
  - `name` (`str`): Full name.
  - `email` (`str`): Primary email.
  - `phone` (`str`): E.164 phone number.
  - `email_hash` (`str`): 64-character SHA-256 hex string.
  - `updated_at` (`iso_date`): Identity record update timestamp.

### 3.5 `user_audit_log.csv` (Identity Audit History)
- **Row count:** 306
- **Missing values:** 0
- **Columns & Types:**
  - `audit_id` (`str`): e.g., `audit_01`.
  - `user_id` (`str`): Associated user (`user_32`, etc.).
  - `event_time` (`iso_date`): Mutation timestamp.
  - `field_name` (`str`): `email`, `phone`, or `name`.
  - `old_value` (`str`): Previous identifier value.
  - `new_value` (`str`): Updated identifier value.

### 3.6 `system_activity.csv` (Operational Activity Stream)
- **Row count:** 4,011
- **Missing values:** 0
- **Columns & Types:**
  - `activity_id` (`str`): `activity_01` to `activity_4011`.
  - `event_time` (`iso_date`): UTC timestamp.
  - `event_type` (`str`): `DELETE_RECORD`, `SYNC_RECORD`, `INDEX_RECORD`, `RETAIN_RECORD`, `REFRESH_CACHE`, `SEND_EMAIL`, `CREATE_EXPORT`, `UPDATE_RECORD`.
  - `source_system` (`str`): e.g., `deletion_worker`, `account_service`, `security_service`.
  - `target_system` (`str`): e.g., `account_service`, `analytics_platform`, `search_service`.
  - `resource_id` (`str`): e.g., `account_001`, `analytics_4011`, `search_9729`.
  - `reported_result` (`str`): `SUCCESS`, `PARTIAL`, `FAILED`.
  - `details` (`str`): Descriptive operational message.

### 3.7 `deletion_rules.csv` (Policy Specification)
- **Row count:** 15
- **Missing values:** 0
- **Columns & Types:**
  - `rule_id` (`str`): `rule_01` to `rule_15`.
  - `data_category` (`str`): Business data category.
  - `condition` (`str`): Applicable condition / scope.
  - `required_action` (`str`): `DELETE`, `REDACT`, `ANONYMIZE`, `RETAIN`.

### 3.8 `evidence_files.csv` (Evidence Manifest)
- **Row count:** 94
- **Missing values:** 0
- **Columns & Types:**
  - `file_id` (`str`): `evidence_01` to `evidence_94`.
  - `file_path` (`str`): Relative path under `dataset/`.
  - `origin` (`str`): Subsystem origin.
  - `captured_at` (`iso_date`): Capture timestamp.

---

## 4. Media Inventory and Reading Strategy

All 94 evidence files declared in `evidence_files.csv` exist on disk under `dataset/evidence/` (2.81 MB total). None are missing or corrupted.

| Subdirectory | File Count | Formats | Total Size | Description & Inspection Strategy |
| :--- | :---: | :---: | :---: | :--- |
| `databases/` | 24 | `.sql` | 326.2 KB | **Database Snapshot Exports**: Point-in-time SQLite-compatible DDL and INSERT statements representing primary tables, regional replicas, reporting replicas, and failover replicas. Investigates replication drift.<br/>*Strategy:* Load into in-memory SQLite (`sqlite3.connect(':memory:')`) or parse via regex to check presence/absence of `user_id`, email, or `resource_id`. |
| `records/` | 29 | `.json` (28)<br/>`.txt` (1) | 328.5 KB | **Structured Records & Handover Logs**: Snapshot bundles, service resource exports, connector configurations, and shift handovers.<br/>*Strategy:* Standard `json.load()` and pipe-delimited line parsing. Extract resources, system tags, attributable emails, and anonymization states. |
| `logs/` | 26 | `.log` | 504.1 KB | **Service & Diagnostic Logs**: Observability exports, syslog archives, search diagnostics, and resource lookup traces.<br/>*Strategy:* Streamed regex line parsing for timestamps, target systems, resource IDs, and PII exposure. |
| `documents/` | 4 | `.pdf` | 256.3 KB | **Business & Legal Documents**: Customer statements, legal retention registers, delivery correction attachments, security retention extracts.<br/>*Strategy:* Audited stream structure confirmed standard `/ASCII85Decode` + `/FlateDecode` streams. Decodable natively in Python without binary tools using `base64.a85decode(stream, adobe=True)` and `zlib.decompress(data)` with regex text extraction `(...) Tj`. |
| `images/` | 11 | `.png` | 1.43 MB | **Console UI Screenshots**: 1800x1200 / 1800x1150 screenshots of admin portals, backup restore consoles, connector management, and object storage explorers.<br/>*Strategy:* Structured textual and log evidence covers primary findings. For edge cases, read via multimodal LLM vision calls (e.g., Gemini Vision API) or OCR. |

---

## 5. Exact `output.csv` Schema and Step Contract

The final submission must write `output.csv` to the **repository root** with exactly 518 data rows sorted ascending by `case_id`.

```csv
case_id,deletion_status,steps_json
```

### 5.1 Status Definitions
1. **`COMPLETE`**:
   - The user requested deletion.
   - All personal copies have received required treatment (`ABSENT`, `REDACTED`, `ANONYMIZED`).
   - All policy-required retained records remain (`PRESENT`).
   - No active sync connectors or restore risks exist (`DISABLED`, `BLOCKED`).
   - `steps_json` contains **only verification steps** proving state at `audit_at`.
2. **`INCOMPLETE`**:
   - The user requested deletion.
   - Personal data still exists, active flows remain, or restore risks persist.
   - `steps_json` contains **findings** (with evidence citations), followed by the **remediation plan** (empty evidence ID), followed by **post-remediation verification checks** (empty evidence ID).
3. **`NOT_APPLICABLE`**:
   - The user's request did not authorize deletion (e.g., access, data export, newsletter opt-out, address correction).
   - `steps_json` must be strictly empty: `[]`.

### 5.2 Step Structure
```json
{
  "step_no": 1,
  "phase": "FINDING",
  "system_id": "account_service",
  "resource_id": "account_005",
  "operation": "REPORT_REMAINING_RECORD",
  "state": "PRESENT",
  "evidence_id": "evidence_54"
}
```

### 5.3 Allowed Operations & Order of Operations
Ordering is strictly evaluated: **Phase order**, then **Operation order**, then `system_id` ascending, then `resource_id` ascending.

| Phase | Operation Order | Allowed Operation | Required State | Meaning |
| :--- | :---: | :--- | :---: | :--- |
| **FINDING** | 1 | `REPORT_REMAINING_RECORD` | `PRESENT` | Record that should have been deleted still exists. |
| | 2 | `REPORT_EXPOSED_PII` | `PRESENT` | Record retained, but contains unredacted/identifiable PII. |
| | 3 | `REPORT_ACTIVE_DATA_FLOW` | `ACTIVE` | Active sync job can recreate or copy user data. |
| | 4 | `REPORT_RESTORE_RISK` | `ACTIVE` | Backup path can restore deleted data. |
| **REMEDIATION** | 1 | `DISABLE_DATA_FLOW` | `DISABLED` | Stop sync/replication process. |
| | 2 | `BLOCK_RESTORE` | `BLOCKED` | Prevent backup from restoring user data. |
| | 3 | `DELETE_RECORD` | `ABSENT` | Remove the record. |
| | 4 | `REDACT_RECORD` | `REDACTED` | Keep record, strip direct identifiers. |
| | 5 | `ANONYMIZE_RECORD` | `ANONYMIZED` | Irreversibly unlink record from subject. |
| **VERIFICATION** | 1 | `VERIFY_RECORD_ABSENT` | `ABSENT` | Confirm record does not exist. |
| | 2 | `VERIFY_RECORD_PRESENT` | `PRESENT` | Confirm policy-required retained record exists. |
| | 3 | `VERIFY_RECORD_REDACTED` | `REDACTED` | Confirm required fields were removed. |
| | 4 | `VERIFY_RECORD_ANONYMIZED`| `ANONYMIZED` | Confirm record cannot be linked to subject. |
| | 5 | `VERIFY_DATA_FLOW_DISABLED`| `DISABLED` | Confirm data flow is inactive. |
| | 6 | `VERIFY_RESTORE_BLOCKED` | `BLOCKED` | Confirm backup restore is blocked. |

---

## 6. Deletion and Retention Policy Summary

Mapping from `dataset/deletion_rules.csv`:

| Rule ID | Data Category | Scope / Condition | Required Action | Target State / Permitted Identifiers |
| :--- | :--- | :--- | :---: | :--- |
| `rule_01` | `USER_PROFILE` | Always | **DELETE** | `ABSENT`. Entire record removed. |
| `rule_02` | `SECONDARY_IDENTIFIER`| Always | **DELETE** | `ABSENT`. Secondary contacts/emails removed. |
| `rule_03` | `SEARCH_INDEX_ENTRY` | Always | **DELETE** | `ABSENT`. Index document deleted. |
| `rule_04` | `CACHE_ENTRY` | Always | **DELETE** | `ABSENT`. Evicted from cache. |
| `rule_09` | `USER_EXPORT` | Always | **DELETE** | `ABSENT`. Staged export files removed. |
| `rule_10` | `MARKETING_PROFILE` | Always | **DELETE** | `ABSENT`. Marketing customer record removed. |
| `rule_06` | `SUPPORT_ATTACHMENT` | Belongs only to deletion subject | **DELETE** | `ABSENT`. Attachment file deleted. |
| `rule_05` | `SUPPORT_MESSAGE` | Contains shared customer/agent context | **REDACT** | `REDACTED`. Message retained; subject PII masked. |
| `rule_11` | `EMAIL_DELIVERY_LOG` | Contains user email address | **REDACT** | `REDACTED`. Delivery log kept; email masked. |
| `rule_15` | `ACCOUNT_TOMBSTONE` | Account deleted; stable `user_id` needed | **REDACT** | `REDACTED`. Stable `user_id` permitted; remove name, email, phone, and `email_hash`. |
| `rule_07` | `ANALYTICS_PROFILE` | Record still attributable to user | **ANONYMIZE** | `ANONYMIZED`. Aggregate metrics kept; direct link unlinked. |
| `rule_08` | `PRODUCT_TELEMETRY` | Record still attributable to user | **ANONYMIZE** | `ANONYMIZED`. Telemetry events anonymized. |
| `rule_12` | `SECURITY_AUDIT_LOG` | Within statutory retention period | **RETAIN** | `PRESENT`. Must remain available; cannot be deleted. |
| `rule_13` | `LEGAL_HOLD_RECORD` | Active legal hold in place | **RETAIN** | `PRESENT`. Must remain available. |
| `rule_14` | `BACKUP_ARCHIVE` | Restore access can be blocked | **RETAIN** | `RETAIN` record in backup, but restore path must be `BLOCKED`. |

---

## 7. Evaluation & Submission Requirements

The final challenge submission requires:

1. **`code.zip`**:
   - Contains `README.md`, `code/main.py`, `code/evaluation/`.
   - Must contain `code/evaluation/evaluation_report.md` detailing:
     - Case-level deletion-status accuracy.
     - Step-level and field-level accuracy.
     - Sequence accuracy.
     - At least 3 participant-created evaluation test cases.
     - Failures found and improvements made.
   - Must contain `code/evaluation/usage_report.md` detailing:
     - Model providers and model names.
     - Model calls, input/output token counts, and cost estimates.
   - *Exclusions:* `dataset/`, `.venv/`, `__pycache__/`, `.git/`, and nested archives.
2. **`output.csv`**:
   - Root-level file with 518 rows sorted by `case_id`.
3. **`chat_transcript` (`log.txt`)**:
   - The root `log.txt` file maintaining turn-by-turn records conforming to `AGENTS.md`.
4. **AI Interview**:
   - Live architectural and investigative defense.

---

## 8. Risks, Ambiguities, and Recommended Implementation Plan

### 8.1 Key Risks & Ambiguities
1. **Multilingual Non-Deletion Requests (`NOT_APPLICABLE`)**:
   - Requests arrive in various languages. Some explicitly ask for GDPR/CCPA data export, access, or marketing unsubscribe rather than account erasure. A reliable intent detector is critical.
2. **Replication Drift & Temporal State**:
   - Deletion workflows frequently log `SUCCESS`, but failover or regional read replicas still contain the data. The agent must verify actual presence in evidence as of `audit_at`, ignoring events after that cutoff.
3. **Entity Disambiguation**:
   - Users may have changed emails, phone numbers, or names over time. Historical records in logs may only reference `user_id` or an older email. Complete resolution across `user_identities.csv` and `user_audit_log.csv` is mandatory.
4. **Strict Sequencing of Remediation Actions**:
   - Data flows must be disabled before records are modified (`DISABLE_DATA_FLOW` before `DELETE_RECORD`).

### 8.2 Recommended Phased Implementation Plan

```mermaid
flowchart LR
    P2[Phase 2: Entity & Intent Engine] --> P3[Phase 3: Evidence & State Indexer]
    P3 --> P4[Phase 4: Policy Auditor & Step Sorter]
    P4 --> P5[Phase 5: Benchmark & Reports]
```

- **Phase 2: Identity Graph & Intent Classifier**
  - Implement bidirectional entity resolver (`email` $\leftrightarrow$ `user_id` $\leftrightarrow$ `phone` $\leftrightarrow$ `email_hash`).
  - Implement multilingual request intent classification to accurately route `NOT_APPLICABLE` cases.
- **Phase 3: Evidence Extraction & Temporal Indexer**
  - Build readers for SQL snapshots, JSON records, log streams, and PDF text.
  - Index resources, active flows, and restore risks with strict adherence to `audit_at`.
- **Phase 4: Policy Auditor & Sorter**
  - Apply `deletion_rules.csv` to detect remaining records, exposed PII, active flows, and restore risks.
  - Plan remediation and verification sequences conforming strictly to the required operation order.
  - Generate root `output.csv`.
- **Phase 5: Evaluation Pipeline & Reporting**
  - Implement `code/evaluation/main.py`.
  - Validate 100% agreement on `dataset/sample_output.csv`.
  - Generate `code/evaluation/evaluation_report.md` and `code/evaluation/usage_report.md`.
