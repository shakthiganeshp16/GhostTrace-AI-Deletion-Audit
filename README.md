# GhostTrace — AI-Powered Data Deletion Audit & Remediation Agent

**Evidence-Grounded Privacy Compliance Automation**

**Project Status:** Functional Prototype | Evaluation & Optimization in Progress

**Challenge:** HackerRank Orchestrate — October 2026 | *Ghost Data Still Exists*

---

## Overview

GhostTrace is a Python-based data deletion auditing and remediation planning system designed to investigate whether personal information has actually been removed from distributed systems.

A deletion workflow may report `COMPLETE`, but personal data can still remain in database replicas, search indexes, analytics platforms, support systems, exports, application logs, and backup archives.

GhostTrace analyzes available evidence, reconstructs observable resource states, applies deletion and retention policies, and generates structured audit findings and remediation plans.

The goal is to make data deletion **verifiable, explainable, and evidence-grounded**, rather than relying solely on reported workflow statuses.

## The Problem: Ghost Data

Deleting a user account does not necessarily mean all associated information has disappeared.

Data may remain in:

- Primary and replicated databases
- Search indexes and caches
- Analytics platforms
- Support messages and attachments
- Exported datasets
- Security and email logs
- Backup archives
- Active synchronization pipelines

A synchronization process or backup restoration can also reintroduce previously deleted information.

**GhostTrace addresses this problem by evaluating the available evidence and identifying potential deletion failures and recreation risks.**

## Implemented Features

### 1. Identity Resolution

Resolves deletion requests to user identities using identifiers such as:

- User ID
- Email address
- Phone number
- Email hash

Includes identity-matching components and historical identity analysis utilities. Comprehensive historical identifier reconstruction remains an area for improvement.

### 2. Multi-Format Evidence Processing

Processes evidence from multiple formats:

- JSON records
- SQL database snapshots
- Application logs
- Text-based evidence

The unified evidence index combines normalized observations into a common representation for downstream analysis.

### 3. Resource Discovery

Identifies potentially related resources using:

- Identity-based evidence matching
- Resource references
- Activity-based resource links

### 4. Timestamp-Based State Analysis

Filters observations using their capture and observation timestamps relative to the request's `audit_at` timestamp.

The resource state engine interprets states including:

- `PRESENT`
- `ABSENT`
- `ACTIVE`
- `DISABLED`
- `RESTORABLE`
- `RESTORE_BLOCKED`
- `UNKNOWN`

### 5. Policy-Based Remediation

Uses 15 supplied deletion and retention policies to determine required treatment for different data categories.

Supported remediation operations include:

- `DELETE_RECORD`
- `REDACT_RECORD`
- `ANONYMIZE_RECORD`
- `DISABLE_DATA_FLOW`
- `BLOCK_RESTORE`

The system also handles retention-oriented policy decisions.

### 6. Structured Audit Planning

Generates ordered steps across three phases:

**FINDING:** Identify remaining records, exposed personal information, active data flows, or restoration risks.

**REMEDIATION:** Specify the actions required to address identified issues.

**VERIFICATION:** Specify checks needed to establish the required final state.

### 7. Automated Prediction Generation

Processes the challenge dataset and produces structured CSV predictions.

Each request receives one of three classifications:

- `COMPLETE`
- `INCOMPLETE`
- `NOT_APPLICABLE`

These classifications are model-generated assessments and are subject to ongoing validation.

## System Architecture

![GhostTrace System Architecture](docs/architecture.svg)

**Processing pipeline:**

Deletion Requests → Request Assessment → Identity Resolution → Resource Discovery → Unified Evidence Index → Temporal State Analysis → Policy & Remediation Planning → Audit Status → CSV Output

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core implementation |
| Pandas | Dataset and evidence processing |
| CSV / JSON | Input, intermediate representations, and output |
| SQL snapshot parsing | Database evidence analysis |
| Python datetime | Timestamp-based filtering |
| Rule-based reasoning | Policy evaluation and remediation planning |
| Git & GitHub | Version control |

The current prototype primarily uses deterministic Python-based reasoning. It does not claim to use a deployed large language model for every audit decision.

## Project Structure

```text
GhostTrace-AI-Deletion-Audit/
│
├── code/
│   ├── identity_resolver.py
│   ├── advanced_identity_matcher.py
│   ├── resource_mapper.py
│   ├── unified_evidence_index.py
│   ├── json_evidence_extractor.py
│   ├── sql_evidence_parser.py
│   ├── sql_evidence_normalizer.py
│   ├── text_evidence_parser.py
│   ├── resource_state_engine.py
│   ├── policy_engine.py
│   ├── remediation_planner.py
│   ├── case_audit_engine.py
│   ├── generate_predictions.py
│   └── evaluation/
│       └── evaluate.py
│
├── dataset/
│   ├── deletion_requests.csv
│   ├── sample_deletion_requests.csv
│   ├── sample_output.csv
│   ├── user_identities.csv
│   ├── user_audit_log.csv
│   ├── system_activity.csv
│   ├── deletion_rules.csv
│   ├── evidence_files.csv
│   └── evidence/
│
├── docs/
│   └── architecture.svg
│
├── README.md
└── .gitignore
```

Some generated outputs and documentation files are created locally and may not yet be committed to the repository.

## Getting Started

### Requirements

- Python 3.13 or compatible Python 3 version
- pip
- Git
- Challenge dataset available in `dataset/`

### 1. Clone the Repository

```bash
git clone https://github.com/shakthiganeshp16/GhostTrace-AI-Deletion-Audit.git
cd GhostTrace-AI-Deletion-Audit
```

### 2. Create a Virtual Environment

```bash
python -m venv .venv
```

Activate on Windows:

```bat
.venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install pandas pypdf pillow
```

### 4. Generate Audit Predictions

Run from the project root:

```bash
python code/generate_predictions.py
```

The generator reads the challenge data and produces:

- `output.csv` — structured deletion audit predictions
- `prediction_diagnostics.csv` — processing diagnostics

### 5. Run Sample Evaluation

```bash
python code/evaluation/evaluate.py
```

The evaluation script compares prototype predictions against the provided labeled sample cases.

## Current Execution Results

The latest local prototype run produced:

| Metric | Result |
|---|---:|
| Deletion requests processed | 518 |
| Indexed evidence observations | 3,439 |
| COMPLETE predictions | 30 |
| INCOMPLETE predictions | 487 |
| NOT_APPLICABLE predictions | 1 |
| Prediction output | `output.csv` |
| Diagnostic output | `prediction_diagnostics.csv` |

**Important:** These counts represent generated classifications, not validated prediction accuracy.

## Output Format

The system produces the following CSV schema:

```csv
case_id,deletion_status,steps_json
```

The `steps_json` field contains an ordered JSON array of audit steps.

Illustrative example:

```json
[
  {
    "step_no": 1,
    "phase": "FINDING",
    "system_id": "account_service",
    "resource_id": "account_example",
    "operation": "REPORT_REMAINING_RECORD",
    "state": "PRESENT",
    "evidence_id": "evidence_example"
  },
  {
    "step_no": 2,
    "phase": "REMEDIATION",
    "system_id": "account_service",
    "resource_id": "account_example",
    "operation": "DELETE_RECORD",
    "state": "ABSENT",
    "evidence_id": ""
  },
  {
    "step_no": 3,
    "phase": "VERIFICATION",
    "system_id": "account_service",
    "resource_id": "account_example",
    "operation": "VERIFY_RECORD_ABSENT",
    "state": "ABSENT",
    "evidence_id": ""
  }
]
```

This example is illustrative, not an actual audited customer record. Empty evidence IDs on remediation and verification steps indicate actions or checks that are still required.

## Evaluation and Current Limitations

GhostTrace includes an evaluation pipeline using 32 labeled sample requests.

Current improvement areas include:

- More complete historical identity reconstruction
- Stronger resource discovery across distributed systems
- SQL snapshot scope and negative-evidence interpretation
- Better extraction of complex evidence structures
- More accurate anonymization and retention verification
- Handling of backup restoration and synchronization risks
- Improved agreement with labeled audit outcomes

The prototype is not yet a production-grade compliance system. Its generated findings require validation before use in real deletion workflows.

## Development Roadmap

- [x] Dataset exploration and schema analysis
- [x] Current identity resolution
- [x] Multi-format evidence indexing
- [x] Resource state interpretation
- [x] Policy evaluation
- [x] Remediation planning
- [x] Full 518-request prediction generation
- [x] Sample evaluation pipeline
- [ ] Improve evidence reconstruction and prediction accuracy
- [ ] Expand automated testing
- [ ] Complete evaluation and usage reports
- [ ] Finalize submission packaging

## Why GhostTrace Matters

Privacy compliance requires more than initiating a deletion request.

Organizations need to understand where personal data exists, how it moves between systems, whether it has been properly transformed or removed, and whether future operations can recreate it.

GhostTrace explores how automated evidence analysis and policy-based reasoning can support more transparent, reproducible, and auditable data deletion workflows.

---

**Developed for the HackerRank Orchestrate October 2026 Challenge.**

**Project:** GhostTrace — AI-Powered Data Deletion Audit & Remediation Agent

**Development Status:** Functional prototype under active evaluation and improvement.