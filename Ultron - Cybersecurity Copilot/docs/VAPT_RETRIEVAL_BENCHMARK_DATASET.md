# VAPT Retrieval Evaluation Benchmark Dataset (Phase 0)

## Overview & Purpose

This document specifies the **Gold-Standard VAPT Retrieval Evaluation Benchmark Dataset** created during **Phase 0** of the Local AI-Assisted Bug Bounty Research Platform.

The dataset serves as an implementation-independent benchmark for evaluating VAPT Knowledge Retrieval. It establishes a frozen ground-truth evaluation harness to compare:

- **Baseline:** Current SQLite FTS5 + Dense-Vector projection (`_deterministic_text_vector` MD5 hash bag-of-words) + Reciprocal Rank Fusion (RRF)
- **Phase 1 Target:** SQLite FTS5 + Real local semantic ONNX embeddings (e.g., all-MiniLM-L6-v2) + RRF

---

## Architectural & Epistemic Invariants

The evaluation dataset strictly adheres to the core architectural principles of the platform:

1. **Epistemic Separation:** Canonical target evidence (`evidence.db` / `FACT-*`) and general VAPT knowledge (`vapt_knowledge.db` / `CHK-*`) are completely separate channels.
2. **No Target Evidence Ingestion:** General VAPT knowledge chunks provide methodology and security invariants; they are never target evidence.
3. **No Target-Specific Assumptions:** All 100 queries are formulated as general security research questions and methodology inquiries. None assert or confirm vulnerability presence on any real target.
4. **Deterministic Evaluation:** Grounded in immutable corpus chunk IDs, category tags, and knowledge types.
5. **Implementation Independence:** The benchmark defines semantic targets and 4-tier graded relevance independent of any specific vector dimension, tokenizer, or scoring function.

---

## Dataset Location & Files

- **Benchmark Dataset:** [`tests/evaluation/vapt_retrieval_queries.json`](tests/evaluation/vapt_retrieval_queries.json)
- **Validation Schema:** [`src/eval/vapt_benchmark_schema.py`](src/eval/vapt_benchmark_schema.py)
- **Unit Test Suite:** [`tests/unit/test_vapt_benchmark_dataset.py`](tests/unit/test_vapt_benchmark_dataset.py)

---

## Schema & Field Specifications

Each query record in `vapt_retrieval_queries.json` conforms to the `VaptRetrievalQuery` Pydantic model:

```json
{
  "query_id": "VAPT-Q001",
  "query": "Insecure Direct Object Reference IDOR testing methodology and procedures",
  "security_domain": "AUTHORIZATION_OBJECT_LEVEL",
  "difficulty": "EASY",
  "query_type": "DIRECT_CONCEPT",
  "evidence_gap_type": "MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION",
  "is_negative_control": false,
  "is_security_invariant": false,
  "is_evidence_gap": false,
  "is_experiment": false,
  "is_adversarial_or_paraphrased": false,
  "expected_knowledge_types": ["TESTING_METHODOLOGY"],
  "expected_categories": ["IDOR", "Authorization"],
  "relevance_requirements": [
    "Must retrieve IDOR testing methodology and procedural steps"
  ],
  "must_retrieve": [
    {"type": "chunk_id", "value": "CHK-DOC-WSTG-ATHZ-04-002-01"},
    {"type": "knowledge_type", "value": "TESTING_METHODOLOGY"}
  ],
  "acceptable_retrievals": [
    {"type": "chunk_id", "value": "CHK-DOC-WSTG-ATHZ-04-001-01"},
    {"type": "chunk_id", "value": "CHK-DOC-CWE-639-001-01"}
  ],
  "irrelevant_retrievals": [
    {"type": "chunk_id", "value": "CHK-DOC-PLATFORM-INV-01-004-01", "reason": "Focuses on unauthenticated access rather than object authorization"}
  ],
  "relevance_ratings": {
    "CHK-DOC-WSTG-ATHZ-04-002-01": 3,
    "CHK-DOC-WSTG-ATHZ-04-001-01": 2,
    "CHK-DOC-CWE-639-001-01": 2,
    "CHK-DOC-PLATFORM-INV-01-002-01": 1,
    "CHK-DOC-PLATFORM-INV-01-004-01": 0
  },
  "notes": "Evaluates direct retrieval of OWASP WSTG IDOR procedure using canonical terminology."
}
```

---

## 4-Tier Graded Relevance Model

The benchmark specifies explicit relevance ratings for candidate chunks:

| Grade | Label | Description | Evaluation Usage |
| :---: | :--- | :--- | :--- |
| **3** | **HIGHLY RELEVANT** | Directly answers the security concept, invariant, evidence gap, methodology, or experiment. | Recall@K, MRR@K, nDCG@K |
| **2** | **RELATED / USEFUL** | Relevant supporting knowledge (e.g., related overview, parent invariant) that provides context. | Precision@K, nDCG@K |
| **1** | **WEAKLY RELATED** | Broad domain context that shares terminology but does not directly help resolve the query. | nDCG@K |
| **0** | **IRRELEVANT / DISTRACTOR** | Concepts that should NOT dominate retrieval (e.g., unauthenticated gate when testing IDOR). | Negative Control evaluation |

This grading supports deterministic computation of:
- **Recall@5** and **Recall@10** (binary threshold: Grade $\ge 2$ or Grade $= 3$)
- **Precision@5** and **Precision@10**
- **MRR@5** (first hit of Grade $= 3$)
- **nDCG@5** and **nDCG@10** (using grades 3, 2, 1, 0)

---

## Distribution Statistics

### 1. Security Domains (100 Queries Total)

The queries are distributed across 8 domains directly grounded in the repository's VAPT corpus:

| Security Domain | Count | Description / Primary Grounding |
| :--- | :---: | :--- |
| `AUTHORIZATION_OBJECT_LEVEL` | 18 | Horizontal access control, IDOR, BOLA, CWE-639, tenant isolation invariants |
| `AUTHORIZATION_FUNCTION_LEVEL` | 15 | Vertical privilege escalation, BFLA, role hierarchy boundaries, CWE-285 |
| `AUTHENTICATION_SESSION_CONTROL` | 12 | Unauthenticated access gate, fail-closed default, anonymous controls |
| `API_SECURITY_HTTP_SEMANTICS` | 12 | HTTP verb tampering, verb tunneling, header overrides, wildcard routes |
| `STATE_MUTATION_INTEGRITY` | 10 | Missing checks on state mutations, persistent state verification |
| `ACCESS_CONTROL_ARCHITECTURE` | 10 | Centralized enforcement, middleware ordering, UI hiding vs server validation |
| `TESTING_METHODOLOGY_EXPERIMENTATION` | 11 | Multi-identity verification, two-account workflows, structural response deltas |
| `FALSE_POSITIVE_CONTROLS_BOUNDARY_VERIFICATION` | 12 | Public data traps, idempotent handlers, informational 200 OK, synthetic mocks |

### 2. Difficulty Distribution (Exact 30 / 40 / 30)

| Difficulty | Count | Definition |
| :--- | :---: | :--- |
| **EASY** | 30 | Terminology closely matches corpus terminology (e.g., "BFLA", "IDOR", "ASVS V4.3"). |
| **MEDIUM** | 40 | Uses paraphrasing and related concepts (e.g., "horizontal authorization", "two-account testing"). |
| **HARD** | 30 | Describes security situations or invariants without naming the vulnerability class. |

### 3. Analytical Query Subsets

| Subset Characteristic | Target | Actual | Purpose |
| :--- | :---: | :---: | :--- |
| **Negative Controls** (`is_negative_control`) | $\ge 15$ | **18** | Tests difficult semantic distinctions (e.g., IDOR vs CSRF, authn vs authz, BFLA vs unauthenticated access, active flaw vs non-operational route). |
| **Security Invariants** (`is_security_invariant`) | $\ge 15$ | **16** | Framed around mandatory system rules rather than vulnerability names. |
| **Evidence Gaps** (`is_evidence_gap`) | $\ge 15$ | **16** | Expressed as missing-information problems required to distinguish competing hypotheses. |
| **Manual Experiments** (`is_experiment`) | $\ge 10$ | **11** | Focuses on minimal manual experiments, probes, and negative control execution. |
| **Paraphrased / Adversarial** (`is_adversarial_or_paraphrased`) | $\ge 15$ | **42** | Completely avoids canonical vulnerability keywords to test semantic matching capability. |

---

## Corpus Coverage & Grounding

Every query is grounded in the active corpus in `data/vapt_corpus/vapt_knowledge.db`:
- **Total Corpus Documents:** 6 (100% represented)
  - `DOC-ASVS-V4-01`: OWASP ASVS v4.0.3 Chapter 4 (Access Control)
  - `DOC-CWE-285`: MITRE CWE-285 (Improper Authorization)
  - `DOC-CWE-639`: MITRE CWE-639 (Authorization Bypass Through User-Controlled Key)
  - `DOC-PLATFORM-INV-01`: Platform Security Invariants and Tenant Isolation
  - `DOC-WSTG-ATHZ-02`: OWASP WSTG v4.2 (Testing for BFLA)
  - `DOC-WSTG-ATHZ-04`: OWASP WSTG v4.2 (Testing for IDOR)
- **Total Corpus Chunks:** 23 (100% represented — every chunk is a target in at least one query)
- **Corpus Gaps Discovered:** The active corpus contains no documents for SSRF, CSRF, XSS, Path Traversal / File Upload (aside from user-controlled key filenames), Cryptography, or SQL Injection. In strict accordance with Phase 0 instructions, queries do not force unsupported categories or invent phantom chunk IDs; distinctions involving these concepts are tested as precision negative controls.

---

## Running Dataset Validation Tests

To execute the test suite:

```bash
.venv\Scripts\python.exe -m pytest tests/unit/test_vapt_benchmark_dataset.py -v
```
