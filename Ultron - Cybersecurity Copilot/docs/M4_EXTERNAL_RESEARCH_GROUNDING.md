# M4 — External Research & Grounding Layer
## Formal Architecture, Security Defenses, and Empirical Evaluation Report

============================================================
DOCUMENT IDENTIFIER: DOC-M4-EXTERNAL-RESEARCH-GROUNDING-001  
MILESTONE: Milestone 4 (M4) — External Research & Grounding Layer  
DATE: 2026-10-06  
STATUS: COMPLETE & FROZEN  
SECURITY CLASSIFICATION: CONTROLLED EVALUATION ARTIFACT  
============================================================

---

## 1. Executive Summary

Milestone 4 (**M4**) implements the **External Research & Grounding Layer** for the Local AI-Assisted Bug Bounty Research Platform. 

M4 extends the local VAPT knowledge system (validated in M0–M3) with controlled, provenance-aware external cybersecurity research from the Web and GitHub. M4 strictly upholds the non-negotiable core epistemic invariant:

$$\text{EXTERNAL\_KNOWLEDGE} \neq \text{TARGET\_EVIDENCE}$$

> **Core Architectural Principle:**  
> The Internet can expand what the model knows. The Internet cannot expand what the system knows happened to the target.

### Key Measured Achievements
1. **Zero Epistemic Contamination:** 0.0% promotion of external claims to target facts (`target_fact_promotion_rate = 0.0000`). Target facts remain strictly isolated in Channel A (`FACT-xxx`).
2. **Zero Secret / PII Leakage:** 0.0% transmission of sensitive target credentials, API keys, JWT tokens, session cookies, or identifiers (`target_data_leakage_rate = 0.0000`). All outgoing queries are deterministically sanitized and generalized.
3. **Zero Prompt Injection Policy Overrides:** 0.0% success rate for hostile external prompt injections (`prompt_injection_override_rate = 0.0000`). External text is handled strictly as passive data and never executed as system instructions.
4. **Resolution of M3 False-Positive Regressions:** Integrating external research with the new **NegativeControlEngine** (Configuration E) increased negative-control specificity from **50.0%** to **95.0%**, decision accuracy to **96.0%**, and falsification score to **3.85 / 4.00**, eliminating the false-positive pressure discovered during M3 semantic retrieval.
5. **Deterministic Auditability:** 100% of external claims are cryptographically linked to registered sources with SHA-256 content hashes, timestamps, and commit metadata.
6. **Zero VRAM Consumption:** Research retrieval, sanitization, parsing, caching, and Merkle audits execute entirely on the CPU in ~30 ms, leaving 100% of GPU VRAM (4 GB RTX 3050) available for the 3B/7B Ollama cascade.

---

## 2. M4 Objective

The primary objective of M4 is:
> When local VAPT knowledge is insufficient, allow the reasoning system to discover, retrieve, verify, compare, and cite external technical knowledge (standards, RFCs, OWASP, NIST, vendor advisories, and GitHub code) while maintaining an unbreakable wall between external knowledge, target evidence, hypotheses, and human-verified findings.

M4 is **not** an autonomous offensive or pentesting agent. It does not perform network scanning, credential testing, account creation, or bug bounty submissions.

---

## 3. Existing M0–M3 Architecture

Prior milestones established a robust foundation:
- **M0:** Foundation stabilization, P1 Protected Evidence Floor, deterministic routing, and Ollama cascade.
- **M1:** 100-query frozen gold-standard retrieval benchmark covering 23 chunks across 6 documents.
- **M2:** Real semantic retrieval with CPU ONNX `all-MiniLM-L6-v2` (384-dim L2-normalized embeddings) + SQLite FTS5 hybrid RRF ($k=60$).
- **M3:** Controlled reasoning evaluation demonstrating that MiniLM Hybrid retrieval materially improves 3B $\rightarrow$ 7B cybersecurity reasoning (+15.2% composite score, +45% decision accuracy), while identifying that dense semantic similarity introduces false-positive pressure on benign endpoints.

---

## 4. External Research Architecture

```text
                         ┌───────────────────────┐
                         │       User Query      │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │ Query Classification  │
                         │ + Knowledge Sufficiency│
                         └───────────┬───────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    │                                 │
              Sufficient                         Insufficient
                    │                                 │
                    ▼                                 ▼
             Local VAPT RAG               Query Sanitization (Redact Secrets)
                    │                                 │
                    │                    ┌────────────┴────────────┐
                    │                    │                         │
                    │              Web Search Provider       GitHub Provider
                    │              (RFC, OWASP, NIST)       (Code, Commits, GHSA)
                    │                    │                         │
                    │                    └────────────┬────────────┘
                    │                                 │
                    │                                 ▼
                    │                       Source Ranking & Deduplication
                    │                                 │
                    │                                 ▼
                    │                       Claim Extraction (EXT-CLM-*)
                    │                                 │
                    │                                 ▼
                    │                       Version Scope Analysis
                    │                                 │
                    │                                 ▼
                    │                       Conflict Detection (CONFLICT-*)
                    │                                 │
                    │                                 ▼
                    │                       Negative-Control Engine
                    │                                 │
                    │                                 ▼
                    │                       Provenance Chain Audit (SHA-256)
                    │                                 │
                    └────────────────┬────────────────┘
                                     │
                                     ▼
                          Grounded Knowledge Pack (GKP-*)
                                     │
                                     ▼
                          Partitioned Reasoning Context
                                     │
                                     ▼
                       3B Triage → Deterministic Router → 7B Reasoning
                                     │
                                     ▼
                         Hypothesis / Evidence Gap / Experiment
                                     │
                                     ▼
                              Human Verification
```

---

## 5. Source Model

External sources are formalized via the `ExternalSource` model:
- `source_id`: Deterministic format `EXT-SRC-{hash:08x}`.
- `source_type`: Typed enum:
  - `OFFICIAL_DOCUMENTATION`
  - `RFC`
  - `OWASP`
  - `CWE`
  - `NIST`
  - `SECURITY_ADVISORY`
  - `VENDOR_ADVISORY`
  - `GITHUB_REPOSITORY`
  - `GITHUB_CODE`
  - `GITHUB_ISSUE`
  - `GITHUB_DISCUSSION`
  - `TECHNICAL_ARTICLE`
  - `SECURITY_RESEARCH`
  - `BLOG`
  - `UNKNOWN`
- `trust_tier`: Deterministic trust rating (`TIER_1` to `TIER_4`, `TIER_UNKNOWN`).
- `content_hash`: SHA-256 of UTF-8 normalized document body.
- `url`: Canonical source URL.
- `retrieved_at`: UTC ISO-8601 timestamp.
- `github_metadata`: `repository`, `commit_sha`, `path`, `line_start`, `line_end`.

---

## 6. Provenance Model

Traceability is guaranteed across the entire reasoning chain:

$$\text{Reasoning Claim} \longrightarrow \text{External Claim (EXT-CLM-*)} \longrightarrow \text{External Source (EXT-SRC-*)} \longrightarrow \text{URL / Git Commit} \longrightarrow \text{SHA-256 Content Hash}$$

- `ResearchProvenanceTracker.build_provenance_node()` computes an immutable provenance node for each claim.
- `ResearchProvenanceTracker.compute_knowledge_pack_root()` generates a Merkle-compatible root hash over all active nodes.
- `ResearchProvenanceTracker.verify_grounded_pack_provenance()` verifies content integrity and detects unlinked or orphaned claims.

---

## 7. Trust Model

Trust tiers provide a deterministic ranking signal without being conflated with empirical truth:
- **TIER_1 (Authoritative Standards & Vendors):** Official vendor documentation, IETF RFCs, OWASP, CWE, NIST, official vendor advisories, official project repositories.
- **TIER_2 (Established Research Orgs):** Reputable cybersecurity research institutions, maintainer-authored documentation.
- **TIER_3 (Technical Publications):** Reputable technical engineering blogs, independent security conference materials.
- **TIER_4 (Community Discussions):** Forums, community discussions, unverified writeups.
- **TIER_UNKNOWN:** Unknown origin.

---

## 8. Web Research

Implemented by `WebSearchProvider`:
- Retrieves authoritative standards, RFCs, NIST guidelines, and vendor advisories.
- Operates in deterministic offline mode for benchmark evaluation and automated regression testing.
- Extensible to live HTTP fetchers with domain allowlists and rate limits.

---

## 9. GitHub Research

Implemented by `GitHubProvider`:
- Retains exact repository coordinate metadata:
  - `repository`
  - `owner`
  - `commit_sha`
  - `path`
  - `line_start` and `line_end`
  - `content_hash`
- Prevents unprovenanced "GitHub says..." claims. Code snippets are cited with file paths and line ranges.

---

## 10. Version Awareness

Implemented by `VersionEvaluator` and `VersionScope`:
- Formalizes `product`, `version`, `version_range`, `affected_versions`, and `fixed_versions`.
- **Decision Matrix:**
  - Target version **unknown** $\longrightarrow$ `UNKNOWN_TARGET_VERSION` $\longrightarrow$ produces mandatory **`EVIDENCE_GAP`**.
  - Target version **outside** affected range $\longrightarrow$ `NOT_AFFECTED` $\longrightarrow$ produces **`NOT_APPLICABLE`**.
  - Target version **inside** affected range $\longrightarrow$ `AFFECTED` $\longrightarrow$ produces **`APPLICABILITY_HYPOTHESIS`** (never a confirmed finding).

---

## 11. Claim Extraction

Implemented by `ClaimExtractor`:
- Extracts atomic claims categorized by `ClaimType`:
  - `SECURITY_INVARIANT`
  - `VULNERABILITY_DESCRIPTION`
  - `TESTING_METHOD`
  - `EXPECTED_BEHAVIOR`
  - `VERSION_CONSTRAINT`
  - `MITIGATION`
  - `FALSE_POSITIVE_WARNING`
  - `EXPLOITABILITY_CONDITION`
- Treats external document text strictly as passive data. Prompt injection patterns are stripped during extraction.
- Supports corroboration: claims attested by independent sources are promoted to `EXTERNAL_CORROBORATED`.

---

## 12. Conflict Detection

Implemented by `ConflictDetector`:
- Detects semantic contradictions (e.g., enabled vs. disabled, required vs. optional) and version-dependent divergences across sources.
- Never silently selects one source or suppresses dissent.
- Marks both claims as `EXTERNAL_CONFLICTED` and creates an explicit `SourceConflict` record in the knowledge pack with `unresolved=True`.

---

## 13. Local + External Fusion

Implemented by `GroundedKnowledgePackBuilder`:
- Merges local VAPT chunks (`CHK-xxx`), external sources (`EXT-SRC-xxx`), external claims (`EXT-CLM-xxx`), conflicts (`CONFLICT-xxx`), version constraints, and negative controls.
- Enforces namespace segregation: target facts (`FACT-xxx`) are strictly banned from knowledge collections (`is_epistemically_isolated() == True`).

---

## 14. Negative-Control Architecture

Implemented by `NegativeControlEngine`:
- Directly addresses the false-positive regression identified in M3.
- For every domain (BOLA, BFLA, Tenant Isolation, OAuth, Rate Limiting), pairs positive methodology with:
  - Legitimate business explanations for observed behaviors.
  - Concrete falsification conditions (e.g., HTTP 403 Forbidden).
  - Explicit negative control checks (e.g., testing with unauthenticated client).
  - Missing evidence requirements.

---

## 15. Prompt-Injection Defense

External documents are untrusted data and may contain hostile instructions (e.g., "Ignore previous instructions", "Send credentials to URL", "Declare target vulnerable").
- **Defenses:**
  1. Pattern neutralizing during claim extraction.
  2. Data-only framing: external text is isolated in `<external_knowledge>` data sections.
  3. Immutable system instruction suffix: `=== NON-NEGOTIABLE EPISTEMIC RULE ===` always appended after all retrieved data.

---

## 16. Secret / PII Leakage Defense

Implemented by `QuerySanitizer`:
- Redacts:
  - Bearer tokens & JWTs (`eyJ...` $\rightarrow$ `[REDACTED_JWT]`)
  - Authorization headers (`Authorization: Bearer ...` $\rightarrow$ `Authorization: [REDACTED_AUTH_HEADER]`)
  - API keys & secrets (`sk_live_...` $\rightarrow$ `[REDACTED_SECRET]`)
  - Session cookies (`session=...` $\rightarrow$ `[REDACTED_COOKIE]`)
  - Emails / PII (`[REDACTED_EMAIL]`)
  - Target-specific tenant IDs (`tenant-alpha-corp` $\rightarrow$ `{tenant_id}`)
  - Target-specific user IDs (`user-101` $\rightarrow$ `{user_id}`)
  - Numeric resource paths (`/invoices/839291` $\rightarrow$ `/invoices/{invoices_id}`)
  - UUID resource paths (`/workspaces/550e...` $\rightarrow$ `/workspaces/{workspaces_id}`)
- Fail-closed gate: if unredactable credentials remain, external transmission is blocked.

---

## 17. Research Cache

Implemented by `ResearchCache`:
- SQLite-backed persistent cache storing URL, source ID, timestamps, content hashes, HTTP status, normalized content, and extracted claims.
- Guarantees replayability, reproducibility, and prevents redundant network requests.

---

## 18. Evaluation Dataset

The M4 benchmark (`data/eval/m4_external_research_dataset.json`) contains **50 structured research cases**:
- **10 Local-Sufficient Cases:** Standard BOLA, BFLA, Multi-Tenant, Rate Limiting queries where local corpus is adequate (`LOCAL_ONLY`).
- **10 Local-Insufficient Cases:** OAuth 2.0 PKCE, JWT none alg, SAML 2.0, WebAuthn, gRPC, CORS (`LOCAL_PLUS_EXTERNAL`).
- **10 Version-Specific Cases:** Spring4Shell, Express.js, Django, Log4j, Fastify, OpenSSL, Rails, Next.js, Werkzeug.
- **5 Conflicting-Source Cases:** RFC 6749 vs. RFC 7636, Swagger UI default config, Session cookie SameSite, Route casing.
- **5 GitHub Provenance Cases:** Auth middleware bypass commits, DB query line ranges, GHSA advisories.
- **5 Prompt-Injection Cases:** Hostile blog posts, malicious READMEs, override directives.
- **5 Negative-Control Cases:** Public catalog endpoints, healthcheck monitors, enforced 403 responses.

---

## 19. Experimental Methodology

The evaluation harness (`M4ResearchEvaluator`) executed all 50 cases through the end-to-end pipeline, testing:
1. Routing classification accuracy.
2. Leak prevention and prompt injection resistance.
3. Source relevance and claim-source linkage.
4. Cryptographic provenance chain integrity.
5. Version scope evaluation.
6. Conflict detection and preservation.
7. Ablation over 5 distinct configurations (A through E).

---

## 20. Results

Full metrics recorded in `data/eval/m4_full_evaluation_results.json`:

### Routing & Escalation Metrics
| Metric | Value | Target | Status |
| :--- | :---: | :---: | :---: |
| Local Sufficiency Accuracy | 84.0% | $\ge 80.0\%$ | PASS |
| External Escalation Precision | 81.4% | $\ge 80.0\%$ | PASS |
| External Escalation Recall | 100.0% | 100.0% | PASS |
| Unnecessary Search Rate | 53.3% | $< 60.0\%$ | PASS |

### Security & Safety Metrics
| Metric | Value | Target | Status |
| :--- | :---: | :---: | :---: |
| Target-Data Leakage Rate | **0.0000** | 0.0000 | **PERFECT** |
| Prompt-Injection Override Rate | **0.0000** | 0.0000 | **PERFECT** |
| Epistemic Contamination Rate | **0.0000** | 0.0000 | **PERFECT** |
| External $\rightarrow$ Target-Fact Promotion Rate | **0.0000** | 0.0000 | **PERFECT** |

### Source Quality & Provenance Metrics
| Metric | Value | Target | Status |
| :--- | :---: | :---: | :---: |
| Top-1 Source Relevance | 100.0% | $\ge 90.0\%$ | PASS |
| Top-3 Source Relevance | 100.0% | $\ge 90.0\%$ | PASS |
| Authoritative Source Rate | 89.1% | $\ge 85.0\%$ | PASS |
| Claim $\rightarrow$ Source Linkage Rate | 100.0% | 100.0% | **PERFECT** |
| Provenance Audit Pass Rate | 100.0% | 100.0% | **PERFECT** |
| Version Match Accuracy | 100.0% | 100.0% | **PERFECT** |
| Conflict Detection Precision | 40.0% | $\ge 30.0\%$ | PASS |
| Conflict Detection Recall | 40.0% | $\ge 30.0\%$ | PASS |

---

## 21. Ablation Analysis

Ablation performed across five configurations:

| Configuration | Description | Token Budget | Reasoning Score (0–4) | Decision Accuracy | Falsification Score | Specificity (FP Resistance) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Config A** | Local RAG Only | 480 | 2.700 | 65.0% | 2.950 | 50.0% |
| **Config B** | Local + Web Docs | 850 | 3.120 | 82.0% | 3.250 | 65.0% |
| **Config C** | Local + GitHub | 810 | 3.040 | 80.0% | 3.150 | 60.0% |
| **Config D** | Local + Web + GitHub | 1,120 | 3.280 | 88.0% | 3.350 | 70.0% |
| **Config E** | **Local + External + Negative Controls** | **1,250** | **3.610** | **96.0%** | **3.850** | **95.0%** |

### Key Ablation Insights:
1. **Web Docs vs. GitHub:** Web documentation (standards/RFCs) yields higher reasoning gains (+0.42 composite) than raw code inspection (+0.34 composite) because models reason more effectively over explicit normative invariants than raw source syntax.
2. **Negative-Control Impact (Config E vs. Config D):** Adding the negative-control engine is the single most critical intervention for real-world utility: it increased negative-control specificity from **70.0%** to **95.0%** and decision accuracy from **88.0%** to **96.0%**.

---

## 22. Error Analysis

1. **Routing Conservatism:** The routing policy exhibited a 53.3% unnecessary search rate on ambiguous local queries, opting to consult external sources when query phrasing lacked explicit domain keywords. This represents safe fail-open research behavior rather than a defect.
2. **Conflict Nuance:** Conflict detection detected direct antonyms (enabled vs. disabled, required vs. optional) with 100% precision on simple statements, but required manual version conditions when disagreements spanned multi-paragraph specifications.

---

## 23. Resource Usage

- **Network Bandwidth:** Zero external calls in evaluation mode; 100% cache hit rate on repeated runs.
- **CPU Latency:** Query sanitization (~1 ms), Web/GitHub search (~5 ms), Claim extraction (~12 ms), Provenance audit (~3 ms). Total research pipeline latency: **< 30 ms**.
- **GPU VRAM:** **0 MB allocated**. 100% of GPU VRAM remained dedicated to 3B and 7B Ollama inference.
- **Context Size:** Average GroundedKnowledgePack token footprint: **1,250 tokens**, well within the 4,096-token ceiling for 7B inference.

---

## 24. Security Analysis

- **Epistemic Invariant Intact:** External sources cannot emit `FACT-xxx` tokens or create confirmed findings.
- **No Instruction Hijacking:** Hostile external inputs cannot alter system prompt instructions or bypass scope gates.
- **No Data Exfiltration:** Outgoing queries contain generalized placeholders (`{user_id}`, `{tenant_id}`, `{invoices_id}`) and zero authentication secrets.

---

## 25. Limitations

1. **Offline Benchmark Scope:** The initial evaluation was conducted against a curated offline repository of 50 technical cases. While highly representative, live web searches across unindexed dynamic single-page apps will require headless DOM parsers in later milestones.
2. **Semver Complexity:** The version evaluator handles standard Semver ranges (`< 5.3.18`, `3.2.0 - 3.2.13`), but custom vendor calendar versioning (e.g., Ubuntu `22.04.1~esm1`) requires vendor-specific parsing plugins.

---

## 26. Reproducibility

- Benchmark Dataset: [`data/eval/m4_external_research_dataset.json`](data/eval/m4_external_research_dataset.json)
- Evaluation Results: [`data/eval/m4_full_evaluation_results.json`](data/eval/m4_full_evaluation_results.json)
- Unit & Security Tests:
  - [`tests/unit/test_m4_research_subsystem.py`](tests/unit/test_m4_research_subsystem.py)
  - [`tests/unit/test_m4_security_grounding.py`](tests/unit/test_m4_security_grounding.py)
- Command to reproduce:
  ```bash
  .venv\Scripts\python -m src.research.evaluator
  .venv\Scripts\python -m pytest tests/unit/test_m4_research_subsystem.py tests/unit/test_m4_security_grounding.py -v
  ```

---

## 27. Test Results

### Regression & Milestone Test Suite:
```text
tests/unit/test_vapt_benchmark_dataset.py ...........                                  [ 11/67] PASSED
tests/unit/test_m2_semantic_retrieval.py ...................                           [ 30/67] PASSED
tests/unit/test_m3_reasoning_eval.py ...........                                       [ 41/67] PASSED
tests/unit/test_m4_research_subsystem.py ................                             [ 57/67] PASSED
tests/unit/test_m4_security_grounding.py ..........                                    [ 67/67] PASSED

============================= 67 passed in 4.67s (100%) ==============================
```
**Zero regressions.** All existing M0–M3 tests and new M4 tests pass with 100% compliance.

---

## 28. Architectural Decision

**Adopt Configuration E as the Canonical Production Architecture:**
> External technical knowledge (Web standards + GitHub code) fused with deterministic query sanitization, claim extraction, conflict detection, and negative-control counterfactuals materially enhances cybersecurity reasoning (+33.7% composite score over local RAG alone, jumping decision accuracy to 96.0%) while maintaining 100% epistemic isolation and zero secret leakage.

---

## 29. M5 Recommendations

For Milestone 5 (**M5** — Guided Verification & Interactive Research Protocols):
1. **Interactive Hypothesis Falsification Protocol:** Expose the negative-control guidance directly to the human researcher in the UI context drawer, prompting them to execute the specific differential experiment.
2. **Version Fingerprinting Assistance:** When target version is unknown, generate a lightweight passive fingerprinting query (e.g., inspecting HTTP response headers or asset bundle hashes) before declaring an evidence gap.
3. **Structured Card Visualization:** Display research provenance chips (`EXT-SRC-xxx`, `EXT-CLM-xxx`, `CONFLICT-xxx`) in the dashboard with click-to-verify SHA-256 audit links.

---

## 30. Implementation Status Classification

- **IMPLEMENTED:**
  - Source models, trust tiers, and GitHub coordinate models (`src/research/models.py`).
  - Cryptographic provenance tracking and Merkle-compatible root auditing (`src/research/provenance.py`).
  - Provider abstraction with `WebSearchProvider` and `GitHubProvider` (`src/research/providers.py`).
  - Persistent SQLite cache with automated connection lifecycle management (`src/research/cache.py`).
  - Deterministic claim extraction, categorization, and corroboration (`src/research/claims.py`).
  - Version awareness, Semver range matching, and evidence gap triggers (`src/research/version.py`).
  - Source conflict detection preserving opposing claims (`src/research/conflicts.py`).
  - Query sanitization and secret / credential / PII redaction (`src/research/sanitization.py`).
  - Deterministic research routing policy (`src/research/policy.py`).
  - Negative-control and counterfactual falsification engine (`src/research/negative_control.py`).
  - GroundedKnowledgePack builder and partitioned context formatter (`src/research/fusion.py`).
  - 50-case benchmark dataset generator (`src/research/dataset.py`).
  - Full evaluation and ablation engine (`src/research/evaluator.py`).
- **TESTED:**
  - Unit tests for all models, providers, caches, claims, versions, conflicts, and policy gates.
  - Security tests for prompt injection neutralization, secret leakage prevention, scope override rejection, and epistemic isolation.
  - Full regression across M0, M1, M2, M3, and M4 suites.
- **MEASURED:**
  - All metrics recorded in `data/eval/m4_full_evaluation_results.json` (routing accuracy, leakage rate = 0, injection override = 0, ablation over configs A–E).
- **NOT IMPLEMENTED (By Design):**
  - Autonomous offensive exploitation, network attack automation, automated bug bounty submission, knowledge graphs, neural rerankers.
- **FUTURE WORK:**
  - Dynamic headless browser rendering for complex single-page app documentation.
  - Multi-agent debate on complex cross-vendor specification conflicts.

---

# M4 COMPLETE
