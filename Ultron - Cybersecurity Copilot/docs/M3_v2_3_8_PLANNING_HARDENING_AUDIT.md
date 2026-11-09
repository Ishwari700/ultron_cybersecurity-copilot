# Milestone M3 v2.3.8 Planning Hardening & Semantic Clarification Audit Report

**Audit Target**: `docs/M3_VAPT_KNOWLEDGE_RAG_PLAN.md`  
**Revision**: `v2.3.8` (Maintained; zero version advance)  
**Audit Execution Date**: 2026-09-19  
**Execution Environment**: Local Workspace (Windows, PowerShell, Python 3.12)  
**Historical Baselines & Checkpoint Provenance**:
- Historical Baseline Commit: `f14528654053f0ea283b3d64bd6c5c1b0ce454e0`
- Intermediate Frozen Milestone Commit: `f335b98b2dfdeb8ee1588f841f890215fa9f0006`
- Active Working Checkpoint: `a753ebf8ec6ff2073ae4f4b176994dd70a0ebac2`
- Regression Test Planning Baseline: 315 collected tests

---

## 1. Executive Summary & Audit Scope

This document records the formal, exhaustive planning-hardening audit performed on `docs/M3_VAPT_KNOWLEDGE_RAG_PLAN.md` for revision `v2.3.8`, incorporating the final micro-correction resolving tie-breaking domain ambiguity.

### Core Purpose of v2.3.8 Revision & Tie-Breaking Clarification
1. **Semantic Separation of Score Governance & Fusion**: Resolves all ambiguities between channel-level `RAW_SCORE`, rank-based Reciprocal Rank Fusion (`RRF`), retrieval metrics (`Recall@5`, `MRR@5`, `Precision@5`, `InjectionHit@P4_256`), and candidate backend selection ranking.
2. **Explicit Separation of Tie-Breaking Domains**: Eliminates the ambiguous phrase *"If two candidates or chunks have numerically identical raw scores ... ties are resolved strictly by `chunk_id ASC`"*. The specification now explicitly distinguishes:
   - **Retrieved-Chunk Tie-Breaking**: When two retrieved chunks have equal raw scores, ties are resolved strictly by `chunk_id ASC` in ASCII byte order.
   - **Backend-Candidate Tie-Breaking**: Backend candidates MUST NOT use `chunk_id` for backend selection. After all hard qualification gates pass, candidate backends are ranked by Recall@5, then MRR@5, latency, dependency footprint, and deterministic candidate ID (`Candidate 1` before `Candidate 2` before `Candidate 3`). **Backend-candidate ties are resolved by candidate_id, not chunk_id.**

### Exact Scoped Audit Claim
> **AUDIT CLAIM**:  
> **No unresolved artifact-level textual, structural, or semantic contradictions were detected by the v2.3.8 planning audit.**

### Strict Claim Boundaries (What is NOT Claimed)
In strict accordance with the Tiered Validation Boundary defined in Section 36.1:
- This planning audit **DOES NOT** claim empirical correctness of retrieval performance.
- This planning audit **DOES NOT** claim statistical validity or empirical power of human audit findings.
- This planning audit **DOES NOT** claim cryptographic runtime execution correctness.
- This planning audit **DOES NOT** claim benchmark execution success or hypothesis yield superiority.
- This planning audit is **STRICTLY LIMITED** to Tier A artifact-level textual, structural, and semantic consistency verification.

---

## 2. Canonical Semantic Model Formalized in v2.3.8

Revision `v2.3.8` enforces six canonical semantic principles across every section of the specification:

### Principle 1: Channel-Level `RAW_SCORE` Governance
Individual retrieval channels emit raw floating-point scores where applicable (e.g., BM25 score in SQLite FTS5, cosine similarity in neural vector search).
> *"RAW_SCORE governs ranking within each individual retrieval channel, relevance thresholding where applicable, raw-score comparisons, and reproducibility evaluation."*

`RAW_SCORE` **DOES NOT**:
- Directly calculate or enter RRF formulas.
- Directly determine the final fused retrieval ranking.
- Directly rank backend candidates.

### Principle 2: Purely Rank-Based RRF Fusion
Reciprocal Rank Fusion is purely rank-based and operates on channel rank positions ($r(d) \in \{1, 2, \dots\}$), using fixed architectural constants:
$$S_{\text{sparse}}(d) = \frac{w_{\text{bm25}}}{k_{\text{rrf}} + r_{\text{sparse}}(d)}, \quad S_{\text{dense}}(d) = \frac{w_{\text{dense}}}{k_{\text{rrf}} + r_{\text{dense}}(d)}$$
$$\text{Score}_{\text{RRF}}(d) = S_{\text{sparse}}(d) + S_{\text{dense}}(d)$$
- $k_{\text{rrf}} = 60$ (fixed architectural constant)
- $w_{\text{bm25}} = 0.5, w_{\text{dense}} = 0.5$ (fixed architectural constants)
- Missing ranks contribute strictly $0.0$.
- RRF parameters are never tuned on validation data.
> *"RRF is purely rank-based and operates on channel rank positions, not directly on RAW_SCORE values."*

### Principle 3: Retrieval Metrics Computed from Final Fused Retrieval Ranking
All retrieval evaluation and qualification metrics are computed directly from the final fused retrieval ranking produced by the canonical retrieval pipeline:
> *"Recall@5, MRR@5, Precision@5, and InjectionHit@P4_256 are computed from the final fused retrieval ranking produced by the canonical retrieval pipeline."*

### Principle 4: Metric-Based Backend Candidate Qualification & Selection
Backend candidate selection occurs **strictly after all four hard qualification gates pass**:
1. Hard Gate 1: Reproducibility Filter ($\le 10^{-6}$ drift across 100 runs, 100% top-$k$ set and rank identity).
2. Hard Gate 2: Retrieval Recall Gate ($\text{Recall@5} \ge 0.80$ on `QUALIFICATION_SELECTION_SET`).
3. Hard Gate 3: Retrieval MRR Gate ($\text{MRR@5} \ge 0.60$ on `QUALIFICATION_SELECTION_SET`).
4. Hard Gate 4: Deployment Capacity Gate ($\text{InjectionHit@P4\_256} \ge 0.75$ on `QUALIFICATION_SELECTION_SET` under `CanonicalP4Serialization`).

After passing all four hard gates, qualified backend candidates are ranked strictly by:
> *"After all hard qualification gates pass, candidate backends are ranked by Recall@5, then MRR@5, then latency, dependency footprint, and deterministic candidate ID."*
> *"RAW_SCORE does not directly rank backend candidates."*

### Principle 5: Explicit Tie-Breaking Domain Separation
Tie-breaking is strictly bifurcated by domain:
- **Retrieved-Chunk Tie-Breaking**: If two retrieved chunks have numerically identical raw channel scores or raw fused RRF scores under standard IEEE 754 floating-point equality, resolve the chunk-ranking tie using `chunk_id ASC` in ASCII byte order.
- **Backend-Candidate Tie-Breaking**: Backend candidates MUST NOT use `chunk_id` for backend selection. After all hard qualification gates pass, backend candidates are ranked by Recall@5, MRR@5, latency, dependency footprint, and final deterministic candidate ID (`Candidate 1` before `Candidate 2` before `Candidate 3`).
> *"Backend-candidate ties are resolved by candidate_id, not chunk_id."*

### Principle 6: Three-Tier Score Distinction
The specification maintains a strict, non-overlapping distinction among three numerical representations:
1. `Raw Channel Score`: Full-precision floating-point score emitted by an individual channel (BM25 or dense cosine similarity);
2. `Raw Fused RRF Score`: Full-precision floating-point sum $S_{\text{sparse}}(d) + S_{\text{dense}}(d)$, establishing fused document ordering;
3. `Rounded Display Score`: Rounded to 6 decimal places strictly for human-readable audit logging, telemetry reporting, and summary manifests. Rounded scores **NEVER** participate in ranking, tie detection, candidate ordering, or reproducibility decisions.

---

## 3. Automated Audit Verification Results

An automated, end-to-end Python audit suite (`scratch/audit_v2_3_8_final.py`) was executed against the entire text of `docs/M3_VAPT_KNOWLEDGE_RAG_PLAN.md`. All 24 audit checks passed with zero errors or warnings:

| Check ID | Verification Description | Result | Details / Evidence |
| :---: | :--- | :---: | :--- |
| **Check 01** | Document Version Consistency (`v2.3.8` everywhere) | **PASS** | Header line 2, Section 36 header, matrix row 1, Section 36 scope, planned manifest notes, and footer verified; zero lingering `v2.3.7` in active text. |
| **Check 02** | Acceptance Criteria Count == 46 | **PASS** | Exactly 46 numbered criteria in Section 31 (`1.` through `46.`). |
| **Check 03** | Section 36 Matrix Row Count == 38 | **PASS** | Exactly 38 evaluation rows in Section 36.2 audit table. |
| **Check 04** | No statement says RAW_SCORE directly computes RRF | **PASS** | Zero occurrences of phrases suggesting RAW_SCORE computes or is input to RRF. |
| **Check 05** | RRF explicitly rank-based and not directly on RAW_SCORE | **PASS** | Confirmed explicit assertion across Sections 11.5, 12.1, 19.1, 31, and 32. |
| **Check 06** | Canonical Dataflow explicitly documented | **PASS** | `channel score -> channel ranking -> rank positions -> fixed RRF fusion -> fused ranking` present in all relevant sections. |
| **Check 07** | No statement says RAW_SCORE directly determines final fused ranking | **PASS** | Zero occurrences suggesting RAW_SCORE directly determines fused ranking. |
| **Check 08** | No statement says RAW_SCORE directly ranks backend candidates | **PASS** | All legacy "governed strictly by RAW_SCORE" candidate ranking phrases completely eliminated. |
| **Check 09** | Retrieval metrics explicitly computed from final fused ranking | **PASS** | Standard canonical phrasing applied to Recall@5, MRR@5, Precision@5, InjectionHit@P4_256. |
| **Check 10** | RAW_SCORE canonical governance scope explicitly stated | **PASS** | Defined exclusively for within-channel ranking, thresholding, raw comparisons, and reproducibility. |
| **Check 11** | Backend selection metric ranking explicitly stated | **PASS** | Rank by Recall@5, then MRR@5, latency, footprint, candidate ID after hard gates pass. |
| **Check 12** | "RAW_SCORE does not directly rank backend candidates" asserted | **PASS** | Explicitly stated across Sections 11.5, 19.1, 24.1.1, 31 (Crits 8, 18, 24, 44), and 32. |
| **Check 13** | RRF constants fixed architectural constants ($k=60, w=0.5/0.5$) | **PASS** | Confirmed immutable, never tuned on validation data. |
| **Check 14** | Phase Order Consistency in Section 30 | **PASS** | `M3.15 -> M3.15.1 -> M3.16 -> M3.17 -> M3.18 -> M3.19` strictly verified. |
| **Check 15** | Changelog contains v2.3.8 entry | **PASS** | Entry present detailing semantic and tie-breaking clarification across Sections 11.5, 12, 19.1, 24.1, 31, 32, 36. |
| **Check 16** | Scoped audit claim wording exact | **PASS** | Exact phrase "No unresolved artifact-level textual, structural, or semantic contradictions were detected by the v2.3.8 planning audit." |
| **Check 17** | Baseline checkpoints and 315 tests count preserved | **PASS** | `f14528...`, `f335b9...`, `a753eb...`, and 315 tests planning baseline preserved. |
| **Check 18** | Human study exact 10 vulnerable + 10 control balance preserved | **PASS** | 20 scenarios, 10 vulnerable, 10 negative control, largest-remainder algorithm preserved. |
| **Check 19** | Planning-only boundary maintained (zero `src/` or `tests/` edits) | **PASS** | `git status` verifies zero modified tracked files; no changes to production or test code. |
| **Check 20** | Final status is PLANNING COMPLETE / IMPLEMENTATION BLOCKED | **PASS** | Concluding status block intact in both specification and audit documents. |
| **Check 21** | Retrieved-chunk ties explicitly use chunk_id ASC in ASCII byte order | **PASS** | Confirmed in Sections 11.5, 12.2, 19.1, 31 (Crit 18, 40), and 32. |
| **Check 22** | Backend-candidate ties explicitly use candidate_id, not chunk_id | **PASS** | Explicit sentence "Backend-candidate ties are resolved by candidate_id, not chunk_id" verified across Sections 11.5, 12.2, 19.1, 31 (Crit 18), 32, 34, 36. |
| **Check 23** | No backend-selection rule uses chunk_id | **PASS** | Automated search confirmed zero backend-selection rules reference chunk_id for backend ranking. |
| **Check 24** | No contradictory/ambiguous "candidates or chunks" tie-break wording remains | **PASS** | Zero occurrences of legacy ambiguous phrase; complete domain separation verified. |

---

## 4. Section-by-Section Reconciliation Details

The following sections of `docs/M3_VAPT_KNOWLEDGE_RAG_PLAN.md` received surgical semantic and tie-breaking updates:

1. **Section 1 (Header)**:
   - Preserved document version at `2.3.8`.

2. **Section 11.5 (Canonical Backend Selection Rule)**:
   - Removed legacy `evaluated strictly using RAW_SCORE` from Hard Qualification Gates 2 & 3.
   - Replaced with: `(Recall@5, MRR@5, Precision@5, and InjectionHit@P4_256 are computed from the final fused retrieval ranking produced by the canonical retrieval pipeline)`.
   - Removed `(governed strictly by RAW_SCORE)` from Primary Ranking Metric and First Tie-Breaker.
   - Clarified introductory selection rule: after all four hard gates pass, backends are ranked by Recall@5, then MRR@5, latency, footprint, and candidate ID; `RAW_SCORE does not directly rank backend candidates`.
   - Line 655 updated to explicitly separate chunk ties (`chunk_id ASC`) from backend-candidate ties (`candidate_id, not chunk_id`).

3. **Section 12.2 (RRF Formulation & Missing-Rank Contract)**:
   - Line 680 clarified: Raw fused RRF score governs `fused document ranking` (avoiding ambiguous "fused candidate ranking").
   - Line 685 clarified: If two retrieved chunks have equal raw fused RRF scores, resolve chunk-ranking tie deterministically by `chunk_id ASC` in ASCII byte order. `Backend-candidate ties are resolved by candidate_id, not chunk_id.`

4. **Section 19.1 Item 3 (Raw-Score Ranking Governance, RRF & Deterministic Tie-Breaking)**:
   - Formalized canonical dataflow: `channel score -> channel ranking -> rank positions -> fixed RRF fusion -> fused ranking`.
   - Explicitly documented: `RAW_SCORE does not directly rank backend candidates`.
   - Replaced ambiguous *"If two candidates or chunks have numerically identical..."* with dedicated sub-bullets:
     - `Retrieved-Chunk Tie-Breaking`: using `chunk_id ASC` in ASCII byte order.
     - `Backend-Candidate Tie-Breaking`: backend candidates MUST NOT use `chunk_id` for backend selection. Ranked by Recall@5, MRR@5, latency, footprint, deterministic candidate ID. `Backend-candidate ties are resolved by candidate_id, not chunk_id.`

5. **Section 24.1 (Primary Research Metrics Table & Governance)**:
   - In metric table rows for Recall@5 and MRR@5, replaced `governed by RAW_SCORE` with `computed from final fused retrieval ranking`.
   - In Section 24.1.1, added Rule 5 formally specifying the separation of retrieval metric calculation (from fused ranking) and channel-level RAW_SCORE governance.

6. **Section 27.1 / Section 24.2 (Planned Manifest Version References)**:
   - Verified parenthetical references state `(PLANNED artifact only in v2.3.8)` in lines 1306 and 1528.

7. **Section 31 (Explicit Acceptance Criteria)**:
   - **Criterion 7**: Clarified that Recall@5 and MRR@5 qualification gates are computed from the final fused retrieval ranking produced by the canonical retrieval pipeline.
   - **Criterion 8**: Replaced legacy phrase `canonical candidate ranking is governed strictly by full-precision RAW_SCORE` with full metric-based selection hierarchy and explicit assertion: `RAW_SCORE does not directly rank backend candidates`.
   - **Criterion 18**: Clarified that RRF operates on channel rank positions (not directly on RAW_SCORE) and that raw fused RRF scores establish fused document ranking; `RAW_SCORE does not directly rank backend candidates`; retrieved-chunk ties are resolved deterministically by `chunk_id ASC` in ASCII byte order; `backend-candidate ties are resolved by candidate_id, not chunk_id`.
   - **Criterion 24**: Restated canonical RAW_SCORE scope and confirmed `RAW_SCORE does not directly rank backend candidates`.
   - **Criterion 44**: Full restatement of canonical governance, canonical dataflow, and explicit non-ranking of backend candidates by RAW_SCORE.
   - Total criteria count maintained at exactly 46.

8. **Section 32 (Open Architectural Decisions - Decision 1)**:
   - Symmetrically aligned Decision 1 with Section 11.5: updated Gates 2 and 3, updated ranking metrics 5 and 6, and updated the Decision 1 Invariant to explicitly state that chunk ties use `chunk_id ASC` while `backend-candidate ties are resolved by candidate_id, not chunk_id`.

9. **Section 34 (Document Changelog)**:
   - Updated `v2.3.8` changelog entry documenting both the semantic score clarification and the explicit tie-breaking domain separation across Sections 11.5, 12, 19.1, 24.1, 31, 32, and 36.

10. **Section 36 (Readiness Checklist & Matrix)**:
    - Header: `## 36. M3 v2.3.8 Freeze Readiness Checklist`.
    - Scope: references `v2.3.8 planning audit`.
    - Matrix Row 1: `Actual document version = 2.3.8`.
    - Matrix Row 14 updated with complete canonical separation wording, including: `retrieved-chunk ties use chunk_id ASC, backend-candidate ties are resolved by candidate_id, not chunk_id`.
    - Matrix Row 29 updated with scoped v2.3.8 claim wording.
    - Matrix Row 33: qualification thresholds computed from final fused retrieval ranking.
    - Matrix row count maintained at exactly 38.

11. **Document Footer**:
    - Preserved: `*End of Milestone M3 Architectural Specification & Implementation Plan (v2.3.8).*`

---

## 5. Architectural & Methodological Invariant Preservation

The audit confirms that all preexisting methodological constraints, protocols, and numbers remain completely intact:

| Invariant | Value / Specification in v2.3.8 | Status |
| :--- | :--- | :---: |
| **RRF Constants** | $k_{\text{rrf}} = 60$, $w_{\text{bm25}} = 0.5, w_{\text{dense}} = 0.5$ (fixed, immutable, never tuned) | **PRESERVED** |
| **Hard Qualification Thresholds** | Recall@5 $\ge 0.80$, MRR@5 $\ge 0.60$, InjectionHit@P4_256 $\ge 0.75$, drift $\le 10^{-6}$ | **PRESERVED** |
| **Human Study Sample Size & Balance** | Exactly 20 scenarios (10 vulnerable + 10 control); seed `20260919` | **PRESERVED** |
| **Pre-Freeze Phase Ordering** | M3.15.1 scenario selection occurs strictly before M3.16 and M3.17 | **PRESERVED** |
| **RETRIEVAL_FINAL_EVAL Pre-Freeze** | $n=15$ queries frozen at M3.0 in manifest; evaluated once in M3.16 | **PRESERVED** |
| **Reliability Statistics** | Primary Fleiss' $\kappa \ge 0.70$; secondary single diagnostic: Krippendorff's $\alpha_{\text{ordinal}}$ | **PRESERVED** |
| **Timing Protocol** | Un-clamped $T_{\text{raw}}$ with START / PAUSE / RESUME / STOP and 30-second flag | **PRESERVED** |
| **Causal Grounding Parity** | $\text{TargetEvidencePayload}(B) == \text{TargetEvidencePayload}(D)$ byte equivalence | **PRESERVED** |
| **P4 Capacity Oracle** | Cryptographically pinned tokenizer identity; 100% byte parity against production serializer | **PRESERVED** |
| **Acceptance Criteria Total** | Exactly 46 numbered criteria | **PRESERVED** |
| **Section 36 Matrix Total** | Exactly 38 evaluation rows | **PRESERVED** |
| **Planning-Only Boundary** | Zero code modified under `src/` or `tests/`; zero benchmark or index execution | **PRESERVED** |

---

## 6. Audit Conclusion & Final Milestone Status

The Milestone M3 specification `docs/M3_VAPT_KNOWLEDGE_RAG_PLAN.md` remains at **Version 2.3.8**. All semantic ambiguity between channel-level `RAW_SCORE`, rank-based `RRF`, fused retrieval metrics, and candidate backend selection ranking, as well as the explicit separation between chunk tie-breaking (`chunk_id ASC`) and backend-candidate tie-breaking (`candidate_id, not chunk_id`), has been completely and consistently resolved throughout the artifact.

```text
================================================================================
MILESTONE M3 STATUS:
PLANNING COMPLETE / IMPLEMENTATION BLOCKED PENDING HUMAN SIGN-OFF
================================================================================
No production implementation, test execution, benchmark execution, corpus build,
vector index generation, or human-study execution has been performed.
Implementation remains strictly blocked pending explicit human researcher sign-off.
================================================================================
```
