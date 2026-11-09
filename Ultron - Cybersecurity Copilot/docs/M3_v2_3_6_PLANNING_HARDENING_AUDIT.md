# Milestone M3 v2.3.6 Planning Hardening & Methodology Audit Report

**Audit Target Artifact:** [`docs/M3_VAPT_KNOWLEDGE_RAG_PLAN.md`](docs/M3_VAPT_KNOWLEDGE_RAG_PLAN.md)  
**Revision Transition:** `v2.3.5` $\longrightarrow$ `v2.3.6`  
**Audit Execution Date:** 2026-09-19  
**Audit Scope:** STRICT PLANNING-ONLY METHODOLOGY HARDENING & ARTIFACT-LEVEL CONSISTENCY AUDIT  
**Operating Mode:** STRICT PLANNING ONLY (Zero source code modifications, zero test changes, zero benchmark execution, zero corpus/index modifications)  

---

## 1. Executive Summary & Verification Boundary

This audit report documents the formal methodology hardening pass applied to the Milestone M3 Architectural Specification and Implementation Plan (`docs/M3_VAPT_KNOWLEDGE_RAG_PLAN.md`), transitioning the specification from version `2.3.5` to `2.3.6`.

### 1.1 Strict Four-Tier Verification Boundary Scope
In strict adherence to scientific rigor and platform governance, this audit claims **ONLY artifact-level textual and structural consistency** (Tier A). It does **NOT** claim empirical, statistical, cryptographic runtime, or benchmark success:

- **Tier A (Artifact Consistency Verification — THIS AUDIT)**: Automated text and structural consistency verification confirming that phase numbering, interfaces, mathematical formulations, acceptance criteria, split definitions, serialization schemas, rubrics, estimands, and readiness matrices are mutually consistent and free of contradictions across Markdown sections.  
  *(Audit Result: 100% PASS — Claimed COMPLETE)*
- **Tier B (Statistical Methodology Validation)**: Empirical validation of statistical properties, statistical power, and distribution assumptions on observed human review timing and hypothesis yield data during Phase M3.19.  
  *(Audit Result: PENDING — VALIDATION upon human study execution)*
- **Tier C (Cryptographic Implementation Validation)**: Runtime validation of RFC 9162 Merkle tree construction, Ed25519 digital signature generation/verification with pinned public-key bytes and fingerprint, and SHA-256 byte-parity in Python runtime during Phases M3.4 and M3.12.  
  *(Audit Result: PENDING — IMPLEMENTATION)*
- **Tier D (Empirical Benchmark Validation)**: Full execution of the 84-scenario benchmark and quantification of observed hypothesis yield and latency across ablation tracks during Phases M3.17 and M3.18.  
  *(Audit Result: PENDING — VALIDATION upon benchmark execution)*

---

## 2. Preserved Baselines & Absolute Constraints Verification

```text
┌────────────────────────────────────────┬────────────────────────────────────────┬─────────────────────┐
│ Constraint / Baseline Item             │ Required Value / State                 │ Verification Result │
├────────────────────────────────────────┼────────────────────────────────────────┼─────────────────────┤
│ Historical Reviewer Baseline           │ f14528654053f0ea283b3d64bd6c5c1b0ce454 │ PRESERVED           │
│ Intermediate Frozen Milestone          │ f335b98b2dfdeb8ee1588f841f890215fa9f00 │ PRESERVED           │
│ Currently Verified Active Checkpoint   │ a753ebf8ec6ff2073ae4f4b176994dd70a0eba │ PRESERVED           │
│ Planning-Time Collected Test Baseline  │ 315 tests (not claimed as final count) │ PRESERVED           │
│ Source Code Modifications (`src/`)     │ Exactly 0 files modified               │ PASS (0 files)      │
│ Test Suite Modifications (`tests/`)    │ Exactly 0 files modified               │ PASS (0 files)      │
│ Knowledge Corpus (`data/vapt_corpus/`) │ Exactly 0 files modified               │ PASS (0 files)      │
│ Vector Indexes / Databases             │ Exactly 0 generated / modified         │ PASS (0 files)      │
│ Benchmark Execution                    │ Exactly 0 executions                   │ PASS (0 runs)       │
│ External Network Downloads             │ Exactly 0 downloads                    │ PASS (0 downloads)  │
└────────────────────────────────────────┴────────────────────────────────────────┴─────────────────────┘
```

---

## 3. Systematic Methodology Corrections Audit (P0-1 through P2-3)

### P0-1: Retrieval Qualification vs. Final Generalization Partition Disambiguation
- **Previous Contradiction**: The 15-query split in `data/eval/retrieval_gold.json` was labeled `HELD_OUT_QUALIFICATION` and simultaneously used for hard qualification gating and candidate backend ranking/selection, while also being colloquially referred to as an untouched held-out generalization set.
- **v2.3.6 Correction**:
  1. Renamed the 15-query split in `retrieval_gold.json` to **`QUALIFICATION_SELECTION_SET`** ($n=15$).
  2. Defined its explicit semantic scope: Used strictly for enforcing the four hard qualification gates, selecting the canonical production backend, and breaking deterministic ties. The plan explicitly mandates that it **MUST NOT be described anywhere as an unbiased final test/generalization set**.
  3. Established a distinct, dedicated **`RETRIEVAL_FINAL_EVAL`** partition ($n=15$, physically stored in `data/eval/retrieval_final_eval.json`).
  4. Enforced strict operational rules for `RETRIEVAL_FINAL_EVAL`:
     - Evaluated strictly once in Phase M3.16 after the entire production configuration (backend, renderer, parameters, packing policy) is sealed.
     - NEVER used for tuning.
     - NEVER used for renderer selection.
     - NEVER used for backend selection.
     - NEVER used for qualification thresholds.
     - Provides the unbiased final retrieval generalization measurement of the sealed production retrieval engine.
  5. The four evaluation roles are now strictly separated:
     $$\text{DEV } (n=20) \to \text{Tuning}$$
     $$\text{VAL } (n=15) \to \text{Renderer Selection \& Non-Renderer Freeze}$$
     $$\text{QUALIFICATION\_SELECTION\_SET } (n=15) \to \text{Qualification \& Backend Selection}$$
     $$\text{RETRIEVAL\_FINAL\_EVAL } (n=15) \to \text{Final Unbiased Retrieval Generalization}$$
- **Verification**: Zero non-changelog occurrences of `HELD_OUT_QUALIFICATION` remain in `docs/M3_VAPT_KNOWLEDGE_RAG_PLAN.md`. Sections 11.3, 11.3.1, 11.4, 11.5, 16.3, 24.1, 27.1, 30, 31, 32, and 36 have been fully reconciled.

### P0-2: Canonical P4 Wire Serialization Grammar & Capacity Oracle Parity
- **Previous Contradiction**: Multiple divergent prompt envelope representations existed across sections (e.g. `<vapt_methodology_advisory>` vs. `<advisory_vapt_knowledge id="...">`), conflicting with the promise of byte-for-byte parity between the capacity oracle and production serializer.
- **v2.3.6 Correction**:
  1. Defined ONE canonical wire grammar: **`CanonicalP4Serialization`**.
  2. Complete grammar rules formalized:
     - Outer envelope: Opening `<vapt_methodology_advisory>\n` and closing `\n</vapt_methodology_advisory>` (no outer attributes).
     - Static advisory notice: Immediately follows opening tag, followed by `\n\n`.
     - Per-chunk envelope: `<advisory_chunk id="{chunk_id}" priority="{priority_int}" category="{category}">\n` and `\n</advisory_chunk>`. Attributes strictly ordered: `id`, then `priority`, then `category`.
     - Per-chunk metadata header: `[DOCUMENT: {document_title}] [SECTION: {section_title}]\n`.
     - Chunk body escaping: XML characters `&`, `<`, `>` escaped as `&amp;`, `&lt;`, `&gt;`. Newlines preserved as `\n`. Whitespace normalized.
     - Inter-chunk separator: Exactly `\n\n`.
     - Truncation / capacity budget: Greedy packing up to 256 tokens total under pinned tokenizer. No mid-chunk truncation; chunks either fit completely or are excluded. Unused capacity remains empty.
     - Empty-pack behavior: If 0 chunks fit or are retrieved, serialized wire output is strictly the empty string (`""`, 0 bytes, 0 tokens in P4).
     - Encoding: Strict UTF-8 without BOM.
  3. Formalized parity invariant:
     $$\text{CanonicalP4CapacityOracle}(\text{pack}) \equiv \text{ProductionP4Serializer}(\text{pack})$$
     byte-for-byte under identical pinned tokenizer and runtime configuration.
  4. Clarified that `CanonicalP4CapacityOracle` is scorer-side qualification infrastructure, not an independent formatting dialect.
- **Verification**: Zero occurrences of `<advisory_vapt_knowledge` remain. Sections 13.6, 15, 16.3, 18.1, 31, and 36 strictly adhere to `CanonicalP4Serialization`.

### P0-3: Symmetric Primary Human Rubric for Track B vs. Track D
- **Previous Contradiction**: The human review rubric previously evaluated whether the model faithfully interpreted retrieved VAPT methodology, which was inapplicable to Track B (the un-augmented condition).
- **v2.3.6 Correction**:
  1. **Primary Common Outcome**: Established the **Evidence-Grounded Security Reasoning & Verification Rubric** (5-point symmetric scale), applicable identically to BOTH Track B and Track D.
     - Evaluates: (1) evidence-grounded reasoning, (2) correct use of observed target evidence, (3) correct application of security invariants, (4) appropriate handling of evidence gaps, (5) correctness and discriminative quality of proposed verification experiment, and (6) freedom from unsupported inference / hallucination.
     - Reviewers evaluate output quality blindly **WITHOUT knowing or needing to know whether VAPT knowledge was present or retrieved**.
  2. **Secondary D-Only Outcome**: Established the **Retrieved Methodology Semantic Fidelity Rubric** (5-point scale) measuring *"How faithfully did the model use the retrieved VAPT methodology?"*. Relegated strictly to a secondary, exploratory diagnostic applicable only to Track D; prohibited from being used as the primary B $\to$ D causal outcome.
- **Verification**: Section 24.2, Section 31 (Criteria 10, 33, 45), and Section 36 have been updated.

### P1-1: Primary Useful Hypothesis Yield Estimand Frozen
- **Previous Contradiction**: Section 24.1 specified a ratio-of-sums estimand ($\frac{\sum U}{\sum \overline{T}} \times N$) while Section 24.2 defined scenario-level yield ($\frac{U_c(s)}{\overline{T}_c(s)} \times N$) and based paired hypothesis testing on scenario-level differences.
- **v2.3.6 Correction**:
  1. **Primary Estimand Frozen**: Explicitly defined the primary Useful Hypothesis Yield estimand as the mean of the 20 paired scenario-level yields:
     $$\text{MeanYield}_c(N) = \frac{1}{20}\sum_{s=1}^{20} \text{Yield}_c(s; N), \quad \text{where } \text{Yield}_c(s; N) = \frac{U_c(s)}{\overline{T}_c(s)} \times N$$
  2. Defined paired within-scenario difference:
     $$\Delta \text{Yield}(s) = \text{Yield}_D(s; N) - \text{Yield}_B(s; N)$$
  3. Primary inferential statistical testing (two-sided paired Monte Carlo randomization/permutation test, $R=100,000$, seed=42) and paired BCa bootstrap 95% CI ($B=2000$) operate strictly on the 20 $\Delta \text{Yield}(s)$ values.
  4. Secondary descriptive statistic: The ratio-of-sums metric is retained strictly as secondary descriptive summary:
     $$\text{AggregateRate}_c(N) = \frac{\sum_{s=1}^{20} U_c(s)}{\sum_{s=1}^{20} \overline{T}_c(s)} \times N$$
     (labeled strictly as secondary; does NOT participate in primary inferential testing).
- **Verification**: Sections 24.1, 24.2, 31 (Criteria 10, 45), and Section 36 are unified under `MeanYield_c(N)`.

### P1-2: Zero Silent Clamping of Observed Active Review Time
- **Previous Contradiction**: The timing protocol previously specified that timing instrumentation enforces $\overline{T}_c(s) \ge 0.5$ minutes (30 seconds), which risked silently overwriting genuine observed times below 30 seconds.
- **v2.3.6 Correction**:
  1. Defined $T_{\text{raw}}(s, c, r)$ as the actual instrumented active reviewer time.
  2. Mandated the **Zero Silent Clamping Rule**: Genuine observed times below 30 seconds are NEVER overwritten or clamped.
  3. Introduced the pre-registered audit flag:
     $$T_{\text{validity\_flag}}(s, c, r) = \text{TRUE} \quad \text{when } T_{\text{raw}}(s, c, r) < 30\text{ seconds}$$
     Sub-30-second observations are flagged for forensic transparency rather than altered.
  4. Preserved raw observed times in audit logs; established positive denominator guarantee ($\overline{T}_c(s) > 0$) for mathematical display based on physical UI submission mechanics.
- **Verification**: Sections 24.2, 31 (Criteria 33, 45), and Section 36 updated.

### P1-3: Complete Offline Cryptographic Trust Root
- **Previous Contradiction**: The plan pinned trusted public-key fingerprints, but a fingerprint is an identifier, not the verification key itself.
- **v2.3.6 Correction**:
  1. Defined the complete **`Immutable Offline Trust-Root Record`**:
     - `key_id`: e.g. `"vapt-corpus-signer-202609-primary"`
     - `public_key_bytes`: Pinned raw 32-byte Ed25519 public key (hex/base64 encoded in configuration code)
     - `public_key_fingerprint`: SHA-256 hash over raw public key bytes: $\text{SHA-256}(\text{public\_key\_bytes})$
     - `algorithm`: `"Ed25519"` (RFC 8032)
     - `version_metadata`: Epoch, activation date, signing authority metadata
  2. Complete offline verification flow:
     $$\text{PinnedPublicKeyBytes} \longrightarrow \text{SHA-256} \longrightarrow \text{assert } == \text{fingerprint} \longrightarrow \text{ed25519\_verify}(\text{manifest.sig}, \text{JCS}(\text{manifest.json}), \text{public\_key\_bytes})$$
  3. Explicitly mandated: The fingerprint verifies the identity and integrity of the pinned key; the actual pinned public-key bytes perform signature verification. Zero runtime network calls, zero DNS/URL key fetching, zero dynamic trust discovery, zero LLM influence.
- **Verification**: Sections 8.3, 8.4, 31 (Criterion 38), and Section 36 updated.

### P1-4: Raw-Score Ranking Governance vs. Rounded-Score Display Separation
- **Previous Contradiction**: The specification permitted 6-decimal rounding for logged scores, creating ambiguity regarding whether rounded scores could influence ranking or tie detection.
- **v2.3.6 Correction**:
  1. Explicitly defined **`RAW_SCORE` Governance**: Full-precision floating-point raw scores govern all candidate ranking, RRF computation, relevance threshold filtering ($\theta_{\min}$), deterministic score comparisons, and reproducibility evaluations.
  2. Explicitly defined **`ROUNDED_SCORE` Boundary**: Display rounding (to 6 decimal places) is restricted strictly to human-readable audit logging, telemetry reporting, and summary manifests. Score rounding MUST NEVER participate in candidate ranking, candidate ordering, tie detection, or reproducibility decisions.
  3. Deterministic tie-breaking: If raw scores are numerically identical under IEEE 754 floating-point comparison, then and only then does the deterministic `chunk_id ASC` tie-breaker apply.
- **Verification**: Sections 11.5, 19.1, 31 (Criteria 8, 24, 44), 32 (Decision 1), and Section 36 updated.

### P1-5: Retrieval Latency Formally Classified as Non-Gating Target
- **Previous Contradiction**: Retrieval contribution to TTD $\le 100\text{ms}$ was ambiguously positioned as both an engineering bound and a potential qualification gate.
- **v2.3.6 Correction**:
  1. Formally classified retrieval TTD $\le 100\text{ms}$ as a **NON-GATING ENGINEERING TARGET / RESOURCE VALIDITY BOUND**.
  2. Confirmed that it is strictly NOT a fifth hard qualification gate.
  3. Re-affirmed that the four hard qualification gates remain:
     1. Reproducibility ($\le 10^{-6}$ drift, 100% top-$k$/rank stability)
     2. $\text{Recall@5} \ge 0.80$ on `QUALIFICATION_SELECTION_SET`
     3. $\text{MRR@5} \ge 0.60$ on `QUALIFICATION_SELECTION_SET`
     4. $\text{InjectionHit@P4\_256} \ge 0.75$ on `QUALIFICATION_SELECTION_SET`
  4. Latency serves as an engineering profiling metric, resource boundary, and second candidate tie-breaker among candidates that have passed all four hard gates. Exceeding 100 ms does not independently disqualify a candidate unless a future milestone explicitly promotes the target to a hard gate.
- **Verification**: Sections 11.2, 11.5, 31 (Criteria 8, 36), 32 (Decision 1), and Section 36 updated.

### P2-1: Three-Rater Binary Majority Rule & Elimination of Binary Ties
- **Previous Contradiction**: Protocol text previously mentioned "ties/disagreements adjudicated in consensus" for three binary raters.
- **v2.3.6 Correction**:
  1. Formalized that for $m = 3$ independent binary ratings $U(s, c, r) \in \{0, 1\}$, the sum $\sum_{r=1}^3 U \in \{0, 1, 2, 3\}$.
  2. A sum of $\ge 2$ indicates a positive majority ($2-1$ or $3-0$); a sum of $\le 1$ indicates a negative majority ($1-2$ or $0-3$). **Binary ties are mathematically impossible with three raters.**
  3. Primary scenario useful score is un-adjudicated: $U_c(s) = \mathbb{I}(\sum_{r=1}^3 U(s, c, r) \ge 2)$.
  4. Adjudicated consensus score $U_c^{\text{adj}}(s)$ is generated only under structured consensus conference and reported strictly as a secondary sensitivity analysis. Primary analysis operates strictly on un-adjudicated raw ratings.
- **Verification**: Section 24.2, Section 31 (Criteria 33, 45), and Section 36 updated.

### P2-2: Optional Ordinal-Compatible Reliability Diagnostic
- **v2.3.6 Enhancement**:
  1. Preserved primary preregistered inter-rater reliability threshold: Pre-adjudication Fleiss' $\kappa \ge 0.70$ on original independent ratings.
  2. Authorized an ordinal-compatible secondary reliability/agreement diagnostic (e.g. quadratic weighted Cohen's/Fleiss' kappa or ICC[2,1]) to be reported for descriptive completeness on the 5-point ordinal scale.
  3. Explicitly stated that the secondary diagnostic does NOT replace or alter the primary preregistered $\kappa \ge 0.70$ acceptance threshold.
- **Verification**: Section 24.2, Section 31 (Criteria 33, 45), and Section 36 updated.

### P2-3: Narrowed Audit Claim Scope
- **v2.3.6 Correction**:
  1. Replaced all broad, unqualified claims (e.g. "No unresolved methodological contradictions") with:
     > *"No unresolved artifact-level textual or structural contradictions were detected by the v2.3.6 planning audit."*
  2. Scoped all readiness claims to "100% compliance with predefined artifact-level consistency checks."
  3. Re-affirmed the strict four-tier validation taxonomy (Tier A artifact, Tier B statistical, Tier C cryptographic, Tier D empirical benchmark).
- **Verification**: Section 36.1, Section 36.2, and this audit artifact updated.

---

## 4. Cross-Section Consistency Audit Matrix

```text
┌──────────────────────────────────────────────┬──────────────────┬─────────────────────────────────────────────────────────────┐
│ Audit Topic / Dimension                      │ Verification     │ Exact Artifact Location / Verification Basis                │
├──────────────────────────────────────────────┼──────────────────┼─────────────────────────────────────────────────────────────┤
│ Document Version Consistency                 │ PASS             │ Header line 2: Document Version: 2.3.6                      │
│ Stale Version Mentions                       │ PASS (0 stale)   │ All non-changelog 2.3.5 references completely eliminated   │
│ Stale Split Names (HELD_OUT_QUALIFICATION)   │ PASS (0 stale)   │ All non-changelog references replaced by QUALIFICATION_SET │
│ Retrieval Final Generalization Partition     │ PASS             │ RETRIEVAL_FINAL_EVAL defined in Sec 11.3.1, 24.1, 27.1, 30  │
│ Canonical P4 Wire Grammar Terminology        │ PASS             │ CanonicalP4Serialization defined in Sec 13.6, 15, 16.3      │
│ Stale Illustrative Envelopes                 │ PASS (0 stale)   │ All advisory_vapt_knowledge tags completely eliminated      │
│ Capacity Oracle Parity Contract              │ PASS             │ Invariant defined in Sec 13.6; Oracle == Serializer         │
│ Symmetric Primary Human Rubric (Tracks B/D)  │ PASS             │ Evidence-Grounded Security Reasoning Rubric in Sec 24.2     │
│ Secondary Track-D VAPT Fidelity Rubric       │ PASS             │ Relegated strictly to exploratory diagnostic in Sec 24.2    │
│ Primary Useful Hypothesis Yield Estimand     │ PASS             │ MeanYield_c(N) = (1/20) * sum Yield_c(s;N) in Sec 24.1/24.2│
│ Secondary Aggregate Yield Rate Statistic     │ PASS             │ AggregateRate_c(N) labeled secondary descriptive in Sec 24.1│
│ Active Reviewer Time Measurement Rule        │ PASS             │ T_raw preserved exactly; zero silent clamping in Sec 24.2   │
│ Sub-30-Second Reviewer Time Audit Flag       │ PASS             │ T_validity_flag = TRUE for T_raw < 30s in Sec 24.2, 31      │
│ Immutable Offline Cryptographic Trust Root   │ PASS             │ Record with pinned public_key_bytes & fingerprint in Sec 8.4│
│ Raw-Score Ranking Governance                 │ PASS             │ RAW_SCORE governs ranking; display rounding only in Sec 19.1│
│ Retrieval Latency Classification (TTD 100ms) │ PASS             │ Non-gating engineering target / validity bound in Sec 11.2  │
│ Three-Rater Binary Majority Rule             │ PASS             │ Binary ties eliminated; primary score un-adjudicated (24.2) │
│ Ordinal Reliability Diagnostic               │ PASS             │ Secondary ordinal diagnostic permitted alongside Fleiss' k  │
│ Scoped Audit Claim Language                  │ PASS             │ Claims strictly scoped to artifact-level consistency        │
│ Section 31 Numbered Criteria Count           │ PASS (46 exact)  │ Numbered sequentially 1 to 46 in Section 31                 │
│ Section 36 Audit Matrix Data Row Count       │ PASS (38 exact)  │ 29 PASS-ARCH, 2 PEND-IMPL, 6 PEND-VAL, 1 BLOCKED           │
│ Section 34 Changelog Reconciliation          │ PASS             │ Comprehensive v2.3.6 changelog block added in Section 34    │
│ Source / Test Code Integrity                 │ PASS (0 changes) │ git status confirms zero modifications to src/ and tests/   │
│ Benchmark Execution Boundary                 │ PASS (0 runs)    │ Zero benchmark or empirical executions authorized           │
└──────────────────────────────────────────────┴──────────────────┴─────────────────────────────────────────────────────────────┘
```

---

## 5. Section 36 Freeze Readiness Summary

The Section 36 audit matrix in [`docs/M3_VAPT_KNOWLEDGE_RAG_PLAN.md`](docs/M3_VAPT_KNOWLEDGE_RAG_PLAN.md) has been reconciled and maintains exact categorical balance across all 38 evaluation criteria:

- **`PASS — ARCHITECTURAL` (29 criteria)**: All architectural designs, schema models, split role definitions, serialization grammars, rubric structures, mathematical estimands, offline cryptographic trust roots, raw-score ranking rules, and latency classifications are fully specified and verified mutually consistent.
- **`PENDING — IMPLEMENTATION` (2 criteria)**: Runtime implementation of `TargetEvidencePayload(B) == TargetEvidencePayload(D)` context budget parity (Phase M3.11) and executable retrieval gold schema, oracle parity test, and Merkle tree generation (Phases M3.4, M3.7, M3.10).
- **`PENDING — VALIDATION` (6 criteria)**: Empirical validation requiring runtime execution: hardware/latency resource profiling (M3.6), retriever qualification gate on `QUALIFICATION_SELECTION_SET` (M3.8), deployment-aware capacity gate (M3.8), corpus leakage automated test (M3.4), regression test pass (Criterion 32), and condition-masked human study execution (M3.19).
- **`BLOCKED` (1 criterion)**: Overall platform execution gate.

---

## 6. Final Mandatory Attestation & Milestone State

```text
========================================================================================
MILESTONE M3 STATUS:
PLANNING COMPLETE / IMPLEMENTATION BLOCKED PENDING HUMAN SIGN-OFF

No production implementation, benchmark execution, corpus build, index generation,
or human-study execution is authorized by this revision alone.
========================================================================================
```

*Audit verified and certified complete by Antigravity Planning Hardening Harness.*
