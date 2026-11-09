# M13 Research Integration & Analytical Agents

## 1. Overview

The `Research` section of the workspace brings together specialized analytical agents (M7), multi-tier memory (M12), and security hypothesis synthesis (M6).

---

## 2. Specialized Analytical Agents (M7 Integration)

The workspace orchestrates specialized AI agents focused on distinct vulnerability and architecture domains:
1. **Authentication & Session Analyst**: Evaluates token lifecycles, OAuth flows, and cookie attributes.
2. **Access Control & Multi-Tenancy Analyst**: Detects BOLA (CWE-639) and BFLA (CWE-285) design anomalies.
3. **Input Validation & Injection Analyst**: Analyzes parameter handling across SQL, command, and template contexts.
4. **API & Business Logic Analyst**: Inspects state machine transitions, rate limiting, and workflow integrity.
5. **Attack Surface Mapper**: Correlates exposed routes, undocumented parameters, and technology stacks.

### 2.1. Analytical Boundaries & Safety Guarantees
- **`M13-15`**: Agent recommendations cannot mark findings verified. Recommendations remain advisory (`MODEL_REASONING`).
- **`M13-08`**: External knowledge and model reasoning cannot become target evidence automatically.
- **Single Concurrent LLM Inference**: Max concurrent agent inference is hard-capped at `1` to avoid GPU VRAM contention on the target NVIDIA RTX 3050 Laptop GPU (4 GB VRAM).
- **Zero Autonomous Target Probing**: Specialized analytical agents cannot issue network requests directly against target infrastructure.

---

## 3. Multi-Tier Memory Integration (M12 Integration)

The workspace provides seamless context access through the M12 memory engine across three distinct scopes:

### 3.1. Memory Tiers
1. **Assessment-Scoped Memory**: Research notes, anomalies, and observations specific to the active assessment.
2. **Researcher Episodic Memory**: Past procedure patterns, effective negative controls, and verification checklists.
3. **Global Security Knowledge**: Curated CWE definitions, OWASP ASVS rules, and standard invariants.

### 3.2. Isolation Invariant (`M13-26`, `M13-05`)
- When querying memory within an assessment, cross-assessment and cross-tenant records are strictly excluded.
- Memory search combines BM25 keyword matching (FTS5) and dense semantic embeddings with Reciprocal Rank Fusion (RRF).
- Deletion or supersession of a memory item immediately invalidates it from retrieval.
