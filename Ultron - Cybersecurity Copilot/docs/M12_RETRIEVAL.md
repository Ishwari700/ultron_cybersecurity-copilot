# M12 Memory Retrieval Engine & Hybrid Ranking Architecture

## 1. Overview

The M12 Memory Retrieval Engine (`src/memory/retrieval.py` and `ranking.py`) combines lexical BM25 search via SQLite FTS5 with dense semantic vector embeddings via local CPU MiniLM using Reciprocal Rank Fusion (RRF).

---

## 2. Mandatory Pipeline Sequence

The retrieval pipeline strictly enforces the following sequence:

```
User Query
    ↓
Intent / Domain Context
    ↓
Memory Access Context (Tenant, User, Assessment ID)
    ↓
Namespace Authorization & Pre-Ranking Isolation (M12-30)
    ↓
Candidate Retrieval (SQLite FTS5 + MiniLM Cosine Similarity)
    ↓
Epistemic & Provenance Validation
    ↓
Reciprocal Rank Fusion (RRF)
    ↓
Authority, Freshness, & Confidence Scoring
    ↓
Contradiction / Conflict Annotation
    ↓
Context Budgeting Allocation
    ↓
Prompt Context Assembly ([GLOBAL KNOWLEDGE], [RESEARCH MEMORY], [TARGET EVIDENCE])
```

Isolation is **strictly enforced before candidate ranking** to prevent high similarity scores in unauthorized assessments from leaking private memory.

---

## 3. Hybrid RRF Scoring Formula

Given candidate $m$:
$$\text{RRF}(m) = \frac{1}{k + \text{rank}_{\text{fts}}(m)} + \frac{1}{k + \text{rank}_{\text{dense}}(m)} \quad (\text{with } k = 60)$$

$$\text{Effective Score}(m) = \text{RRF}(m) \times \text{Weight}_{\text{authority}}(m) \times \text{Multiplier}_{\text{freshness}}(m) \times \text{Confidence}(m)$$

### Authority Weights
- `AUTHORITATIVE_EXTERNAL`: $1.20$
- `HUMAN_VERIFIED`: $1.15$
- `CANONICAL_OBSERVATION`: $1.10$
- `CURATED_RESEARCH`: $1.05$
- `USER_PROVIDED`: $1.00$
- `MODEL_DERIVED`: $0.85$
- `UNVERIFIED`: $0.70$

### Freshness Decay Multiplier
Freshness decay is calculated dynamically based on age in days:
- $\le 14$ days: $1.00$ (CURRENT)
- $15 - 60$ days: $0.90$ (AGING)
- $61 - 180$ days: $0.75$ (STALE)
- $> 180$ days: $0.50$ (DECAYED)
- Superseded items: $0.10$ (suppressed from active search)

---

## 4. Negative Memory Retrieval

Negative controls are first-class retrieval candidates. When investigating potential vulnerabilities (such as apparent 403 authorization bypasses or timing variations), the engine retrieves relevant past negative controls to evaluate whether benign conditions (such as reverse proxy timeouts or CDN error routing) explain the observed behavior.
