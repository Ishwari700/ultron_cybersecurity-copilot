# M12 Memory Governance, Lifecycle & Contradiction Handling

## 1. Governance Architecture

Security research memory must be auditable and actively governed to prevent historical mutation, silent corruption, or unvetted privilege escalation.

---

## 2. Memory Lifecycle States (`LifecycleState`)

- `CREATE`: Initial validation and structural intake.
- `ACTIVE`: Admitted to primary SQLite database and active FTS5/dense indexes.
- `ARCHIVED`: Retained for auditability but deprioritized from active candidate retrieval.
- `EXPORTED`: Sanitized, abstracted package exported for peer review.
- `DELETED`: Tombstoned and completely excised from active search indexes.

---

## 3. Human-Reviewed Promotion Workflow (`MemoryPromotionEngine`)

Research memory from `ASSESSMENT_LOCAL` or `USER_RESEARCH` can only be promoted to `SHARED_RESEARCH` or `VERIFIED_PATTERN` through an auditable workflow requiring human review:

1. **Candidate Stage**: Memory is tagged `CANDIDATE` with explicit rationale.
2. **Sanitization & Abstraction**: Target-specific credentials, private hostnames, and customer identifiers are stripped.
3. **Review Stage**: Human security lead inspects candidate rationale and abstracted reproduction patterns.
4. **Promotion Stage**: Promoted to team namespace with immutable audit log event.
5. **Rejection Safeguard**: Model-derived memories cannot approve their own promotion.

---

## 4. Contradiction & Conflict Resolution (`ConflictDetector`)

When two memories present conflicting claims (e.g., initial test suggested SSRF vulnerability, subsequent negative control proved it was benign edge routing):

1. **Detection**: Identified via semantic polarity markers, target entity collision, or stale-vs-new timestamps.
2. **Explicit Representation**: Recorded in `memory_conflicts` table (`ConflictType.DIRECT_CONTRADICTION`, `STALE_VS_NEW`, `HYPOTHESIS_VS_OBSERVATION`).
3. **Transparent Surfacing**: Rather than silently hiding or discarding one memory, both are preserved with explicit contradiction annotations so analysts can inspect the evolving hypothesis.

---

## 5. Supersession Chains (`MemoryLifecycleEngine`)

Corrections never mutate history in place:
$$\text{Memory V1} \xrightarrow{\text{superseded\_by}} \text{Memory V2} \xrightarrow{\text{superseded\_by}} \text{Memory V3}$$

- Historical snapshots are archived in `memory_versions`.
- Active search indexes index only current versions unless historical mode is requested.
