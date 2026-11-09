# Milestone M2 Track Labeling Discrepancy & Authoritative Resolution

**Date:** September 18, 2026  
**Status:** RESOLVED (Phase 7 Canonical Convention Adopted)

---

## 1. Specification Contradiction Identified

In `docs/M1_5_M2_PLAN.md`, an internal naming contradiction exists between Section 15.1 and Sections 10.2 / 10.3:

### Section 15.1 (Authoritative Benchmark Scope)
```text
- Track A (7B Baseline): Direct execution using qwen2.5-coder:7b with the full V6 reasoning pipeline.
- Track B (3B Baseline): Direct execution using qwen2.5-coder:3b with the V6 reasoning pipeline.
- Track C (3B -> 7B Cascade): Cascade Router with EvidencePreservationGate and dual-channel handoff.
```

### Sections 10.2 and 10.3 (ReasoningContextBuilder Code Signature & Provenance)
```python
cascade_mode: str = "TRACK_B_CASCADE"
# Docs: ("TRACK_A_7B_BASELINE", "TRACK_B_CASCADE", "TRACK_C_3B_BASELINE")
```

---

## 2. Phase 7 Implementation Inspection

Inspection of the committed Phase 7 implementation ([`src/engine/context_builder.py`](src/engine/context_builder.py), lines 22–38) confirms:

```python
# Canonical Track Identifiers per Section 15.1 and Pre-Execution Addendum
TRACK_A_7B_BASELINE = "TRACK_A_7B_BASELINE"
TRACK_B_3B_BASELINE = "TRACK_B_3B_BASELINE"
TRACK_C_CASCADE = "TRACK_C_CASCADE"

# Internal normalization for legacy literals in Section 10 examples
_LEGACY_TRACK_MAP = {
    "TRACK_B_CASCADE": TRACK_C_CASCADE,
    "TRACK_C_3B_BASELINE": TRACK_B_3B_BASELINE,
}


def normalize_track_identifier(mode: str) -> str:
    """Normalize any track identifier to canonical Section 15.1 semantics."""
    if mode in _LEGACY_TRACK_MAP:
        return _LEGACY_TRACK_MAP[mode]
    return mode
```

---

## 3. Resolution Decision

1. **Adopted Canonical Track Identifiers**:
   - `TRACK_A_7B_BASELINE`: Direct 7B execution baseline (`"TRACK_A_7B_BASELINE"`).
   - `TRACK_B_3B_BASELINE`: Direct 3B execution baseline (`"TRACK_B_3B_BASELINE"`).
   - `TRACK_C_CASCADE`: 3B $\to$ Gate $\to$ Router $\to$ 7B cascade (`"TRACK_C_CASCADE"`).
2. **Phase 6 Alignment**:
   - For Phase 6 live 3B triage runner in the cascade context: the runner produces 3B triage output (`RawTriageOutput`) for Channel B of `TRACK_C_CASCADE`.
   - When 3B runs as an independent reasoning baseline, it operates under `TRACK_B_3B_BASELINE`.
3. **Legacy Normalization**:
   - Legacy literal strings (`TRACK_B_CASCADE`, `TRACK_C_3B_BASELINE`) are normalized automatically via `normalize_track_identifier()`.
4. **Frozen Specification Integrity**:
   - `docs/M1_5_M2_PLAN.md` is **NOT modified**.
