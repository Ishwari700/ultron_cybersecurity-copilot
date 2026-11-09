# Post-Hoc Benchmark Baseline Attestation

**Attestation Statement**: Post-hoc benchmark baseline established after M2 Phases 0–10.

---

## 1. Provenance and Historical Distinction

- **Historical Freeze Status**: The original M1.5 frozen artifact was **unrecoverable / never historically created**.
- **Recovery Audit**: An exhaustive recovery audit across the working tree, local Git history, deleted objects, and stashes confirmed no original freeze artifact was ever created or committed.
- **New Baseline Status**: This operation creates a **NEW post-hoc benchmark baseline** established after M2 Phases 0–10 engineering was completed.
- **Canonical Filename Justification**: The canonical path `data/benchmarks/m1_5_frozen_manifest.json` is used strictly because the frozen M2 specification requires this exact file location.
- **Holdout Integrity Notice**: The hidden evaluation split **cannot be claimed as a previously sealed holdout** established before M2 engineering.
- **Non-Retroactivity**: This baseline **must not be described as historical pre-M2 freeze evidence**.

---

## 2. Baseline Identity

| Property | Value |
| :--- | :--- |
| **Manifest Path** | `data/benchmarks/m1_5_frozen_manifest.json` |
| **Manifest Byte Size** | `30,826` bytes |
| **Manifest SHA-256** | `b2b85a672124acf21066a257d8c7f5093000368b224ee013c02574c96a0ae707` |
| **Companion Checksum Path** | `data/benchmarks/m1_5_frozen_manifest.json.sha256` |
| **Checksum Contents** | `b2b85a672124acf21066a257d8c7f5093000368b224ee013c02574c96a0ae707` |
| **Checksum Verification** | **PASS / EXACT MATCH** (verified from disk byte stream) |
| **Source File** | `src/eval/scenarios.py` |
| **Source Function** | `get_benchmark_manifest()` |
| **Source Git Blob SHA** | `e6f1289efa0a3b391e19f48ba3c017241f5825ac` |
| **Source Base Commit SHA** | `6a2eb983baa78be577c0d57d6a82034c4f7e5e43` |

---

## 3. Scenario Composition

| Dimension | Specification | Actual Count | Status |
| :--- | :--- | :--- | :--- |
| **Total Scenarios** | 84 | 84 | **MATCH** |
| **Application Families** | 6 families (14 each) | `saas_billing` (14), `ecommerce_orders` (14), `identity_provider` (14), `document_collaboration` (14), `healthcare_portal` (14), `iot_fleet_mgmt` (14) | **MATCH** |
| **Splits** | Dev: 28, Val: 28, Eval: 28 | Development (28), Validation (28), Evaluation (28) | **MATCH** |
| **Vulnerable Scenarios** | 36 | 36 | **MATCH** |
| **Patched Counterparts** | 36 | 36 | **MATCH** |
| **Negative Controls** | 12 | 12 | **MATCH** |
| **Scenario ID Uniqueness** | 84 unique IDs | 84 unique IDs, 0 collisions | **MATCH** |

---

## 4. Five-Part Cryptographic Stamp

Per Section 2.5 of `docs/M1_5_M2_PLAN.md`:

1. **Dataset Hash**:
   `SHA256(data/benchmarks/m1_5_frozen_manifest.json)` = `b2b85a672124acf21066a257d8c7f5093000368b224ee013c02574c96a0ae707`
2. **Config Hash**:
   `SHA256(config/default_config.yaml + scope.yaml)` = `1840ab25764e366bff218858aba6331c201bb860018bccdb6c67b2b9026298c7`
   - `config/default_config.yaml` SHA-256: `e5fcc19418f51733ffc3818cff7981e307df179f165c63310d6694d7c8a99366`
   - `scope.yaml` SHA-256: `e75b56056fb0ac31fc8a7e6e24c5bdf5676b83007d14686daa8362aceb6aa020`
3. **Model Digests**:
   - `qwen2.5-coder:3b`: `f72c60cabf6237b07f6e632b2c48d533cef25eda2efbd34bed21c5e9c01e6225`
   - `qwen2.5-coder:7b`: `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`
4. **Git Establishment Commit SHA**:
   `a005c5c11ab1a4c93ef9bd7167091b868f3b4f1d` (`m1.5 establish post-hoc benchmark baseline`)
5. **StructuralDiffEngine Version / Content Hash**:
   - Version: `v2.0.0` (Schema `2.0.0`)
   - SHA-256: `2e02c8c6cd02c23c5b48650a7a80c42f42fb6334b832c159736ab2cee1bff96b`
   - Path: `src/evidence/structural_diff.py`

---

## 5. Integrity Test Verification

- **Pre-Export Isolation Tests (`tests/unit/test_evaluation_isolation.py`)**: 5 passed in 0.28s (100% pass, 0 skips)
- **Pre-Export Real Ablation Tests (`tests/unit/test_real_ablation_integrity.py`)**: 8 passed in 0.26s (100% pass, 0 skips)
- **Post-Export Isolation Tests (`tests/unit/test_evaluation_isolation.py`)**: 5 passed in 0.27s (100% pass, 0 skips)
- **Post-Export Real Ablation Tests (`tests/unit/test_real_ablation_integrity.py`)**: 8 passed in 0.26s (100% pass, 0 skips)
- **Deterministic Double-Export Check**: PASS (byte-for-byte identical, 30,826 bytes, identical SHA-256)

---

## 6. Ground-Truth and Label Leakage Validation

- **Vulnerability Verdict Fields**: None added.
- **Expected Track Winners**: None added.
- **Scorer-Only Labels**: None added.
- **Hidden Labels / Ground Truth**: Zero ground-truth leakage into manifest records (`ground_truth_vulnerable` omitted; only neutral observable attributes present).
- **Schema Conformity**: Exactly 7 required neutral fields per item: `scenario_id`, `name`, `app_family`, `split`, `vulnerable_variant`, `category_id`, `target_asset_id`.

---

## 7. Status

**NEW POST-HOC BENCHMARK BASELINE ESTABLISHED — PHASE 11 STILL REQUIRES EXPLICIT AUTHORIZATION.**
