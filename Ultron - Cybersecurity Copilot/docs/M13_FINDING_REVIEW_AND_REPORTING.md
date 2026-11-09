# M13 Finding Review and Reporting

## 1. Finding Verification Architecture

A core epistemic principle of the system is:
> **Zero Automated Exploit Confirmation.**
> Automated tools, heuristics, and LLMs can produce observations and testable hypotheses, but ONLY an authoritative human review workflow can establish a confirmed vulnerability finding.

### 1.1. Invariants Enforced
- **`M13-15`**: Agent recommendations cannot mark findings verified.
- **`M13-16`**: Only the authoritative human-review workflow can establish verification.
- **`M13-17`**: Finding verification cannot bypass `FindingValidator`.
- **`M13-23`**: Reports cannot silently include unverified findings as confirmed vulnerabilities.
- **`M13-24`**: Report exports strictly use existing redaction and authorization policies.

---

## 2. 13-Point Deterministic Validation Checklist

Before a candidate finding is transitioned to `HUMAN_VERIFIED`, `FindingValidator.assert_finding_valid` deterministically checks 13 mandatory criteria:

1. **Reproduction Steps**: Step-by-step instructions exist and are reproducible.
2. **Deterministic Evidence Attached**: In-scope observation IDs or experiment results linked.
3. **Business Impact Statement**: Clear technical and business impact described.
4. **Scope Confirmed**: Target asset is confirmed in-scope by ScopeGate.
5. **Non-Destructive Actions**: No state-destructive or DoS activities occurred.
6. **Data Minimization Respected**: Confidential payloads minimized/masked.
7. **Negative Control Passed**: Negative control protocol executed and verified.
8. **Safe Verification Only**: Methodology stayed within safe bounds.
9. **Epistemic Provenance Sound**: Complete lineage DAG from observation to finding.
10. **No Automated Exploitation**: Finding verified by human, zero autonomous exploits.
11. **Authorization Active**: Valid authorization window active during testing.
12. **Falsification Checked**: Hypotheses tested against falsification conditions.
13. **Human Reviewer Sign-Off**: Explicit reviewer name and written justification provided.

---

## 3. Formal Assessment Report Generation

Reports are generated dynamically by `AssessmentManager.generate_report`:
- Format: GitHub-flavored markdown.
- Structure:
  1. Executive Summary
  2. Authorization Details (with validity window and signatory)
  3. Assessment Scope (in-scope targets and exclusions)
  4. Methodology (M6 Authorized Testing Framework)
  5. Attack Surface Summary
  6. **Confirmed Findings (Human Verified Only)**
  7. **Unverified Hypotheses & Open Evidence Gaps (Quarantined with prominent disclaimer)**
  8. Out-of-Scope Observations (Quarantined)
  9. Testing Limitations & Constraints

### 3.1. Unverified Hypotheses Quarantine Notice
In the report, Section 7 features a mandatory warning block:
> [!NOTE]
> The following items represent plausible technical hypotheses or observed anomalies that have NOT been verified by a human researcher. They MUST NOT be treated as confirmed security findings.
