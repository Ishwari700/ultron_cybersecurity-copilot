# Security Vault Architecture & Trust Boundary (v6 Final)

## 1. Security Overview

The **Local AI-Assisted Bug Bounty Research Platform** operates on consumer hardware under a strict zero-leakage security posture. Real-world HTTP traffic, HAR captures, and PCAP data ingested into the system inherently contain high-privilege credentials (JWTs, session cookies, Basic authentication headers, OAuth tokens, AWS API keys, and sensitive payload parameters).

Under v6 Final specifications, **raw secrets must never enter**:
1. Reasoning model prompts or context windows (`ReasoningRunner`);
2. Local dense vector embeddings or ChromaDB vector collections (`LocalVectorStore`);
3. Unified SQLite database persistent records (`evidence_items`, `assets`, `parameters`);
4. Plaintext or structured audit logs (`data/audit.log`);
5. Benchmark evaluation reports or ablation outputs (`AblationFramework`, `DeterministicScorer`).

---

## 2. Redaction Architecture & Data Flow

```
[Target Raw HTTP Traffic]
         │
         ▼
 ┌────────────────────────────────────────────────────────┐
 │ Ingestion Boundary: Adapters (Burp, Reqable, Generic)   │
 │   - URL Parsing & Path Normalization                  │
 │   - Header & Body Extraction                           │
 └───────────────────────┬────────────────────────────────┘
                         │
                         ▼
 ┌────────────────────────────────────────────────────────┐
 │ RedactionVault (src/evidence/vault.py)                 │
 │   - Regex Scanner: JWT, AWS, Basic, Bearer, Key-Value  │
 │   - Typed Placeholder Assignment: [REDACTED_TYPE_N]    │
 │   - Volatile In-Memory Mapping: Raw <-> Placeholder    │
 └───────────────────────┬────────────────────────────────┘
                         │
        ┌────────────────┴────────────────┐
        ▼                                 ▼
┌──────────────────────────────┐ ┌──────────────────────────────┐
│ Storage & Context Boundary   │ │ Human Verification Boundary  │
│ - evidence.db (SQLite)       │ │ - Dashboard Session Gate     │
│ - ChromaDB / Vector Store    │ │ - Reversible Placeholder     │
│ - audit.log (Immutable JSONL)│ │   Resolution (human-only)    │
│ - Ollama Model Prompt        │ │                              │
└──────────────────────────────┘ └──────────────────────────────┘
```

---

## 3. Stable Typed Placeholders & Correlation Fidelity

A critical vulnerability of naive secret redaction (such as stripping tokens or hashing each occurrence independently) is loss of semantic correlation: an authorization reasoning engine cannot detect Broken Object Level Authorization (BOLA) or Broken Function Level Authorization (BFLA) if it cannot determine whether Request 1 and Request 2 were issued by the **same identity** or **competing identities**.

`RedactionVault` solves this with **stable typed placeholders**:
* `[REDACTED_JWT_1]`
* `[REDACTED_JWT_2]`
* `[REDACTED_AWS_KEY_1]`
* `[REDACTED_BASIC_AUTH_1]`
* `[REDACTED_SECRET_1]`

### Guarantee:
* If User A's token `eyJ...tenantA...` appears across 50 requests, every appearance is replaced by `[REDACTED_JWT_1]`.
* If User B's token `eyJ...tenantB...` appears across 30 requests, every appearance is replaced by `[REDACTED_JWT_2]`.
* The LLM reasoning runner reliably observes:
  `GET /invoices/INV-100 Authorization: Bearer [REDACTED_JWT_1] -> 200 OK (Owner: user_a)`
  `GET /invoices/INV-100 Authorization: Bearer [REDACTED_JWT_2] -> 200 OK (Owner: user_a)`
  The model correctly infers cross-tenant violation without ever observing the cryptographic signature or sensitive payload of either token.

---

## 4. Vault Isolation & Reversibility Boundary

| Component | Access to Raw Secret? | Data Format Received |
| :--- | :--- | :--- |
| **Observation Adapters** | Yes (transient ingress only) | Raw network capture / HTTP interaction |
| **RedactionVault** | Yes (in-memory mapping only) | Bidirectional `raw <-> placeholder` map |
| **evidence.db (SQLite)** | **NO** | Sanitized `CanonicalEvidence` with placeholders |
| **LocalVectorStore / ChromaDB** | **NO** | Dense vectors computed on sanitized text |
| **ReasoningRunner (Ollama)** | **NO** | Budgeted prompt chunks with placeholders |
| **AuditLogger (audit.log)** | **NO** | Sanitized event records with payload SHA256 hashes |
| **Dashboard UI** | Optional (Human verification only) | Reconstituted for analyst verification via `reverse_text()` |

### Reversal Restrictions:
* Placeholders can ONLY be reversed in-process via `RedactionVault.reverse_placeholder()` or `RedactionVault.reverse_text()`.
* Reversal is invoked solely during active human test verification in Phase 11 / Dashboard.
* The reversal table is never written to disk or transmitted to any external API or LLM endpoint.
