# M13 REST API Reference

## 1. Overview

The Security Assessment Workspace provides a REST API mounted directly on the existing FastAPI service. All endpoints enforce strict request validation, fail-closed access control, and JSON envelopes.

Base URL: `http://localhost:8000/api`

---

## 2. Assessment Management Endpoints

### 2.1. List Assessments
`GET /api/assessments`
- **Description**: Returns all assessment summaries for the workspace switcher.
- **Query Parameters**:
  - `limit: int` (default: 50)
  - `status_filter: Optional[str]`
- **Response**: `200 OK`
```json
{
  "status": "success",
  "count": 2,
  "assessments": [
    {
      "assessment_id": "ASM-A1B2C3D4E5F6",
      "organization": "Acme Corp",
      "assessment_name": "Q4 AppSec Audit",
      "state": "ASSESSMENT_ACTIVE",
      "authorization_status": "AUTHORIZED",
      "asset_count": 5,
      "finding_count": 2,
      "verified_finding_count": 1
    }
  ]
}
```

### 2.2. Get Workspace Shell
`GET /api/assessments/{assessment_id}/workspace`
- **Description**: Returns aggregated workspace shell state, view preferences, permissions, and warnings.
- **Response**: `200 OK`
```json
{
  "status": "success",
  "workspace": {
    "overview": { ... },
    "view_state": { "active_section": "OVERVIEW", "search_query": "" },
    "allowed_sections": ["OVERVIEW", "SCOPE_ASSETS", ...],
    "is_read_only": false,
    "warning_banners": []
  }
}
```

### 2.3. Get Assessment Overview
`GET /api/assessments/{assessment_id}/overview`
- **Description**: Returns high-level assessment metrics and milestone progress.
- **Response**: `200 OK`

### 2.4. Update View State
`POST /api/assessments/{assessment_id}/view-state`
- **Description**: Persists researcher UI navigation preferences.
- **Request Body**:
```json
{
  "active_section": "EXPERIMENTS",
  "search_query": "invoice",
  "selected_asset_id": null
}
```
- **Response**: `200 OK`

---

## 3. Scope & Artifact Endpoints

### 3.1. Validate Scope Target
`POST /api/assessments/{assessment_id}/scope/validate`
- **Description**: Tests a target against the authoritative ScopeGate in real time. NEVER mutates scope policy (`M13-03`).
- **Request Body**:
```json
{
  "target": "https://api.acme.com/v1/user"
}
```
- **Response**: `200 OK`
```json
{
  "status": "success",
  "result": {
    "assessment_id": "ASM-A1B2C3D4E5F6",
    "target": "https://api.acme.com/v1/user",
    "is_in_scope": true,
    "is_allowed": true,
    "scope_program": "Acme Pentest",
    "evaluation_reason": "Target matches authorized in-scope rule: api.acme.com"
  }
}
```

### 3.2. List Artifacts
`GET /api/assessments/{assessment_id}/artifacts`
- **Description**: Returns all artifacts registered under the assessment namespace.
- **Response**: `200 OK`

### 3.3. Register Artifact
`POST /api/assessments/{assessment_id}/artifacts`
- **Description**: Registers a new artifact with SHA-256 hash and quarantine state.
- **Request Body**:
```json
{
  "artifact_id": "ART-010203040506",
  "filename": "burp_export.har",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "byte_size": 2048,
  "artifact_type": "HAR",
  "quarantine_status": "QUARANTINED"
}
```
- **Response**: `200 OK`

---

## 4. Search & Reporting Endpoints

### 4.1. Global Workspace Search
`GET /api/workspace/search?query={query}&assessment_id={assessment_id}`
- **Description**: Real-time cross-entity search with strict namespace isolation (`M13-05`).
- **Response**: `200 OK`
```json
{
  "status": "success",
  "count": 1,
  "results": [
    {
      "entity_id": "FIND-01020304",
      "entity_type": "finding",
      "title": "BOLA on Invoices [HIGH]",
      "assessment_id": "ASM-A1B2C3D4E5F6",
      "snippet": "User Bob can retrieve User Alice invoices...",
      "url_target": "/workspace/ASM-A1B2C3D4E5F6/findings_review"
    }
  ]
}
```

### 4.2. Export Report Markdown
`POST /api/assessments/{assessment_id}/reports/export`
- **Description**: Generates and returns the authoritative assessment report in markdown format.
- **Response**: `200 OK`
```json
{
  "status": "success",
  "assessment_id": "ASM-A1B2C3D4E5F6",
  "markdown_content": "# Authorized Security Assessment Report: Acme Pentest..."
}
```
