---
document_id: DOC-WSTG-ATHZ-02
title: Testing for Broken Function Level Authorization (BFLA)
source_name: OWASP WSTG
source_version: v4.2
source_url: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Broken_Function_Level_Authorization.md
license: CC-BY-SA-4.0
author: OWASP Foundation
knowledge_type: TESTING_METHODOLOGY
category_tags:
- BFLA
- Vertical_Privilege_Escalation
- Role_Hierarchy
content_hash: 8b784fc3ae32cd4b6884d4f090381d3826d336b3ce64eefb8f0b8ae9af3d33bd
---

## Overview of Function Level Authorization
Broken Function Level Authorization (BFLA) occurs when an application fails to properly enforce vertical authorization controls on administrative or sensitive functions. Complex applications support different user roles with hierarchical or distinct privileges. When authorization checks are omitted or delegated solely to client-side interfaces, unprivileged users can execute sensitive actions.

## Step-by-Step Testing Procedure
A rigorous BFLA assessment requires systematic testing across role boundaries:

1. Map Administrative and Privileged Endpoints: Inspect administrative consoles, API schemas, Swagger specifications, and frontend JavaScript bundles for management endpoints (e.g., /api/v1/admin/users, /api/management/export).
2. Execute with Low-Privilege Credentials: Send requests to administrative endpoints using a standard, unprivileged user token or cookie.
3. Test Alternative HTTP Verbs: Attempt operations using various HTTP methods (GET, POST, PUT, DELETE, PATCH) to identify verbs that lack middleware authorization filters.
4. Inspect Header Overrides: Evaluate whether custom routing headers (e.g., X-Original-URL, X-Rewrite-URL, X-HTTP-Method-Override) circumvent gateway authorization checks.

```http
POST /api/v1/admin/users/promote HTTP/1.1
Host: target.example.com
Authorization: Bearer <Standard_User_Token>
Content-Type: application/json

{"user_id": "usr-1092", "role": "administrator"}
```

## Negative Controls and Verification
To ensure hypothesis validity, apply the following negative controls:

- Unauthenticated Control: Verify that anonymous requests receive 401 Unauthorized or 403 Forbidden. If anonymous access succeeds, the vulnerability is unauthenticated access rather than BFLA.
- Authorized Admin Control: Verify that the administrative user can successfully execute the request, confirming that the endpoint is active and functional.
- Mutation Confirmation: Verify that state changes actually persist in the system (e.g., confirming the promoted user now possesses admin permissions).

## False Positive Prevention
Be vigilant for common false positive scenarios:

- Informational Status Codes: Endpoints returning 200 OK with message bodies indicating access denied or insufficient permissions must not be classified as vulnerable.
- Staged or Non-Operational Endpoints: Legacy or prototype routes that parse JSON payloads but do not execute any underlying business logic are not exploitable BFLA.
