---
document_id: DOC-WSTG-ATHZ-04
title: Testing for Insecure Direct Object References (IDOR)
source_name: OWASP WSTG
source_version: v4.2
source_url: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References.md
license: CC-BY-SA-4.0
author: OWASP Foundation
knowledge_type: TESTING_METHODOLOGY
category_tags:
- IDOR
- Authorization
- Horizontal_Privilege_Escalation
content_hash: 800a3493f6977624cbe8158450b58d0a3e2b46c264b9c207336fdd1bd4b7fd11
---

## Summary and Scope
Insecure Direct Object References (IDOR) occur when an application provides direct access to objects based on user-supplied input. As a result of this vulnerability, attackers can bypass authorization and access resources in the system directly, such as database records or files belonging to other users.

Testing for IDOR focuses on identifying instances where an application accepts an identifier from the client and retrieves the corresponding record without verifying that the authenticated user possesses authorization to view or modify that object.

## Test Methodology and Procedure
To test for IDOR vulnerabilities, researchers must follow a structured, multi-identity verification workflow:

1. Identify All Direct Object References: Inspect HTTP request parameters, path segments, and JSON payloads for object identifiers such as account numbers, order IDs, invoice keys, or customer UUIDs.
2. Establish Multiple Test Accounts: Provision at least two distinct user accounts within the same organization or role level (User A and User B) to test horizontal authorization boundaries.
3. Perform Cross-Identity Access Substitution: Using User B's active session credentials, submit requests containing User A's object identifiers.
4. Observe Server Response: Compare status codes, response bodies, and state mutations to determine whether access was granted, denied, or silently ignored.

```http
GET /api/v1/invoices/10482 HTTP/1.1
Host: target.example.com
Authorization: Bearer <User_B_Session_Token>
```

## Negative Controls and Boundary Verification
Validating an IDOR finding requires strict adherence to negative controls:

1. Unauthenticated Baseline: Submit the exact object request without authentication headers. If the response succeeds with identical data, the resource is publicly accessible and not an IDOR vulnerability.
2. Non-Existent Object Probe: Request a non-existent identifier (e.g., 999999999). If the application returns identical 200 OK responses with empty bodies or static templates, the endpoint may be an idempotent dummy handler rather than an authorized data accessor.
3. Sibling Role Baseline: Confirm that the user role itself is expected to have access before asserting horizontal object boundary violations.

## False Positive Guidance and Traps
Researchers must account for common false positive traps during IDOR evaluation:

- Public Data Exposure: Resources that are deliberately public, such as product catalogs, public user profiles, or documentation links, often use numeric IDs but do not represent authorization failures.
- Idempotent Read Handlers: Endpoints that return 200 OK with empty collections or default settings regardless of the requested identifier do not prove unauthorized data leakage.
- Synthetic Sandbox Environments: Multi-tenant mocks that simulate isolated tenant stores but serve shared mock fixtures must be confirmed against real database mutations.
