---
document_id: DOC-ASVS-V4-01
title: Access Control Verification Requirements
source_name: OWASP ASVS
source_version: v4.0.3
source_url: https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x12-V4-Access-Control.md
license: CC-BY-SA-4.0
author: OWASP Foundation
knowledge_type: SECURITY_INVARIANT
category_tags:
- Access_Control
- Security_Invariants
- ASVS
content_hash: 4ba79c83268d66d61389c054bb7941097d03e2845311aea71d1e4bae0858d9ed
---

## General Access Control Design Principles
Access control mechanisms ensure that authenticated identities can only perform actions and access data permitted by their specific roles and organizational context. The application architecture must enforce access control centrally at the server-side, adhering to the principle of least privilege and fail-safe defaults (deny by default).

## Key Verification Requirements
Applications must verify compliance with core access control invariants:

- V4.1 Centralized Enforcement: Verify that access controls are applied using a well-defined, centralized component or middleware rather than scattered ad-hoc checks.
- V4.2 Contextual Data Access: Verify that every data access request verifies record ownership or explicit multi-tenant sharing rights against the user session claims.
- V4.3 Method and Action Binding: Verify that access controls restrict specific HTTP verbs and action parameters, preventing method spoofing or verb tunneling bypasses.
- V4.4 Principle of Least Privilege: Verify that accounts operate with the minimal set of privileges required for their assigned business function.

## Verification Experiments and Invariant Testing
When evaluating application compliance with ASVS access control rules:

1. Validate Contextual Claims: Check whether changing user IDs in headers or tokens causes immediate rejection.
2. Invariant Assertion: Assert that every private endpoint requires active authentication and authorized context before retrieving resources.
3. Deny-by-Default Testing: Issue requests to unmapped routes or wildcard paths to verify that undefined routes reject requests by default.

## Negative Control Guidance
- Ensure that tests verify the presence of explicit authorization checks rather than relying on network perimeter security or IP whitelisting.
- Confirm that error responses do not leak sensitive object metadata or tenant identifiers.
