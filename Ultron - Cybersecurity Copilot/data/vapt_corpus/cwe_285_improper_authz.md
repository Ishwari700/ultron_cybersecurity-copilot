---
document_id: DOC-CWE-285
title: Improper Authorization
source_name: CWE Web Slices
source_version: v4.14
source_url: https://cwe.mitre.org/data/definitions/285.html
license: MITRE Terms (Permissive)
author: MITRE Corporation
knowledge_type: SECURITY_INVARIANT
category_tags:
- CWE-285
- Authorization
- Access_Control_Failure
content_hash: 3a3eb6eb2a9c106a1abdbee6e86dda6453318bda28671e81093de0a97aecf716
---

## Weakness Overview
The software does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action. Authorization ensures that a requested action is permissible for the authenticated actor. When authorization is missing, improperly configured, or bypassed, unauthorized actors may read sensitive data or execute privileged actions.

## Common Architecture Flaws
Improper authorization typically stems from one of the following architectural defects:

- Missing Checks on State Mutations: Read operations check permissions, but mutating operations (POST, PUT, DELETE) omit validation.
- Inconsistent Middleware Ordering: Authentication and authorization filters execute in the wrong order or are skipped on certain route prefixes.
- Client-Side Enforcement Only: The user interface hides buttons or links for unauthorized actions, but the backend API accepts requests without verification.

## Testing and Verification Methodology
1. Enumerate Endpoint Actions: Identify all actions available across standard, managerial, and administrative roles.
2. Probe Action Execution: Send requests executing actions from accounts with insufficient privileges.
3. Compare Behavior: Verify whether the system returns 403 Forbidden or allows the action to proceed.
4. Verify State Change: Inspect database or subsequent API responses to confirm whether the unauthorized action produced persistent changes.
