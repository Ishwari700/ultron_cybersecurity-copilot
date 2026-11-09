---
document_id: DOC-CWE-639
title: Authorization Bypass Through User-Controlled Key
source_name: CWE Web Slices
source_version: v4.14
source_url: https://cwe.mitre.org/data/definitions/639.html
license: MITRE Terms (Permissive)
author: MITRE Corporation
knowledge_type: EXPERIMENT_PATTERN
category_tags:
- CWE-639
- Key_Substitution
- Authorization_Bypass
content_hash: e87b09e11543aa8d59103516f2b98a00cbb6f5935b51596ac5df06d4ca9b70d6
---

## Weakness Description
The application uses user-controllable key values to access resources, but it does not properly verify that the user is authorized to access those resources with the given key. When the key is an integer, sequential number, filename, or predictable GUID, an attacker can enumerate or guess keys belonging to other users.

## Observed Vulnerability Patterns
CWE-639 manifests in several common architectural patterns:

- REST API Path Identifiers: Routes such as /api/v1/customers/{customer_id}/orders where customer_id can be modified freely.
- Query Parameter Object Keys: Queries like ?doc_id=5819 where changing doc_id exposes confidential documents of other organizations.
- Body Payload Parameter Tampering: JSON mutation requests where the target object_id in the body differs from the session owner.

```json
{
  "action": "download_statement",
  "account_id": "ACC-99214",
  "format": "pdf"
}
```

## Experiment Design and Hypothesis Construction
When formulating an experiment to test for CWE-639:

1. State the Invariant: The system must enforce that the requested account_id belongs to the tenant identified by the session token.
2. Formulate Hypothesis: If the system returns full account records for ACC-99214 when requested by a user belonging to ACC-11002, then an authorization bypass exists.
3. Execute Test with Controls: Pair the test with a request for a non-existent account ID to establish whether the handler returns 404 Not Found or generic data.
