# M13 Scope and Asset Inventory Architecture

## 1. ScopeGate Integration & Boundaries

The ScopeGate subsystem (M1, M6) guarantees that no network action, experiment, or finding creation can target an unauthorized system.

### 1.1. Core Invariants
- **`M13-02`**: A listed asset is not automatically an authorized asset. Listing an asset in the inventory graph does NOT grant permission to target it.
- **`M13-03`**: No workspace operation can silently expand scope. Scope validation queries (`/scope/validate`) are read-only and never mutate program scope.
- **`M13-04`**: Invalid or missing authorization blocks target interactions, active experiments, and state progression.

### 1.2. Scope Validation Logic
The `UnifiedWorkspaceService.validate_scope_target` delegates directly to `ScopeGate.evaluate_extended_scope(target)`:
1. **Explicit Exclusion Check**: Target is compared against all `out_of_scope` rules. If matched, returns `is_permitted=False` (`OUT_OF_SCOPE`).
2. **In-Scope Inclusion Check**: Target is compared against all `in_scope` patterns (domain, wildcard subdomain `*.domain`, CIDR subnet, host:port, URL path, mobile package, repository). If matched, returns `is_permitted=True` (`IN_SCOPE`).
3. **Fail-Closed Default**: Targets matching neither rule return `is_permitted=False` with `UNKNOWN treated as OUT_OF_SCOPE`.

### 1.3. Interactive Target Validator in UI
In the `Scope & Assets` tab (`ScopeAssetsTab.tsx`), researchers can input any URL, domain, or IP. The validator tests the target against the authoritative `ScopeGate` in real time, displaying:
- Green `IN SCOPE (ALLOWED)` badge with matched rule.
- Red `OUT OF SCOPE (DENIED)` badge with explicit reason.
- Clear indicators preventing accidental out-of-scope probes.

---

## 2. Asset Inventory Graph

The `AssetGraph` maintains a directed acyclic graph of discovered and inventoried assets.

### 2.1. Asset Types
Supported `AssetType` classifications:
- `DOMAIN`, `SUBDOMAIN`, `IP`, `CIDR`, `PORT`, `SERVICE`, `URL`, `API`, `ENDPOINT`
- `WEB_APPLICATION`, `MOBILE_APPLICATION`, `ANDROID_APP`, `MOBILE_BACKEND`
- `BINARY`, `SOURCE_REPOSITORY`, `HOST`, `CONTAINER`, `CLOUD_RESOURCE`

### 2.2. Asset Relationships & Hierarchy
- Assets can declare `parent_asset_id` creating parent-child linkages (e.g. `DOMAIN -> SERVICE -> URL -> ENDPOINT`).
- Tags enable cross-cutting organization (e.g. `production-edge`, `core-auth`, `external-cdn`).
- Discovery provenance tracks whether an asset was discovered via `PASSIVE_TELEMETRY`, `MANUAL_ENTRY`, or `DNS_ENUMERATION`.
