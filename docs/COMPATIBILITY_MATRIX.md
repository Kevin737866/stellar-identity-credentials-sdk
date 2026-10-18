# SDK ↔ Contract Compatibility Matrix

> Created for Issue #522. This matrix is authoritative for which SDK
> versions work with which contract versions on which network protocol
> versions. The release checklist (below) requires updating this table for
> every release that changes a contract interface, storage layout, event
> schema or the SDK's supported range.

## Supported combinations

| SDK version | Contract version | Network protocol | Status |
| --- | --- | --- | --- |
| 0.1.0 (unreleased, master) | 1.0.x | Stellar protocol 22 (testnet, futurenet, mainnet presets) | Development — contract version pinned via `SUPPORTED_CONTRACT_VERSION` |

Notes:

- Contract versions are the on-chain `SemanticVersion` reported by each
  contract's `get_version` (`src/contract_version.rs`, current build
  constants: major 1, minor 0, patch 0).
- The SDK's supported range is declared in code as
  `SUPPORTED_CONTRACT_VERSION` (`sdk/src/compatibility.ts`) and must match
  the newest contract version the SDK was tested against.
- Network protocol versions come from `NETWORK_PRESETS`
  (`sdk/src/networks.ts`).

## Client-side enforcement

The SDK ships `checkContractCompatibility(contractVersion)`
(`sdk/src/compatibility.ts`), which implements this policy:

| Condition | Outcome | SDK behaviour |
| --- | --- | --- |
| Same major, same minor as `SUPPORTED_CONTRACT_VERSION` | `compatible` | Proceed |
| Same major, **newer** minor than SDK was tested against | `warning` | Proceed with a console warning (`provider_too_new`) |
| Same major, **older** minor than SDK requires | `incompatible` | Throw an actionable error (`provider_too_old`) |
| Different major | `incompatible` | Throw an actionable error (`major_mismatch`) |
| Contract reports no/malformed version | `incompatible` | Throw (`uninitialized`) — never guess |

### Usage

```typescript
import { checkContractCompatibility } from '@stellar-identity/sdk';

// contractVersion: the value returned by the deployed contract's get_version
const report = checkContractCompatibility(contractVersion);

if (report.outcome === 'incompatible') {
  throw new Error(report.detail);
}
if (report.outcome === 'warning') {
  console.warn(report.detail);
}
```

Run this check on SDK construction (or before the first contract call) so a
client pointed at a contract of unknown vintage fails fast with an
actionable message instead of silently misbehaving.

## Deprecation policy for contract interfaces

1. **Minor** contract releases may add functions and events. The SDK
   ignores unknown functions; older SDKs keep working (hence the
   `warning`-only outcome for newer minors).
2. **Major** contract releases may change function signatures, storage
   layouts and event schemas. Older SDKs must fail with `major_mismatch`
   rather than mis-decode.
3. A contract interface is deprecated for at least one minor release
   (with a changelog entry) before it may be removed in a major release.
4. Event schema changes follow the same rule: additive fields are minor;
   renamed or removed fields are major.

## Release checklist (compatibility)

Every release must:

- [ ] Update `SUPPORTED_CONTRACT_VERSION` in `sdk/src/compatibility.ts` if
      the contract interface changed.
- [ ] Add a row to the matrix above mapping the new SDK version to its
      tested contract version and network protocol version.
- [ ] Run the compatibility tests (`sdk/src/__tests__/compatibility.test.ts`)
      covering matching, older-compatible and incompatible combinations.
- [ ] Verify matrix entries against an actual deployment (testnet at
      minimum) before tagging.
