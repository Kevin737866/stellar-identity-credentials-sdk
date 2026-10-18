/**
 * SDK ↔ Contract version compatibility (Issue #522).
 *
 * Enforces the compatibility matrix published in
 * `docs/COMPATIBILITY_MATRIX.md`. The SDK declares the contract version
 * range it supports; `checkContractCompatibility` compares that range
 * against the semantic version reported by a deployed contract
 * (`get_version`).
 *
 * Policy:
 * - same major, contract minor <= SDK-supported minor → compatible
 * - same major, contract newer than the SDK's supported range → warning
 * - different major (or uninitialized contract version) → incompatible
 *
 * @category Configuration
 */

/** The contract interface version this SDK build supports. */
export const SUPPORTED_CONTRACT_VERSION = Object.freeze({
  major: 1,
  minor: 0,
  patch: 0,
});

/** Semantic version as reported by the contracts' `get_version`. */
export interface SemanticVersion {
  major: number;
  minor: number;
  patch: number;
}

export type CompatibilityOutcome = 'compatible' | 'warning' | 'incompatible';

export interface CompatibilityResult {
  outcome: CompatibilityOutcome;
  /** Machine-readable reason mirroring the contract's CompatibilityReport. */
  reason: 'compatible' | 'provider_too_new' | 'provider_too_old' | 'major_mismatch' | 'uninitialized';
  /** Human-readable elaboration of `reason`. */
  detail: string;
  sdkSupported: SemanticVersion;
  contract: SemanticVersion | null;
}

function isSemanticVersion(value: unknown): value is SemanticVersion {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.major === 'number' &&
    typeof v.minor === 'number' &&
    typeof v.patch === 'number' &&
    Number.isInteger(v.major) &&
    Number.isInteger(v.minor) &&
    Number.isInteger(v.patch)
  );
}

function format(v: SemanticVersion): string {
  return `${v.major}.${v.minor}.${v.patch}`;
}

/**
 * Compare a deployed contract's version against the SDK's supported range.
 *
 * @param contractVersion - Value returned by the contract's `get_version`,
 *   or `null`/invalid when the contract does not report a version.
 * @returns A {@link CompatibilityResult} describing the outcome.
 *
 * @example
 * ```typescript
 * const report = checkContractCompatibility(await readContractVersion());
 * if (report.outcome === 'incompatible') {
 *   throw new Error(report.detail);
 * }
 * if (report.outcome === 'warning') {
 *   console.warn(report.detail);
 * }
 * ```
 */
export function checkContractCompatibility(
  contractVersion: unknown,
): CompatibilityResult {
  const sdkSupported = SUPPORTED_CONTRACT_VERSION;

  if (!isSemanticVersion(contractVersion)) {
    return {
      outcome: 'incompatible',
      reason: 'uninitialized',
      detail:
        'Contract did not report a semantic version (get_version missing or malformed). ' +
        'Refusing to proceed against a contract of unknown vintage.',
      sdkSupported,
      contract: null,
    };
  }

  if (contractVersion.major !== sdkSupported.major) {
    return {
      outcome: 'incompatible',
      reason: 'major_mismatch',
      detail:
        `Contract version ${format(contractVersion)} is not compatible with this SDK ` +
        `(supports contract major ${sdkSupported.major}.x). Upgrade the SDK or connect ` +
        'to a matching contract deployment.',
      sdkSupported,
      contract: contractVersion,
    };
  }

  if (contractVersion.minor > sdkSupported.minor) {
    return {
      outcome: 'warning',
      reason: 'provider_too_new',
      detail:
        `Contract version ${format(contractVersion)} is newer than the newest contract ` +
        `version this SDK was tested against (${format(sdkSupported)}). ` +
        'Known features will work, but new contract behaviour is not covered by this SDK.',
      sdkSupported,
      contract: contractVersion,
    };
  }

  if (contractVersion.minor < sdkSupported.minor) {
    return {
      outcome: 'incompatible',
      reason: 'provider_too_old',
      detail:
        `Contract version ${format(contractVersion)} is older than the minimum ` +
        `contract version this SDK requires (${format(sdkSupported)}). ` +
        'Upgrade the deployed contract.',
      sdkSupported,
      contract: contractVersion,
    };
  }

  return {
    outcome: 'compatible',
    reason: 'compatible',
    detail: `Contract version ${format(contractVersion)} matches SDK support range.`,
    sdkSupported,
    contract: contractVersion,
  };
}
