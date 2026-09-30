/**
 * Multi-network configuration and validation (#212).
 *
 * The SDK's network handling was spread across ten modules, each with its own
 * `getDefaultRpcUrl()` / `getNetworkPassphrase()` switch, and `DEFAULT_CONFIGS`
 * was typed `Record<string, StellarIdentityConfig>` — so `switchNetwork` needed
 * a `!base` guard that TypeScript could not narrow. `StellarIdentityConfig`
 * had no `networkPassphrase` field at all, so a custom network was impossible
 * to express: the passphrase was always derived from the `network` union.
 *
 * This module is the single source of truth:
 *
 * - {@link NETWORK_PRESETS} — the three canonical Stellar networks, as data
 *   rather than as a switch.
 * - {@link StellarNetworkConfig} — a full, self-contained network description
 *   that a custom deployment can define without extending the `network` union.
 * - {@link detectNetwork} — probe an endpoint and report which network it is.
 * - {@link assertNetworkCompatible} — fail fast on a cross-network mistake
 *   before a transaction is signed.
 *
 * @module networks
 * @category Utilities
 */

import { NetworkError, ConfigurationError, ErrorCode } from './errors';

// ── Network model ────────────────────────────────────────────────────────────

/**
 * The three canonical Stellar networks.
 *
 * Kept as a string union so a typo is a compile error rather than a runtime
 * `undefined` — the reason `DEFAULT_CONFIGS` was previously typed loosely.
 */
export type StellarNetworkName = 'mainnet' | 'testnet' | 'futurenet';

/** Every canonical network, in descending order of production readiness. */
export const STELLAR_NETWORKS: readonly StellarNetworkName[] = [
  'mainnet',
  'testnet',
  'futurenet',
] as const;

/**
 * A fully-specified network.
 *
 * Unlike the bare `network` string on `StellarIdentityConfig`, this
 * carries its own passphrase and endpoints, so a private or custom deployment
 * is just another value of this type rather than a special case.
 */
export interface StellarNetworkConfig {
  /**
   * The network identifier.
   *
   * Canonical networks use their standard names. A custom network should use a
   * distinct identifier such as `'local'` or `'futurenet-mirror'` so it is
   * never confused with a canonical one.
   */
  name: string;
  /**
   * The network passphrase, used to sign transactions and to scope the
   * network's transaction history.
   *
   * For a custom network this is whatever the operator configured, and it
   * cannot be derived from `name` — which is exactly why it lives here.
   */
  passphrase: string;
  /** Default Soroban RPC endpoint. */
  rpcUrl: string;
  /** Default Horizon endpoint. */
  horizonUrl: string;
  /**
   * The protocol version this network speaks.
   *
   * Used to detect a protocol mismatch before a transaction is submitted, so
   * the failure is a clear error rather than an opaque simulation failure.
   */
  protocolVersion: number;
  /**
   * `true` for the three canonical networks. Custom networks are always
   * `false`, which is what makes {@link assertNetworkCompatible} able to
   * refuse a canonical-to-custom call by default.
   */
  isCanonical: boolean;
  /** Whether the network carries real value. Defaults to `false`. */
  isProduction: boolean;
}

// Official Stellar network passphrases. These are fixed by the protocol and
// must match exactly or transaction signatures will not validate.
const PASSPHRASES: Record<StellarNetworkName, string> = {
  mainnet: 'Public Global Stellar Network ; September 2015',
  testnet: 'Test SDF Network ; September 2015',
  futurenet: 'Test SDF Future Network ; October 2022',
};

/**
 * The three canonical networks, as complete configurations.
 *
 * Note that mainnet and futurenet ship with empty contract addresses: there is
 * no public deployment of the identity contracts on those networks, and
 * hard-coding placeholder hashes would produce transactions to an address
 * nobody controls. {@link validateNetworkConfig} therefore requires the caller
 * to supply them, which fails loudly at configuration time rather than at
 * submission time.
 *
 * @category Utilities
 */
export const NETWORK_PRESETS: Readonly<Record<StellarNetworkName, StellarNetworkConfig>> = {
  mainnet: {
    name: 'mainnet',
    passphrase: PASSPHRASES.mainnet,
    rpcUrl: 'https://soroban-rpc.stellar.org',
    horizonUrl: 'https://horizon.stellar.org',
    protocolVersion: 22,
    isCanonical: true,
    isProduction: true,
  },
  testnet: {
    name: 'testnet',
    passphrase: PASSPHRASES.testnet,
    rpcUrl: 'https://soroban-testnet.stellar.org',
    horizonUrl: 'https://horizon-testnet.stellar.org',
    protocolVersion: 22,
    isCanonical: true,
    isProduction: false,
  },
  futurenet: {
    name: 'futurenet',
    passphrase: PASSPHRASES.futurenet,
    rpcUrl: 'https://rpc-futurenet.stellar.org',
    horizonUrl: 'https://horizon-futurenet.stellar.org',
    protocolVersion: 22,
    isCanonical: true,
    isProduction: false,
  },
};

/**
 * Return the preset for a canonical network.
 *
 * @throws a `ConfigurationError` when `name` is not one of the three
 *   canonical networks. Use {@link createCustomNetwork | networks.createCustomNetwork} for anything else.
 */
export function getNetworkPreset(name: StellarNetworkName): StellarNetworkConfig {
  const preset = NETWORK_PRESETS[name];
  if (!preset) {
    throw new ConfigurationError(
      ErrorCode.ConfigInvalidNetwork,
      `Unknown Stellar network: "${name}". Expected one of ${STELLAR_NETWORKS.join(', ')}.`,
      { network: name, known: STELLAR_NETWORKS },
    );
  }
  return preset;
}

/** `true` when `name` is one of the three canonical networks. */
export function isCanonicalNetwork(name: string): name is StellarNetworkName {
  return (STELLAR_NETWORKS as readonly string[]).includes(name);
}

/**
 * Build a configuration for a custom or private network.
 *
 * The point of this function is that `passphrase` is required and cannot be
 * inferred. The previous design derived the passphrase from the `network`
 * string, which meant a private deployment either got testnet's passphrase —
 * and silently failed signature validation — or was simply inexpressible.
 *
 * ```ts
 * const local = createCustomNetwork({
 *   name: 'local',
 *   passphrase: 'Local Sandbox Network ; September 2015',
 *   rpcUrl: 'http://localhost:8000/soroban/rpc',
 * });
 * ```
 */
export function createCustomNetwork(options: {
  name: string;
  passphrase: string;
  rpcUrl: string;
  horizonUrl?: string;
  protocolVersion?: number;
  isProduction?: boolean;
}): StellarNetworkConfig {
  if (!options.name || options.name.trim().length === 0) {
    throw new ConfigurationError(
      ErrorCode.ConfigInvalidNetwork,
      'Custom network requires a non-empty name',
      { network: options.name },
    );
  }
  if (isCanonicalNetwork(options.name)) {
    throw new ConfigurationError(
      ErrorCode.ConfigInvalidNetwork,
      `"${options.name}" is a canonical Stellar network. Use getNetworkPreset() so the ` +
        'passphrase and endpoints come from the protocol rather than being hand-written.',
      { network: options.name },
    );
  }
  if (!options.passphrase || options.passphrase.trim().length === 0) {
    throw new ConfigurationError(
      ErrorCode.ConfigInvalidNetwork,
      `Custom network "${options.name}" requires an explicit passphrase. It cannot be ` +
        'derived from the network name, and a wrong passphrase fails signature validation.',
      { network: options.name },
    );
  }

  return {
    name: options.name,
    passphrase: options.passphrase,
    rpcUrl: options.rpcUrl,
    horizonUrl: options.horizonUrl ?? '',
    protocolVersion: options.protocolVersion ?? 22,
    isCanonical: false,
    isProduction: options.isProduction ?? false,
  };
}

// ── Validation ────────────────────────────────────────────────────────────────

/**
 * Validate a network configuration, returning a list of problems.
 *
 * Returning a list rather than throwing lets a settings screen show every
 * field at once; {@link assertNetworkValid} is the throwing wrapper.
 *
 * @category Utilities
 */
export function validateNetworkConfig(config: StellarNetworkConfig): string[] {
  const problems: string[] = [];

  if (!config.name || config.name.trim().length === 0) {
    problems.push('network name must not be empty');
  }
  if (!config.passphrase || config.passphrase.trim().length === 0) {
    problems.push(`network "${config.name}" has no passphrase`);
  }
  if (!config.rpcUrl) {
    problems.push(`network "${config.name}" has no RPC URL`);
  } else {
    try {
      const url = new URL(config.rpcUrl);
      if (url.protocol !== 'https:' && url.protocol !== 'http:') {
        problems.push(`network "${config.name}" RPC URL must be http(s), got "${url.protocol}"`);
      }
      if (url.protocol === 'http:' && !isLoopback(config.rpcUrl)) {
        // Plaintext to a remote host exposes every signed transaction, which
        // for an identity SDK means leaking the user's key-signed claims.
        problems.push(
          `network "${config.name}" uses http for a non-local RPC URL; use https to avoid ` +
            'transmitting signed transactions in plaintext',
        );
      }
    } catch {
      problems.push(`network "${config.name}" RPC URL is not a valid URL: ${config.rpcUrl}`);
    }
  }
  if (config.isCanonical && !isCanonicalNetwork(config.name)) {
    problems.push(`network "${config.name}" claims to be canonical but is not one of ${STELLAR_NETWORKS.join(', ')}`);
  }
  if (config.protocolVersion < 1) {
    problems.push(`network "${config.name}" has an invalid protocol version`);
  }

  return problems;
}

function isLoopback(url: string): boolean {
  try {
    const host = new URL(url).hostname;
    return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
  } catch {
    return false;
  }
}

/**
 * Validate a network configuration and throw on the first problem.
 *
 * @category Utilities
 */
export function assertNetworkValid(config: StellarNetworkConfig): void {
  const problems = validateNetworkConfig(config);
  if (problems.length > 0) {
    throw new ConfigurationError(
      ErrorCode.ConfigInvalidNetwork,
      `Invalid network configuration: ${problems.join('; ')}`,
      { network: config.name, problems },
    );
  }
}

/**
 * Fail when two networks are not safe to mix.
 *
 * The failure this prevents is specific and expensive: submitting a
 * transaction built for testnet to mainnet produces a `tx_bad_seq` or a
 * signature that simply never confirms, with no indication that the network
 * was the problem. Checking up front turns that into a clear error.
 *
 * @param from - The network the caller believes it is on.
 * @param to - The network the operation will actually hit.
 * @param options.allowCrossNetwork - Skip the check. Intended for tooling
 *   that genuinely spans networks (a block explorer, a migration script).
 * @category Utilities
 */
export function assertNetworkCompatible(
  from: StellarNetworkConfig,
  to: StellarNetworkConfig,
  options: { allowCrossNetwork?: boolean } = {},
): void {
  if (options.allowCrossNetwork) return;

  if (from.passphrase === to.passphrase) return;

  // Different passphrases are always a mismatch, even if the names happen to
  // match — a mirrored or forked network reuses the name but not the
  // passphrase, and that is exactly the case worth catching.
  throw new NetworkError(
    ErrorCode.NetworkTransactionFailed,
    `Cross-network operation refused: "${from.name}" (passphrase "${from.passphrase}") cannot ` +
      `be used against "${to.name}" (passphrase "${to.passphrase}"). ` +
      'A transaction built for one network will never confirm on another. ' +
      'Pass { allowCrossNetwork: true } if this is intentional.',
    { from: from.name, to: to.name, fromPassphrase: from.passphrase, toPassphrase: to.passphrase },
  );
}

// ── Auto-detection ────────────────────────────────────────────────────────────

/**
 * The outcome of a network probe.
 *
 * @category Utilities
 */
export interface NetworkDetectionResult {
  /** The matched network, or `null` when the endpoint is not recognised. */
  network: StellarNetworkConfig | null;
  /** `true` when a canonical network was matched by passphrase. */
  detected: boolean;
  /** Chain ID reported by the endpoint, when it supplied one. */
  chainId?: string;
  /** Protocol version reported by the endpoint, when it supplied one. */
  protocolVersion?: number;
  /** Why detection failed, when it did. */
  reason?: string;
}

/**
 * Ask an endpoint which network it is.
 *
 * Calls `getNetwork` and matches the returned passphrase against the three
 * canonical networks. Matching on the *passphrase* rather than the chain ID
 * or the RPC hostname is deliberate: chain IDs can be configured, and an
 * operator may run an RPC proxy on a different host, but the passphrase is
 * what transaction signing actually depends on.
 *
 * ```ts
 * const result = await detectNetwork('https://soroban-testnet.stellar.org');
 * if (!result.detected) console.warn(result.reason);
 * ```
 *
 * @category Utilities
 */
export async function detectNetwork(rpcUrl: string): Promise<NetworkDetectionResult> {
  const g = globalThis as unknown as { fetch?: typeof fetch };
  if (typeof g.fetch !== 'function') {
    return {
      network: null,
      detected: false,
      reason: 'fetch is unavailable in this runtime; pass the network explicitly instead of detecting it',
    };
  }

  let payload: unknown;
  try {
    const response = await g.fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getNetwork' }),
    });
    if (!response.ok) {
      return {
        network: null,
        detected: false,
        reason: `getNetwork returned HTTP ${response.status} ${response.statusText}`,
      };
    }
    payload = await response.json();
  } catch (err) {
    return {
      network: null,
      detected: false,
      reason: `getNetwork request failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  const record = payload as {
    result?: { passphrase?: string; protocol_version?: number };
    error?: { message?: string };
  };

  if (record?.error) {
    return { network: null, detected: false, reason: `getNetwork error: ${record.error.message ?? 'unknown'}` };
  }

  const passphrase = record?.result?.passphrase;
  const protocolVersion = record?.result?.protocol_version;

  if (!passphrase) {
    return {
      network: null,
      detected: false,
      reason: 'getNetwork response did not include a passphrase',
    };
  }

  const match = STELLAR_NETWORKS.find((name) => PASSPHRASES[name] === passphrase);
  if (!match) {
    return {
      network: null,
      detected: false,
      protocolVersion,
      reason:
        `Passphrase "${passphrase}" does not match any canonical Stellar network. ` +
        'This is a custom network — pass an explicit passphrase rather than relying on detection.',
    };
  }

  return {
    network: NETWORK_PRESETS[match],
    detected: true,
    protocolVersion,
  };
}

/**
 * Resolve a network from a name, accepting canonical names, custom
 * definitions, or a full config object.
 *
 * This is the single entry point callers should use, so that a custom network
 * flows through the same validation as a canonical one.
 *
 * @category Utilities
 */
export function resolveNetwork(
  input: StellarNetworkName | StellarNetworkConfig,
): StellarNetworkConfig {
  if (typeof input !== 'string') return input;
  if (isCanonicalNetwork(input)) return NETWORK_PRESETS[input];
  throw new ConfigurationError(
    ErrorCode.ConfigInvalidNetwork,
    `"${input}" is not a canonical Stellar network. ` +
      'Use createCustomNetwork() to define one, then pass the resulting config object.',
    { network: input, known: STELLAR_NETWORKS },
  );
}

/**
 * A human-readable label for a network, for UI and log lines.
 *
 * @category Utilities
 */
export function describeNetwork(config: StellarNetworkConfig): string {
  const kind = config.isProduction ? 'production' : config.isCanonical ? 'test' : 'custom';
  const host = config.rpcUrl ? ` (${new URL(config.rpcUrl).host})` : '';
  return `${config.name} — ${kind}${host}`;
}
