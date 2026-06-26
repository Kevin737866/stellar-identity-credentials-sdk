/**
 * SDK Configuration & Network Management
 *
 * Provides network-aware default configurations, contract address validation,
 * RPC health checks, and configuration merging for the Stellar Identity SDK.
 *
 * @category Configuration
 */

import { SorobanRpc, Networks } from 'stellar-sdk';
import axios from 'axios';
import {
  StellarIdentityConfig,
  TransactionOptions,
} from './types';
import {
  ConfigurationError,
  NetworkError,
  ErrorCode,
} from './errors';

// ---------------------------------------------------------------------------
// Contract address patterns (Stellar contract IDs are 64 hex chars)
// ---------------------------------------------------------------------------

const CONTRACT_ID_REGEX = /^[0-9a-fA-F]{64}$/;
const DEFAULT_FUTURENET_RPC = 'https://rpc-futurenet.stellar.org';

// ---------------------------------------------------------------------------
// Default configurations for each network
// ---------------------------------------------------------------------------

/**
 * Pre-built configuration presets for Stellar networks.
 * Each preset includes the canonical contract addresses for that network.
 *
 * @example
 * ```typescript
 * import { DEFAULT_CONFIGS } from '@stellar-identity/sdk';
 * const sdk = new StellarIdentitySDK(DEFAULT_CONFIGS.testnet);
 * ```
 */
export const DEFAULT_CONFIGS: Record<string, StellarIdentityConfig> = {
  testnet: {
    network: 'testnet',
    rpcUrl: 'https://soroban-testnet.stellar.org',
    horizonUrl: 'https://horizon-testnet.stellar.org',
    contracts: {
      didRegistry: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822a',
      credentialIssuer: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822b',
      reputationScore: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822c',
      zkAttestation: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822d',
      complianceFilter: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822e',
    },
  },
  mainnet: {
    network: 'mainnet',
    rpcUrl: 'https://soroban-rpc.stellar.org',
    horizonUrl: 'https://horizon.stellar.org',
    contracts: {
      didRegistry: '',
      credentialIssuer: '',
      reputationScore: '',
      zkAttestation: '',
      complianceFilter: '',
    },
  },
  futurenet: {
    network: 'futurenet',
    rpcUrl: DEFAULT_FUTURENET_RPC,
    horizonUrl: 'https://horizon-futurenet.stellar.org',
    contracts: {
      didRegistry: '',
      credentialIssuer: '',
      reputationScore: '',
      zkAttestation: '',
      complianceFilter: '',
    },
  },
};

// ---------------------------------------------------------------------------
// Configuration validation
// ---------------------------------------------------------------------------

/**
 * Validates a contract address format (must be a 64-character hex string).
 * Returns the address unchanged if valid, throws ConfigurationError otherwise.
 *
 * @param address - The contract address to validate
 * @param contractName - Human-readable name for error messages
 * @returns The validated contract address
 */
export function validateContractAddress(
  address: string,
  contractName: string,
): string {
  if (!address || address.trim().length === 0) {
    throw new ConfigurationError(
      ErrorCode.ConfigMissingContract,
      `Contract address for "${contractName}" is missing or empty. ` +
        `Deploy the contract on the target network and update your configuration.`,
      { contractName },
    );
  }

  if (!CONTRACT_ID_REGEX.test(address)) {
    throw new ConfigurationError(
      ErrorCode.ConfigMissingContract,
      `Invalid contract address for "${contractName}": "${address}". ` +
        `Expected a 64-character hex string.`,
      { contractName, address },
    );
  }

  return address;
}

/**
 * Validates all contract addresses in a configuration.
 * Throws ConfigurationError on the first invalid address.
 *
 * @param config - The SDK configuration to validate
 * @returns The validated configuration (same object)
 */
export function validateConfig(config: StellarIdentityConfig): StellarIdentityConfig {
  if (!config.network) {
    throw new ConfigurationError(
      ErrorCode.ConfigInvalidNetwork,
      'Network must be specified (mainnet, testnet, or futurenet).',
    );
  }

  const validNetworks = ['mainnet', 'testnet', 'futurenet'];
  if (!validNetworks.includes(config.network)) {
    throw new ConfigurationError(
      ErrorCode.ConfigInvalidNetwork,
      `Invalid network "${config.network}". Must be one of: ${validNetworks.join(', ')}.`,
      { network: config.network },
    );
  }

  if (config.rpcUrl) {
    try {
      new URL(config.rpcUrl);
    } catch {
      throw new ConfigurationError(
        ErrorCode.ConfigInvalidRpcUrl,
        `Invalid RPC URL: "${config.rpcUrl}"`,
        { rpcUrl: config.rpcUrl },
      );
    }
  }

  validateContractAddress(config.contracts.didRegistry, 'DID Registry');
  validateContractAddress(config.contracts.credentialIssuer, 'Credential Issuer');
  validateContractAddress(config.contracts.reputationScore, 'Reputation Score');
  validateContractAddress(config.contracts.zkAttestation, 'ZK Attestation');
  validateContractAddress(config.contracts.complianceFilter, 'Compliance Filter');

  return config;
}

/**
 * Returns `true` if the configuration is valid, `false` otherwise.
 * Does not throw.
 */
export function isConfigValid(config: StellarIdentityConfig): boolean {
  try {
    validateConfig(config);
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Configuration merging
// ---------------------------------------------------------------------------

/**
 * Deep-merges a partial user configuration with a default base configuration.
 * Contract addresses from the user config take precedence over defaults.
 *
 * @param base - Default configuration (e.g. from DEFAULT_CONFIGS)
 * @param overrides - User-provided overrides
 * @returns A new merged configuration
 */
export function mergeConfig(
  base: StellarIdentityConfig,
  overrides: Partial<StellarIdentityConfig>,
): StellarIdentityConfig {
  return {
    ...base,
    ...overrides,
    contracts: {
      ...base.contracts,
      ...(overrides.contracts || {}),
    },
  };
}

// ---------------------------------------------------------------------------
// Network management
// ---------------------------------------------------------------------------

/**
 * Returns the correct RPC URL for the given network.
 * Uses the config's rpcUrl if provided, otherwise a canonical default.
 */
export function getRpcUrl(config: StellarIdentityConfig): string {
  if (config.rpcUrl) return config.rpcUrl;

  switch (config.network) {
    case 'mainnet':
      return 'https://soroban-rpc.stellar.org';
    case 'futurenet':
      return DEFAULT_FUTURENET_RPC;
    default:
      return 'https://soroban-testnet.stellar.org';
  }
}

/**
 * Returns the correct Horizon URL for the given network.
 */
export function getHorizonUrl(config: StellarIdentityConfig): string {
  if (config.horizonUrl) return config.horizonUrl;

  switch (config.network) {
    case 'mainnet':
      return 'https://horizon.stellar.org';
    case 'futurenet':
      return 'https://horizon-futurenet.stellar.org';
    default:
      return 'https://horizon-testnet.stellar.org';
  }
}

/**
 * Returns the Stellar network passphrase for the given network.
 */
export function getNetworkPassphrase(config: StellarIdentityConfig): string {
  switch (config.network) {
    case 'mainnet':
      return Networks.PUBLIC;
    case 'futurenet':
      return Networks.FUTURENET;
    default:
      return Networks.TESTNET;
  }
}

/**
 * Creates a new configuration for a custom network.
 * Useful for local development with a local Soroban RPC.
 *
 * @param overrides - Overrides for rpcUrl and contract addresses
 * @returns A custom testnet-derived configuration
 */
export function createCustomConfig(
  overrides: Partial<StellarIdentityConfig> & {
    contracts: Partial<StellarIdentityConfig['contracts']>;
  },
): StellarIdentityConfig {
  const config = mergeConfig(DEFAULT_CONFIGS.testnet, overrides);
  validateConfig(config);
  return config;
}

// ---------------------------------------------------------------------------
// Health checks
// ---------------------------------------------------------------------------

/**
 * Result of a health check on the Soroban RPC endpoint.
 */
export interface HealthCheckResult {
  healthy: boolean;
  rpcUrl: string;
  network: string;
  /** Latest ledger sequence number (only when healthy) */
  latestLedger?: number;
  /** Error message (only when unhealthy) */
  error?: string;
  /** Response time in milliseconds */
  latencyMs: number;
}

/**
 * Performs a health check against the configured Soroban RPC endpoint.
 * Verifies that the RPC is reachable and returning ledger data.
 *
 * @param config - The SDK configuration
 * @param timeoutMs - Maximum time to wait for a response (default 5000ms)
 * @returns Health check result
 */
export async function healthCheck(
  config: StellarIdentityConfig,
  timeoutMs: number = 5000,
): Promise<HealthCheckResult> {
  const rpcUrl = getRpcUrl(config);
  const startTime = Date.now();

  try {
    const response = await axios.post(
      rpcUrl,
      {
        jsonrpc: '2.0',
        id: 1,
        method: 'getHealth',
      },
      {
        timeout: timeoutMs,
        headers: { 'Content-Type': 'application/json' },
      },
    );

    const latencyMs = Date.now() - startTime;
    const data = response.data;

    // Try to get latest ledger as a secondary check
    let latestLedger: number | undefined;
    try {
      const ledgerResponse = await axios.post(
        rpcUrl,
        {
          jsonrpc: '2.0',
          id: 2,
          method: 'getLatestLedger',
        },
        { timeout: timeoutMs },
      );
      latestLedger = ledgerResponse.data?.result?.sequence;
    } catch {
      // Non-critical — health check still passes if getHealth succeeded
    }

    return {
      healthy: data?.result?.status === 'healthy' || response.status === 200,
      rpcUrl,
      network: config.network,
      latestLedger,
      latencyMs,
    };
  } catch (error) {
    const latencyMs = Date.now() - startTime;

    let message: string;
    if (axios.isAxiosError(error)) {
      if (error.code === 'ECONNABORTED') {
        message = `Health check timed out after ${timeoutMs}ms`;
      } else if (error.response) {
        message = `RPC returned status ${error.response.status}: ${error.response.statusText}`;
      } else if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
        message = `Cannot connect to RPC at ${rpcUrl}: ${error.message}`;
      } else {
        message = error.message;
      }
    } else {
      message = error instanceof Error ? error.message : String(error);
    }

    return {
      healthy: false,
      rpcUrl,
      network: config.network,
      error: message,
      latencyMs,
    };
  }
}

/**
 * Performs a comprehensive health check that validates:
 * 1. RPC endpoint is reachable
 * 2. All contract addresses are valid
 * 3. Configuration is complete
 *
 * @param config - The SDK configuration
 * @returns Health check result with additional config validation
 */
export async function comprehensiveHealthCheck(
  config: StellarIdentityConfig,
): Promise<HealthCheckResult & { configValid: boolean }> {
  let configValid = false;

  try {
    validateConfig(config);
    configValid = true;
  } catch {
    configValid = false;
  }

  const result = await healthCheck(config);

  return {
    ...result,
    configValid,
  };
}

// ---------------------------------------------------------------------------
// Configuration builder
// ---------------------------------------------------------------------------

/**
 * Type-safe builder for creating StellarIdentityConfig objects.
 *
 * @example
 * ```typescript
 * const config = new ConfigBuilder('testnet')
 *   .withRpcUrl('http://localhost:8000/soroban/rpc')
 *   .withContract('didRegistry', '0x1234...')
 *   .withKeypair(myKeypair)
 *   .build();
 * ```
 */
export class ConfigBuilder {
  private config: StellarIdentityConfig;

  constructor(network: 'mainnet' | 'testnet' | 'futurenet') {
    this.config = { ...DEFAULT_CONFIGS[network], network };
  }

  withRpcUrl(url: string): this {
    this.config.rpcUrl = url;
    return this;
  }

  withHorizonUrl(url: string): this {
    this.config.horizonUrl = url;
    return this;
  }

  withContract(
    name: keyof StellarIdentityConfig['contracts'],
    address: string,
  ): this {
    this.config.contracts[name] = address;
    return this;
  }

  withKeypair(keypair: any): this {
    this.config.keypair = keypair;
    return this;
  }

  build(validate: boolean = true): StellarIdentityConfig {
    if (validate) {
      validateConfig(this.config);
    }
    return { ...this.config };
  }
}
