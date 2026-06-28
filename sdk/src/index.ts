// Ambient declaration so require() compiles without @types/node installed.
/* eslint-disable no-var */
declare var require: (id: string) => any;
/* eslint-enable no-var */

import { Keypair } from 'stellar-sdk';

// Re-export full network-aware configs from the config module
export { DEFAULT_CONFIGS } from './config';

export const UTILS = {
  generateKeypair: () => Keypair.random(),
};

export { DIDClient } from './didClient';
export { CredentialClient } from './credentialClient';
export { ReputationClient } from './reputation';
export { ZKProofsClient } from './zkProofs';
export { CacheManager, DataType } from './cacheManager';
export { compressPayload, decompressPayload, compressionRatio } from './compression';
export { EventSubscriber } from './eventSubscriber';
export { Logger, LogLevel } from './logger';
export { GDPREngine } from './gdpr';
export type { ConsentRecord, ProcessingRecord, GDPRComplianceOptions } from './gdpr';
export { DataMinimizationEngine } from './dataMinimization';
export type { 
  MinimalDisclosurePolicy, 
  BlindedAttribute, 
  SaltedHashCommitment, 
  AttributeExpiration 
} from './dataMinimization';

export { ComplianceClient } from './compliance';

export {
  validateContractAddress,
  validateConfig,
  isConfigValid,
  mergeConfig,
  getRpcUrl,
  getHorizonUrl,
  getNetworkPassphrase as resolveNetworkPassphrase,
  createCustomConfig,
  healthCheck,
  comprehensiveHealthCheck,
  ConfigBuilder,
} from './config';
export type { HealthCheckResult } from './config';
export type {
  ScreeningStatus,
  ScreeningResult,
  TransactionRisk,
  ComplianceReport,
  TravelRulePayload,
  AlertSubscription,
  ComplianceReportOptions,
  JurisdictionRule,
  RiskLevel,
  EnrichedProfile,
} from './compliance';

export { RegulatoryReportingClient } from './regulatoryReporting';
export type {
  TemplateSection,
  ReportTemplate,
  ReportField,
  ReportSection,
  RegulatoryReport,
  SARReport,
  ReportSchedule,
  TransactionReport,
  ExportSnapshot,
  PaginatedReports,
  PaginatedSARs,
  ReportStatistics,
  ExportFormat,
} from './regulatoryReporting';
export { DEFAULT_TEMPLATES } from './regulatoryReporting';

export { NetworkMonitor } from './networkMonitor';
export type {
  MonitorConfig,
  AlertChannel,
  AlertThreshold,
  AlertEvent,
  AlertSeverity,
  AlertChannelType,
  TransactionMetrics,
  ContractStateChange,
  AnomalyResult,
  MonitorHealth,
} from './networkMonitor';

export {
  // Error codes
  ErrorCode,
  // Error classes
  StellarIdentityError,
  DIDError,
  CredentialError,
  ReputationError,
  ZKProofError,
  ComplianceError,
  ConfigurationError,
  NetworkError,
  ValidationError,
  RateLimitError,
  // Mapping utilities
  mapContractError,
  mapErrorCode,
  // Type guards
  isDIDError,
  isCredentialError,
  isReputationError,
  isZKProofError,
  isComplianceError,
  isConfigurationError,
  isNetworkError,
  isValidationError,
  isRateLimitError,
  isRetryableError,
  // Convenience builders
  missingField,
  fieldTooLong,
  invalidAddress,
  invalidDID,
  // Recovery hints map
  RECOVERY_HINTS,
} from './errors';
export type { ErrorClass } from './errors';

export {
  withRetry,
  calculateDelay,
  CircuitBreaker,
  withRetryAndCircuitBreaker,
} from './retry';
export type {
  RetryOptions,
  RetryContext,
  OnRetryCallback,
  CircuitState,
  CircuitBreakerOptions,
} from './retry';

export {
  ErrorMonitor,
  ConsoleErrorReporter,
  NoOpErrorReporter,
} from './errorMonitor';
export type {
  ErrorEvent,
  ErrorStats,
  ErrorHook,
  ErrorReporter,
  ErrorMonitorOptions,
} from './errorMonitor';

export {
  WalletConnector,
  FreighterConnector,
  XBullConnector,
  AlbedoConnector,
  connectWallet,
  detectInstalledWallets,
} from './walletConnector';
export type { WalletType, WalletInfo } from './walletConnector';

export { DIDResolver } from './didResolver';
export type {
  W3CResolutionResult,
  DIDResolutionMetadata,
  DIDDocumentMetadata,
  DereferencingResult,
  DIDResolveOptions,
} from './didResolver';

export type {
  DIDDocument,
  VerificationMethod,
  Service,
  VerifiableCredential,
  ReputationData,
  ReputationFactors,
  ReputationHistoryPoint,
  ReputationBreakdown,
  ReputationComparison,
  ReputationTierProof,
  TrustEdge,
  ZKProof,
  ZKCircuit,
  ComplianceRecord,
  SanctionsList,
  StellarIdentityConfig,
  CreateDIDOptions,
  UpdateDIDOptions,
  IssueCredentialOptions,
  ZKProofOptions,
  ComplianceCheckOptions,
  TransactionOptions,
  DIDMethod,
  DIDResolutionResult,
  CredentialVerificationResult,
  ReputationScoreResult,
  ZKVerificationResult,
  ComplianceResult,
  PredicateType,
  PredicateInfo,
  SelectiveDisclosureOptions,
  SelectiveDisclosureProof,
  SelectiveDisclosureVerificationResult,
  CombinedDisclosureProof,
} from './types';

import { DIDClient } from './didClient';
import { CredentialClient } from './credentialClient';
import { ReputationClient } from './reputation';
import { ZKProofsClient } from './zkProofs';
import { CacheManager } from './cacheManager';
import { EventSubscriber } from './eventSubscriber';
import { GDPREngine } from './gdpr';
import { StellarIdentityConfig } from './types';
import {
  validateConfig,
  mergeConfig,
  healthCheck,
  comprehensiveHealthCheck,
  DEFAULT_CONFIGS,
} from './config';
import type { HealthCheckResult } from './config';

/**
 * Stellar Identity SDK - Main entry point.
 *
 * Composes all client modules (DID, Credentials, Reputation, ZK Proofs,
 * Compliance) into a single unified SDK with caching and event subscription.
 *
 * @example
 * ```typescript
 * import { StellarIdentitySDK, DEFAULT_CONFIGS } from '@stellar-identity/sdk';
 *
 * const sdk = new StellarIdentitySDK(DEFAULT_CONFIGS.testnet);
 * const did = await sdk.did.createDID(keypair, options);
 * ```
 * @category Client
 */
export class StellarIdentitySDK {
  public did: DIDClient;
  public credentials: CredentialClient;
  public reputation: ReputationClient;
  public zkProofs: ZKProofsClient;
  public cache: CacheManager;
  public events: EventSubscriber;
  private config: StellarIdentityConfig;

  constructor(config: StellarIdentityConfig, options?: { validate?: boolean }) {
    this.config = config;
    if (options?.validate !== false) {
      validateConfig(config);
    }
    this.did = new DIDClient(config);
    this.credentials = new CredentialClient(config);
    this.reputation = new ReputationClient(config);
    this.zkProofs = new ZKProofsClient(config);
    this.cache = new CacheManager();
    this.events = new EventSubscriber(config);
    this.gdpr = new GDPREngine(this.did, this.credentials);
  }

  /**
   * Get the current SDK configuration.
   */
  getConfig(): StellarIdentityConfig {
    return { ...this.config };
  }

  /**
   * Switch to a different network at runtime.
   * Re-initializes all client modules with the new network configuration.
   * @param network - The target network (mainnet, testnet, futurenet)
   * @param overrides - Optional configuration overrides
   */
  switchNetwork(
    network: 'mainnet' | 'testnet' | 'futurenet',
    overrides?: Partial<StellarIdentityConfig>,
  ): void {
    const base = DEFAULT_CONFIGS[network];
    if (!base) {
      throw new Error(`Unknown network: ${network}`);
    }

    this.config = mergeConfig(base, overrides || {});
    validateConfig(this.config);

    // Re-initialize all clients with new config
    this.did = new DIDClient(this.config);
    this.credentials = new CredentialClient(this.config);
    this.reputation = new ReputationClient(this.config);
    this.zkProofs = new ZKProofsClient(this.config);
    this.events = new EventSubscriber(this.config);
  }

  /**
   * Perform a health check against the configured RPC endpoint.
   * @returns Health check result
   */
  async checkHealth(): Promise<HealthCheckResult> {
    return healthCheck(this.config);
  }

  /**
   * Perform a comprehensive health check including config validation.
   * @returns Health check result with config validation status
   */
  async checkHealthComprehensive(): Promise<HealthCheckResult & { configValid: boolean }> {
    return comprehensiveHealthCheck(this.config);
  }

  /**
   * Initialize a complete user identity: create DID and initialize reputation.
   * @param keypair - The user's Stellar keypair
   * @param verificationMethods - Array of verification methods for the DID
   * @param services - Array of service endpoints for the DID
   * @returns Object containing the DID and Stellar address
   */
  async initializeUserIdentity(
    keypair: Keypair,
    verificationMethods: any[],
    services: any[]
  ) {
    const stellarAddress = keypair.publicKey();
    const did = await this.did.createDID(keypair, {
      verificationMethods,
      services
    });

    await this.reputation.initializeReputation(keypair);

    return {
      did,
      address: stellarAddress
    };
  }

  /**
   * Get a complete identity profile for an address.
   * Fetches DID document, reputation data, and credentials in parallel.
   * @param address - The Stellar address to query
   * @returns Identity profile with DID, reputation, and credentials
   */
  async getIdentityProfile(address: string) {
    const [didDocument, reputationData, credentials] = await Promise.all([
      this.did.resolveDID(this.did.generateDID(address)).catch(() => null),
      this.reputation.getReputationData(address).catch(() => null),
      this.credentials.getSubjectCredentials(address).catch(() => [])
    ]);

    return {
      address,
      didDocument,
      reputationData,
      credentialCount: credentials.length,
      credentials
    };
  }

  async performComplianceCheck(address: string) {
    const [reputationSnapshot, credentials] = await Promise.all([
      this.reputation.getReputationScore(address).catch(() => ({ score: 80 })),
      this.credentials.getSubjectCredentials(address).catch(() => [])
    ]);

    const credentialVerifications = await this.credentials.batchVerifyCredentials(credentials);
    const validCredentials = credentialVerifications.filter(v => v.valid).length;
    const revokedCredentials = credentialVerifications.filter(v => v.revoked).length;
    const expiredCredentials = credentialVerifications.filter(v => v.expired).length;

    return {
      address,
      reputationScore: reputationSnapshot.score,
      totalCredentials: credentials.length,
      validCredentials,
      revokedCredentials,
      expiredCredentials,
      complianceScore: this.calculateComplianceScore(reputationSnapshot.score, validCredentials, credentials.length),
      recommendations: this.generateComplianceRecommendations(reputationSnapshot.score, validCredentials, credentials.length)
    };
  }

  private calculateComplianceScore(reputationScore: number, validCredentials: number, totalCredentials: number): number {
    const credentialScore = totalCredentials > 0 ? (validCredentials / totalCredentials) * 50 : 0;
    return Math.min(100, reputationScore * 0.1 + credentialScore);
  }

  private generateComplianceRecommendations(reputationScore: number, validCredentials: number, totalCredentials: number): string[] {
    const recommendations: string[] = [];

    if (reputationScore < 550) {
      recommendations.push('Increase verified on-chain activity to move beyond the emerging trust tier.');
    }

    if (validCredentials < totalCredentials * 0.8) {
      recommendations.push('Refresh revoked or expired credentials to recover credential-weighted reputation.');
    }

    if (totalCredentials < 3) {
      recommendations.push('Add more verifiable credentials to improve diversity and lender confidence.');
    }

    if (recommendations.length === 0) {
      recommendations.push('Identity profile is in good standing.');
    }

    return recommendations;
  }
}
