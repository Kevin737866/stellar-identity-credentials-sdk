// Ambient declaration so require() compiles without @types/node installed.
// At runtime Node.js provides require natively.
/* eslint-disable no-var */
declare var require: (id: string) => any; // eslint-disable-line @typescript-eslint/no-explicit-any
/* eslint-enable no-var */

import { Keypair } from 'stellar-sdk';

// Core clients
export { DIDClient } from './didClient';
export { CredentialClient } from './credentialClient';
export { ReputationClient } from './reputationClient';
export { ZKProofsClient } from './zkProofs';

// W3C-compliant DID Resolver (did:stellar method)
export { DIDResolver } from './didResolver';
export type {
  W3CResolutionResult,
  DIDResolutionMetadata,
  DIDDocumentMetadata,
  DereferencingResult,
} from './didResolver';

// Types and interfaces
export type {
  DIDDocument,
  VerificationMethod,
  Service,
  VerifiableCredential,
  ReputationData,
  ZKProof,
  ZKCircuit,
  ComplianceRecord,
  SanctionsList,
  StellarIdentityConfig,
  CreateDIDOptions,
  IssueCredentialOptions,
  ZKProofOptions,
  ComplianceCheckOptions,
  TransactionOptions,
  StellarIdentityError,
  DIDMethod,
  DIDResolutionResult,
  CredentialVerificationResult,
  ReputationScoreResult,
  ZKVerificationResult,
  ComplianceResult
} from './types';

// Main SDK class that combines all clients
import { DIDClient } from './didClient';
import { CredentialClient } from './credentialClient';
import { ReputationClient } from './reputationClient';
import { ZKProofsClient } from './zkProofs';
import { StellarIdentityConfig } from './types';

export class StellarIdentitySDK {
  public did: DIDClient;
  public credentials: CredentialClient;
  public reputation: ReputationClient;
  public zkProofs: ZKProofsClient;

  constructor(config: StellarIdentityConfig) {
    this.did = new DIDClient(config);
    this.credentials = new CredentialClient(config);
    this.reputation = new ReputationClient(config);
    this.zkProofs = new ZKProofsClient(config);
  }

  /**
   * Initialize all identity components for a user
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

    // Initialize reputation tracking
    await this.reputation.initializeReputation(stellarAddress);

    return {
      did,
      address: stellarAddress
    };
  }

  /**
   * Get complete identity profile
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

  /**
   * Perform comprehensive compliance check
   */
  async performComplianceCheck(address: string) {
    const [reputationScore, credentials] = await Promise.all([
      this.reputation.getReputationScore(address).catch(() => 50),
      this.credentials.getSubjectCredentials(address).catch(() => [])
    ]);

    // Verify credentials
    const credentialVerifications = await this.credentials.batchVerifyCredentials(credentials);

    const validCredentials = credentialVerifications.filter(v => v.valid).length;
    const revokedCredentials = credentialVerifications.filter(v => v.revoked).length;
    const expiredCredentials = credentialVerifications.filter(v => v.expired).length;

    return {
      address,
      reputationScore,
      totalCredentials: credentials.length,
      validCredentials,
      revokedCredentials,
      expiredCredentials,
      complianceScore: this.calculateComplianceScore(reputationScore, validCredentials, credentials.length),
      recommendations: this.generateComplianceRecommendations(reputationScore, validCredentials, credentials.length)
    };
  }

  private calculateComplianceScore(reputationScore: number, validCredentials: number, totalCredentials: number): number {
    const credentialScore = totalCredentials > 0 ? (validCredentials / totalCredentials) * 50 : 0;
    return Math.min(100, reputationScore * 0.5 + credentialScore);
  }

  private generateComplianceRecommendations(reputationScore: number, validCredentials: number, totalCredentials: number): string[] {
    const recommendations: string[] = [];

    if (reputationScore < 60) {
      recommendations.push('Improve transaction success rate to increase reputation score');
    }

    if (validCredentials < totalCredentials * 0.8) {
      recommendations.push('Update or renew expired/revoked credentials');
    }

    if (totalCredentials < 3) {
      recommendations.push('Obtain additional verifiable credentials to strengthen identity');
    }

    if (recommendations.length === 0) {
      recommendations.push('Identity profile is in good standing');
    }

    return recommendations;
  }
}

// Factory function for easy SDK initialization
export function createStellarIdentitySDK(config: StellarIdentityConfig): StellarIdentitySDK {
  return new StellarIdentitySDK(config);
}

// Default configurations for different networks
export const DEFAULT_CONFIGS = {
  testnet: {
    network: 'testnet' as const,
    contracts: {
      didRegistry: 'CBZQ7J2YQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQ',
      credentialIssuer: 'CBZQ7J2YQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQ',
      reputationScore: 'CBZQ7J2YQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQ',
      zkAttestation: 'CBZQ7J2YQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQ',
      complianceFilter: 'CBZQ7J2YQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQ'
    },
    rpcUrl: 'https://horizon-testnet.stellar.org',
    horizonUrl: 'https://horizon-testnet.stellar.org'
  },
  mainnet: {
    network: 'mainnet' as const,
    contracts: {
      didRegistry: 'CBZQ7J2YQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQ',
      credentialIssuer: 'CBZQ7J2YQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQ',
      reputationScore: 'CBZQ7J2YQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQ',
      zkAttestation: 'CBZQ7J2YQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQ',
      complianceFilter: 'CBZQ7J2YQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQ'
    },
    rpcUrl: 'https://horizon.stellar.org',
    horizonUrl: 'https://horizon.stellar.org'
  }
} as const;

// Utility functions
export const UTILS = {
  /**
   * Generate a random Stellar keypair
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  generateKeypair(): any {
    // stellar-sdk is a peer dependency; loaded at runtime
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return (require('stellar-sdk') as Record<string, any>).Keypair.random();
  },

  /**
   * Validate Stellar address format
   */
  validateStellarAddress(address: string): boolean {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const stellar = require('stellar-sdk') as Record<string, any>;
      stellar.Address.fromString(address);
      return true;
    } catch {
      return false;
    }
  },

  /**
   * Convert Stellar address to DID
   */
  addressToDID(address: string): string {
    return `did:stellar:${address}`;
  },

  /**
   * Extract Stellar address from DID
   */
  didToAddress(did: string): string {
    if (!did.startsWith('did:stellar:')) {
      throw new Error('Invalid DID format');
    }
    return did.substring(11);
  },

  /**
   * Generate timestamp for credential expiration
   */
  generateExpirationTimestamp(yearsFromNow: number): number {
    return Date.now() + (yearsFromNow * 365 * 24 * 60 * 60 * 1000);
  },

  /**
   * Format timestamp for display
   */
  formatTimestamp(timestamp: number): string {
    return new Date(timestamp).toISOString();
  }
};

// Version information
export const VERSION = '0.1.0';

// Error codes
export const ERROR_CODES = {
  DID_NOT_FOUND: 1001,
  INVALID_DID_FORMAT: 1002,
  CREDENTIAL_NOT_FOUND: 2001,
  CREDENTIAL_REVOKED: 2002,
  CREDENTIAL_EXPIRED: 2003,
  INVALID_PROOF: 3001,
  PROOF_VERIFICATION_FAILED: 3002,
  INSUFFICIENT_REPUTATION: 4001,
  COMPLIANCE_CHECK_FAILED: 5001,
  ADDRESS_BLOCKED: 5002,
  TRANSACTION_FAILED: 6001,
  NETWORK_ERROR: 6002
} as const;
