export interface DIDDocument {
  id: string;
  controller: string;
  verificationMethod: VerificationMethod[];
  authentication: string[];
  service: Service[];
  created: number;
  updated: number;
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKey: string;
}

export interface Service {
  id: string;
  type: string;
  endpoint: string;
}

export interface VerifiableCredential {
  id: string;
  issuer: string;
  subject: string;
  type: string[];
  credentialData: any;
  issuanceDate: number;
  expirationDate?: number;
  revocation?: string;
  proof?: string;
}

export interface ReputationData {
  address: string;
  score: number;
  transactionCount: number;
  successfulTransactions: number;
  credentialCount: number;
  validCredentials: number;
  lastUpdated: number;
  reputationFactors: Record<string, number>;
}

export interface ZKProof {
  proofId: string;
  circuitId: string;
  publicInputs: string[];
  proofBytes: string;
  verifierAddress: string;
  createdAt: number;
  expiresAt?: number;
  metadata: Record<string, string>;
}

export interface ZKCircuit {
  circuitId: string;
  name: string;
  description: string;
  verifierKey: string;
  publicInputCount: number;
  privateInputCount: number;
  createdBy: string;
  createdAt: number;
  active: boolean;
}

export interface ComplianceRecord {
  address: string;
  riskScore: number;
  sanctionsList: string[];
  lastChecked: number;
  checkCount: number;
  status: 'cleared' | 'flagged' | 'blocked';
  metadata: Record<string, string>;
}

export interface SanctionsList {
  listId: string;
  name: string;
  source: string;
  lastUpdated: number;
  active: boolean;
  entries: string[];
}

export interface StellarIdentityConfig {
  network: 'mainnet' | 'testnet' | 'futurenet';
  contracts: {
    didRegistry: string;
    credentialIssuer: string;
    reputationScore: string;
    zkAttestation: string;
    complianceFilter: string;
  };
  rpcUrl?: string;
  horizonUrl?: string;
}

export interface CreateDIDOptions {
  verificationMethods: VerificationMethod[];
  services: Service[];
}

export interface IssueCredentialOptions {
  subject: string;
  credentialType: string[];
  credentialData: any;
  expirationDate?: number;
  proof: string;
}

export interface ZKProofOptions {
  circuitId: string;
  publicInputs: string[];
  proofBytes: string;
  expiresAt?: number;
  metadata?: Record<string, string>;
}

export interface ComplianceCheckOptions {
  address: string;
  updateRiskScore?: boolean;
}

export interface TransactionOptions {
  fee?: number;
  timeout?: number;
  memo?: string;
}

export interface StellarIdentityError extends Error {
  code: number;
  type: string;
}

export type DIDMethod = 'stellar';

export interface DIDResolutionResult {
  didDocument: DIDDocument;
  resolverMetadata?: Record<string, any>;
  documentMetadata?: Record<string, any>;
}

export interface CredentialVerificationResult {
  valid: boolean;
  revoked: boolean;
  expired: boolean;
  issuer: string;
  subject: string;
  issuanceDate: number;
  expirationDate?: number;
}

export interface ReputationScoreResult {
  score: number;
  percentile: number;
  factors: Record<string, number>;
  history: number[];
  lastUpdated: number;
}

export interface ZKVerificationResult {
  valid: boolean;
  circuitId: string;
  proofId: string;
  verifiedAt: number;
  expiresAt?: number;
}

export interface ComplianceResult {
  address: string;
  status: 'cleared' | 'flagged' | 'blocked';
  riskScore: number;
  sanctionsLists: string[];
  lastChecked: number;
  recommendations: string[];
}
