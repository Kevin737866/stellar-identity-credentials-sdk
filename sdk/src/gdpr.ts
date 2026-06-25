import { DIDClient } from './didClient';
import { CredentialClient } from './credentialClient';
import { Logger } from './logger';
import { VerifiableCredential } from './types';
import { Keypair } from 'stellar-sdk';

export interface ConsentRecord {
  consentId: string;
  subjectDid: string;
  purpose: string;
  grantedAt: number;
  expiresAt?: number;
  revokedAt?: number;
  dataCategories: string[];
}

export interface ProcessingRecord {
  recordId: string;
  subjectDid: string;
  processingType: string;
  timestamp: number;
  legalBasis: string;
}

export interface GDPRComplianceOptions {
  dataRetentionDays?: number;
}

export class GDPREngine {
  private didClient: DIDClient;
  private credentialClient: CredentialClient;
  private logger: Logger;
  private consents: Map<string, ConsentRecord[]> = new Map();
  private processingRecords: Map<string, ProcessingRecord[]> = new Map();
  private options: GDPRComplianceOptions;

  constructor(didClient: DIDClient, credentialClient: CredentialClient, options?: GDPRComplianceOptions) {
    this.didClient = didClient;
    this.credentialClient = credentialClient;
    this.logger = new Logger('GDPREngine');
    this.options = options || { dataRetentionDays: 365 * 5 }; // default 5 years retention
  }

  /**
   * Implements Right to Erasure (Article 17)
   * Requests soft deletion of credentials via revocation with an Erasure reason.
   */
  async processErasureRequest(did: string, issuerKeypair: Keypair): Promise<boolean> {
    this.logger.info(`Processing right to erasure (soft delete) for DID: ${did}`);
    try {
      // Extract stellar address from DID (assuming did:stellar:G...)
      const address = did.split(':').pop() || '';
      const credentials = await this.credentialClient.getSubjectCredentials(address);
      for (const credId of credentials) {
        await this.credentialClient.revokeCredential(issuerKeypair, credId, 'GDPR Right to Erasure');
      }
      return true;
    } catch (e) {
      this.logger.error('Failed to process erasure request', e);
      return false;
    }
  }

  /**
   * Implements Right to Data Portability (Article 20)
   * Exports all known data for a DID in a machine-readable format.
   */
  async exportDataPortability(did: string): Promise<string> {
    this.logger.info(`Exporting data for portability: ${did}`);
    try {
      const didDoc = await this.didClient.resolveDID(did).catch(() => null);
      const address = did.split(':').pop() || '';
      const credentialIds = await this.credentialClient.getSubjectCredentials(address).catch(() => []);
      
      const credentials: VerifiableCredential[] = [];
      for (const id of credentialIds) {
        const cred = await this.credentialClient.getCredential(id).catch(() => null);
        if (cred) credentials.push(cred);
      }
      
      const consents = this.consents.get(did) || [];
      const processing = this.processingRecords.get(did) || [];
      
      return JSON.stringify({
        did: didDoc,
        credentials,
        consents,
        processingRecords: processing,
        exportedAt: Date.now()
      }, null, 2);
    } catch (e) {
      this.logger.error('Failed to export data', e);
      throw e;
    }
  }

  /**
   * Records user consent for data processing (Article 7)
   */
  recordConsent(consent: ConsentRecord): void {
    const userConsents = this.consents.get(consent.subjectDid) || [];
    userConsents.push(consent);
    this.consents.set(consent.subjectDid, userConsents);
    this.logger.info(`Consent ${consent.consentId} recorded for ${consent.subjectDid}`);
  }

  /**
   * Revokes a previously granted consent
   */
  revokeConsent(did: string, consentId: string): void {
    const userConsents = this.consents.get(did) || [];
    const consent = userConsents.find(c => c.consentId === consentId);
    if (consent) {
      consent.revokedAt = Date.now();
      this.logger.info(`Consent ${consentId} revoked for ${did}`);
    }
  }

  /**
   * Validates if active consent exists for a specific purpose
   */
  hasValidConsent(did: string, purpose: string): boolean {
    const userConsents = this.consents.get(did) || [];
    return userConsents.some(c => 
      c.purpose === purpose && 
      !c.revokedAt && 
      (!c.expiresAt || c.expiresAt > Date.now())
    );
  }

  /**
   * Logs data processing activities for Article 30 compliance
   */
  logDataProcessing(record: ProcessingRecord): void {
    const records = this.processingRecords.get(record.subjectDid) || [];
    records.push(record);
    this.processingRecords.set(record.subjectDid, records);
    this.logger.info(`Data processing logged for ${record.subjectDid}: ${record.processingType}`);
  }

  /**
   * Process data retention policies (Article 5(1)(e))
   * Returns a list of expired records that should be purged.
   */
  getExpiredRecords(did: string): ProcessingRecord[] {
    const records = this.processingRecords.get(did) || [];
    const retentionMs = (this.options.dataRetentionDays || 1825) * 24 * 60 * 60 * 1000;
    const now = Date.now();
    return records.filter(r => now - r.timestamp > retentionMs);
  }

  /**
   * Implements Right to Rectification (Article 16)
   */
  async processRectification(did: string, credentialId: string, issuerKeypair: Keypair): Promise<boolean> {
    this.logger.info(`Processing right to rectification for ${did}, credential: ${credentialId}`);
    try {
      await this.credentialClient.revokeCredential(issuerKeypair, credentialId, 'GDPR Right to Rectification update');
      // Re-issuance flow should be triggered externally by the issuer.
      return true;
    } catch (e) {
      this.logger.error('Failed to process rectification', e);
      return false;
    }
  }
}
